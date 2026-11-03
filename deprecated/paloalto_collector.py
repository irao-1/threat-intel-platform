"""
Palo Alto Networks threat intelligence collector

Integrates with:
- Palo Alto Networks AutoFocus API
- WildFire API
- Threat Prevention subscriptions
- Unit42 threat intelligence feeds

This collector fetches threat data from Palo Alto's threat intelligence
and converts to our standardized format for correlation with other sources.
"""

import requests
import json
from typing import Dict, List, Optional
from datetime import datetime, timedelta
import logging

from .base_collector import SandboxCollector

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class PaloAltoCollector(SandboxCollector):
    """
    Collect threat intelligence from Palo Alto Networks sources

    Supported sources:
    - AutoFocus API (advanced threat data, campaigns)
    - WildFire API (malware analysis, file verdicts)
    - Threat Prevention subscriptions
    - Unit42 intelligence feeds

    API Documentation:
    https://docs.paloaltonetworks.com/autofocus/autofocus-api
    """

    def __init__(self, api_key: Optional[str] = None):
        """
        Initialize Palo Alto collector

        Args:
            api_key: Palo Alto AutoFocus/WildFire API key
                    (Set PALO_ALTO_API_KEY env var or pass here)
        """
        import os
        self.api_key = api_key or os.getenv('PALO_ALTO_API_KEY')
        self.source = "Palo Alto Networks"

        # API endpoints
        self.autofocus_base = "https://autofocus.paloaltonetworks.com/api/v1.0"
        self.wildfire_base = "https://wildfire.paloaltonetworks.com/publicapi"

        if not self.api_key:
            logger.warning("No Palo Alto API key provided. AutoFocus features disabled.")

    def get_analysis(self, task_id: str = None,
                    source: str = "autofocus",
                    query: Optional[str] = None) -> Dict:
        """
        Fetch and parse threat data from Palo Alto

        Args:
            task_id: Unused (compatibility with base class)
            source: 'autofocus', 'wildfire', or 'unit42'
            query: Optional search query for AutoFocus

        Returns:
            Standardized threat analysis dict
        """
        if not self.api_key and source in ['autofocus', 'wildfire']:
            logger.error("Palo Alto API key required for AutoFocus/WildFire")
            return self._empty_analysis()

        if source == 'autofocus':
            threats = self._fetch_autofocus(query)
        elif source == 'wildfire':
            threats = self._fetch_wildfire()
        elif source == 'unit42':
            threats = self._fetch_unit42()
        else:
            logger.warning(f"Unknown source: {source}")
            return self._empty_analysis()

        return self._parse_threats(threats, source)

    def _fetch_autofocus(self, query: Optional[str] = None) -> List[Dict]:
        """
        Fetch threat data from AutoFocus API

        AutoFocus provides:
        - Advanced threat prevention intelligence
        - Campaign information and TTP correlations
        - WildFire verdict data
        - Signature and vulnerability correlations

        Args:
            query: Optional search query (e.g., "file_type:PE")

        Returns:
            List of threat records
        """
        if not self.api_key:
            logger.error("AutoFocus API key required")
            return []

        # Default query: threats seen in last 7 days
        if not query:
            query = "seen_in_the_last_seven_days:true"

        endpoint = f"{self.autofocus_base}/samples"

        try:
            logger.info(f"Fetching AutoFocus threats with query: {query}")

            headers = {
                'Content-Type': 'application/json'
            }

            payload = {
                "apikey": self.api_key,
                "query": query,
                "scope": "public"  # or 'private' for organization-specific
            }

            response = requests.post(endpoint, json=payload, headers=headers, timeout=30)
            response.raise_for_status()

            data = response.json()

            if not data.get('success'):
                logger.error(f"AutoFocus API error: {data.get('message', 'Unknown error')}")
                return []

            threats = data.get('hits', [])
            logger.info(f"Fetched {len(threats)} threats from AutoFocus")
            return threats

        except requests.RequestException as e:
            logger.error(f"Failed to fetch from AutoFocus: {e}")
            return []

    def _fetch_wildfire(self, days_back: int = 7) -> List[Dict]:
        """
        Fetch verdicts from WildFire API

        WildFire provides:
        - File verdict data (malware/benign/grayware)
        - Hash reputation
        - Signature information

        Args:
            days_back: Number of days to look back

        Returns:
            List of file verdicts
        """
        if not self.api_key:
            logger.error("WildFire API key required")
            return []

        # Note: WildFire API usage varies by implementation
        # This is a template for common queries
        endpoint = f"{self.wildfire_base}/get/verdicts"

        try:
            logger.info(f"Fetching WildFire verdicts from last {days_back} days")

            since_date = (datetime.now() - timedelta(days=days_back)).isoformat()

            params = {
                'apikey': self.api_key,
                'since': since_date
            }

            response = requests.get(endpoint, params=params, timeout=30)
            response.raise_for_status()

            data = response.json()
            verdicts = data.get('verdicts', [])

            logger.info(f"Fetched {len(verdicts)} verdicts from WildFire")
            return verdicts

        except requests.RequestException as e:
            logger.error(f"Failed to fetch from WildFire: {e}")
            return []

    def _fetch_unit42(self) -> List[Dict]:
        """
        Fetch Unit42 threat intelligence feeds

        Unit42 is Palo Alto's threat intelligence team.
        Publicly available threat indicators and research.

        Returns:
            List of threat indicators from Unit42
        """
        # Unit42 publishes feeds via GitHub and other channels
        # This would integrate with public feeds or subscriptions

        unit42_feeds = [
            "https://raw.githubusercontent.com/PaloAltoNetworks/Unit42-psscor4/master/",
            # Add more as available
        ]

        all_threats = []

        for feed_url in unit42_feeds:
            try:
                logger.info(f"Fetching Unit42 feed: {feed_url}")
                response = requests.get(feed_url, timeout=15)
                response.raise_for_status()

                # Parse feed (format depends on feed type)
                threats = self._parse_feed(response.text)
                all_threats.extend(threats)

            except requests.RequestException as e:
                logger.warning(f"Failed to fetch Unit42 feed: {e}")
                continue

        logger.info(f"Fetched {len(all_threats)} threats from Unit42")
        return all_threats

    def _parse_feed(self, feed_content: str) -> List[Dict]:
        """Parse various feed formats"""
        threats = []

        # Try JSON first
        try:
            data = json.loads(feed_content)
            if isinstance(data, list):
                return data
            elif isinstance(data, dict):
                return [data]
        except:
            pass

        # Try CSV format
        import csv
        from io import StringIO

        try:
            reader = csv.DictReader(StringIO(feed_content))
            threats = list(reader)
        except:
            pass

        return threats

    def _parse_threats(self, threats: List[Dict], source: str) -> Dict:
        """
        Parse Palo Alto threats into standardized format

        Args:
            threats: List of threat objects from Palo Alto APIs
            source: Source name (autofocus, wildfire, unit42)

        Returns:
            Standardized analysis dict
        """
        analysis = {
            'task_id': f'paloalto-{source}-' + datetime.now().isoformat(),
            'source': f"{self.source} - {source.upper()}",
            'file': {
                'name': f'Palo Alto {source} Threats',
                'type': 'threat_feed'
            },
            'verdict': 'malicious' if threats else 'unknown',
            'c2_domains': self._extract_domains(threats),
            'c2_ips': self._extract_ips(threats),
            'dropped_files': [],
            'download_urls': self._extract_urls(threats),
            'processes': [],
            'network_connections': [],
            'registry_modifications': [],
            'mitre_techniques': self._extract_mitre(threats),
            'file_hashes': self._extract_hashes(threats),
            'malware_families': self._extract_malware_families(threats),
            'threat_actors': self._extract_threat_actors(threats),
            'cves': self._extract_cves(threats),
            'sentiment': self._analyze_severity(threats)
        }

        logger.info(f"Parsed {len(threats)} threats: "
                   f"{len(analysis['c2_domains'])} domains, "
                   f"{len(analysis['c2_ips'])} IPs, "
                   f"{len(analysis['file_hashes'])} hashes")

        return self.standardize_analysis(analysis)

    def _extract_domains(self, threats: List[Dict]) -> List[str]:
        """Extract domains from Palo Alto threats"""
        domains = set()

        for threat in threats:
            # AutoFocus format
            if 'domains' in threat:
                for domain in threat.get('domains', []):
                    if isinstance(domain, str):
                        domains.add(domain.lower())
                    elif isinstance(domain, dict):
                        domains.add(domain.get('name', '').lower())

            # Check in behaviors/network activity
            if 'behavior' in threat:
                for behavior in threat.get('behavior', []):
                    if behavior.get('type') == 'dns':
                        domains.add(behavior.get('value', '').lower())

        return list(domains)

    def _extract_ips(self, threats: List[Dict]) -> List[str]:
        """Extract IPs from Palo Alto threats"""
        ips = set()

        for threat in threats:
            # AutoFocus format
            if 'ips' in threat:
                for ip in threat.get('ips', []):
                    if isinstance(ip, str):
                        ips.add(ip)
                    elif isinstance(ip, dict):
                        ips.add(ip.get('address', ''))

            # Check in network indicators
            if 'indicators' in threat:
                for indicator in threat.get('indicators', []):
                    if indicator.get('type') == 'ip':
                        ips.add(indicator.get('value', ''))

        return list(ips)

    def _extract_urls(self, threats: List[Dict]) -> List[str]:
        """Extract URLs from Palo Alto threats"""
        urls = set()

        for threat in threats:
            if 'urls' in threat:
                urls.update(threat.get('urls', []))

            if 'indicators' in threat:
                for indicator in threat.get('indicators', []):
                    if indicator.get('type') == 'url':
                        urls.add(indicator.get('value', ''))

        return list(urls)

    def _extract_hashes(self, threats: List[Dict]) -> List[Dict]:
        """Extract file hashes from Palo Alto threats"""
        hashes = []

        for threat in threats:
            # AutoFocus provides multiple hash types
            if 'sha256' in threat:
                hashes.append({'hash': threat['sha256'], 'type': 'sha256'})

            if 'sha1' in threat:
                hashes.append({'hash': threat['sha1'], 'type': 'sha1'})

            if 'md5' in threat:
                hashes.append({'hash': threat['md5'], 'type': 'md5'})

            # Check indicators
            if 'indicators' in threat:
                for indicator in threat.get('indicators', []):
                    ioc_type = indicator.get('type', '')
                    if ioc_type in ['md5', 'sha1', 'sha256']:
                        hashes.append({
                            'hash': indicator.get('value', ''),
                            'type': ioc_type
                        })

        return hashes

    def _extract_mitre(self, threats: List[Dict]) -> List[str]:
        """Extract MITRE ATT&CK techniques from Palo Alto threats"""
        techniques = set()

        for threat in threats:
            # AutoFocus uses 'tags' for MITRE mappings
            if 'tag' in threat:
                tags = threat.get('tag', [])
                if isinstance(tags, str):
                    tags = [tags]

                for tag in tags:
                    if tag.startswith('T') and len(tag) >= 5:
                        # Likely MITRE technique
                        techniques.add(tag)

            # Check for TTP data
            if 'ttps' in threat:
                techniques.update(threat.get('ttps', []))

        return list(techniques)

    def _extract_malware_families(self, threats: List[Dict]) -> List[str]:
        """Extract malware family names from Palo Alto threats"""
        families = set()

        for threat in threats:
            # AutoFocus provides malware family info
            if 'malware_family' in threat:
                families.add(threat['malware_family'])

            if 'family' in threat:
                families.add(threat['family'])

            # Check tags for family names
            if 'tag' in threat:
                tags = threat.get('tag', [])
                if isinstance(tags, str):
                    tags = [tags]

                for tag in tags:
                    # Common malware family patterns
                    if any(family in tag for family in
                           ['Emotet', 'TrickBot', 'Ransomware', 'Trojan', 'Worm', 'Mirai']):
                        families.add(tag)

        return list(families)

    def _extract_threat_actors(self, threats: List[Dict]) -> List[str]:
        """Extract threat actor names from Palo Alto threats"""
        actors = set()

        for threat in threats:
            # Check for attribution data
            if 'threat_actor' in threat:
                actors.add(threat['threat_actor'])

            if 'campaign' in threat:
                actors.add(threat['campaign'])

            # Check tags for actor names
            if 'tag' in threat:
                tags = threat.get('tag', [])
                if isinstance(tags, str):
                    tags = [tags]

                for tag in tags:
                    if any(actor in tag for actor in ['APT', 'FIN', 'Lazarus', 'APT28', 'APT29']):
                        actors.add(tag)

        return list(actors)

    def _extract_cves(self, threats: List[Dict]) -> List[str]:
        """Extract CVE identifiers from Palo Alto threats"""
        cves = set()

        for threat in threats:
            if 'cves' in threat:
                cve_list = threat.get('cves', [])
                if isinstance(cve_list, str):
                    cve_list = [cve_list]
                cves.update(cve_list)

            # Check all string fields for CVE pattern
            for value in threat.values():
                if isinstance(value, str) and 'CVE-' in value:
                    import re
                    matches = re.findall(r'CVE-\d{4}-\d{4,}', value)
                    cves.update(matches)

        return list(cves)

    def _analyze_severity(self, threats: List[Dict]) -> str:
        """Analyze threat severity from Palo Alto data"""
        severity_keywords = {
            'critical': ['critical', 'zero-day', 'rce', 'wormable'],
            'high': ['ransomware', 'trojan', 'botnet', 'backdoor'],
            'medium': ['suspicious', 'phishing', 'pup']
        }

        all_text = json.dumps(threats).lower()

        for severity, keywords in severity_keywords.items():
            if any(kw in all_text for kw in keywords):
                if severity == 'critical':
                    return 'critical'
                elif severity == 'high':
                    return 'high'

        return 'medium'

    def _empty_analysis(self) -> Dict:
        """Return empty analysis structure"""
        return {
            'task_id': f'paloalto-empty-' + datetime.now().isoformat(),
            'source': self.source,
            'file': {'name': 'Palo Alto Empty', 'type': 'threat_feed'},
            'verdict': 'unknown',
            'c2_domains': [],
            'c2_ips': [],
            'dropped_files': [],
            'download_urls': [],
            'processes': [],
            'network_connections': [],
            'registry_modifications': [],
            'mitre_techniques': [],
            'file_hashes': [],
            'malware_families': [],
            'threat_actors': [],
            'cves': [],
            'sentiment': 'medium'
        }

    def save_analysis(self, analysis: Dict, output_file: str):
        """Save analysis to JSON file"""
        with open(output_file, 'w') as f:
            json.dump(analysis, f, indent=2)
        logger.info(f"Analysis saved to {output_file}")
