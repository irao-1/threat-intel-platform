"""
Parse security threats from TweetFeed Live official API
Extract IOCs from structured API endpoints (not website scraping)
"""

import re
import requests
import json
from typing import Dict, List, Optional
from datetime import datetime, timedelta
import logging

from .base_collector import SandboxCollector

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class TweetParserCollector(SandboxCollector):
    """
    Collect threat intelligence from TweetFeed Live API

    TweetFeed provides a free REST API for threat intelligence queries.
    This collector uses structured API endpoints (not HTML scraping).

    Official API documentation: https://tweetfeed.live/docs/

    Key endpoints:
    - /v1/today, /v1/week, /v1/month - Time windows with optional filters
    - /v1/since/{timestamp} - Incremental delta sync (only new IOCs)
    - /v1/campaigns - AI-clustered threat campaigns
    - /v1/ioc?value=X - IOC lookup and enrichment
    - /v1/blocklist/* - Pre-formatted blocklists
    - /v1/counts - Aggregated statistics
    - /v1/status - Pipeline freshness

    Supports filters:
    - By type: url, domain, ip, sha256, md5
    - By tag: phishing, ransomware, CobaltStrike, etc.
    - By user: @handle
    """

    def __init__(self):
        self.api_base = "https://api.tweetfeed.live/v1"
        self.source = "TweetFeed Live API"

    def get_analysis(self, task_id: str = None,
                    time_window: str = "week",
                    filter_type: Optional[str] = None,
                    filter_tag: Optional[str] = None) -> Dict:
        """
        Fetch and parse IOCs from TweetFeed API

        Args:
            task_id: Unused (for compatibility with base class)
            time_window: 'today', 'week', 'month', or 'year'
            filter_type: Optional IOC type (url, domain, ip, sha256, md5)
            filter_tag: Optional tag (phishing, ransomware, CobaltStrike, etc.)

        Returns:
            Standardized threat analysis dict
        """
        feed_data = self.fetch_from_api(time_window, filter_type, filter_tag)
        return self.parse_iocs(feed_data, time_window)

    def fetch_from_api(self, time_window: str = "week",
                       filter_type: Optional[str] = None,
                       filter_tag: Optional[str] = None) -> List[Dict]:
        """
        Fetch IOCs from TweetFeed API with optional filters

        Args:
            time_window: 'today', 'week', 'month', or 'year'
            filter_type: Optional type filter
            filter_tag: Optional tag filter

        Returns:
            List of IOC records from API
        """
        # Build endpoint
        endpoint_parts = [self.api_base, time_window]

        if filter_tag:
            # Remove leading # if present
            filter_tag = filter_tag.lstrip('#')
            endpoint_parts.append(filter_tag)

        if filter_type:
            endpoint_parts.append(filter_type)

        endpoint = "/".join(endpoint_parts)

        try:
            logger.info(f"Fetching from TweetFeed API: {endpoint}")
            # Use standard User-Agent (not bare urllib, which Cloudflare blocks)
            headers = {
                'User-Agent': 'ThreatIntelCollector/1.0 (Python requests)'
            }
            response = requests.get(endpoint, headers=headers, timeout=15)
            response.raise_for_status()

            data = response.json()

            # Check for result truncation
            if 'X-Result-Truncated' in response.headers:
                logger.warning("Results truncated at 10k rows (set by API cap)")

            logger.info(f"Fetched {len(data)} IOCs from {time_window} window")
            return data

        except requests.RequestException as e:
            logger.error(f"Failed to fetch from TweetFeed API: {e}")
            return []

    def fetch_incremental(self, since_timestamp: str) -> List[Dict]:
        """
        Fetch only NEW IOCs since last sync (delta sync)

        Useful for incremental updates without re-fetching everything.

        Args:
            since_timestamp: ISO 8601 format (e.g., 2026-11-03T17:30:00Z)

        Returns:
            List of IOCs added after timestamp
        """
        endpoint = f"{self.api_base}/since/{since_timestamp}"

        try:
            logger.info(f"Fetching incremental IOCs since {since_timestamp}")
            headers = {
                'User-Agent': 'ThreatIntelCollector/1.0 (Python requests)'
            }
            response = requests.get(endpoint, headers=headers, timeout=15)
            response.raise_for_status()

            data = response.json()
            logger.info(f"Fetched {len(data)} new IOCs since {since_timestamp}")
            return data

        except requests.RequestException as e:
            logger.error(f"Failed to fetch incremental IOCs: {e}")
            return []

    def get_campaigns(self) -> Dict:
        """
        Fetch AI-clustered threat campaigns (last 30 days)

        Returns:
            Campaign metadata with clustering info
        """
        endpoint = f"{self.api_base}/campaigns"

        try:
            logger.info("Fetching threat campaigns from TweetFeed API")
            headers = {
                'User-Agent': 'ThreatIntelCollector/1.0 (Python requests)'
            }
            response = requests.get(endpoint, headers=headers, timeout=15)
            response.raise_for_status()

            data = response.json()
            logger.info(f"Fetched {data.get('campaign_count', 0)} threat campaigns")
            return data

        except requests.RequestException as e:
            logger.error(f"Failed to fetch campaigns: {e}")
            return {}

    def enrich_ioc(self, ioc_value: str) -> Dict:
        """
        Lookup and enrich a single IOC

        Returns: First/last seen, reporters, tags, related campaigns, RDAP data

        Args:
            ioc_value: Domain, IP, URL, or hash to lookup

        Returns:
            Enriched IOC data with historical context
        """
        endpoint = f"{self.api_base}/ioc"

        try:
            logger.info(f"Enriching IOC: {ioc_value}")
            headers = {
                'User-Agent': 'ThreatIntelCollector/1.0 (Python requests)'
            }
            response = requests.get(endpoint,
                                  params={'value': ioc_value, 'defang': '1'},
                                  headers=headers,
                                  timeout=15)
            response.raise_for_status()

            data = response.json()
            if data.get('found'):
                logger.info(f"IOC {ioc_value} found: {len(data.get('records', []))} records")
            else:
                logger.info(f"IOC {ioc_value} not found in 365-day window")

            return data

        except requests.RequestException as e:
            logger.error(f"Failed to enrich IOC: {e}")
            return {'found': False}

    def parse_iocs(self, iocs: List[Dict], time_window: str) -> Dict:
        """
        Parse IOCs from API response into standardized format

        Args:
            iocs: List of IOC records from API
            time_window: Time window used for fetch (for logging)

        Returns:
            Standardized threat analysis dict
        """
        analysis = {
            'task_id': 'tweetfeed-api-' + datetime.now().isoformat(),
            'source': self.source,
            'file': {
                'name': f'TweetFeed API {time_window}',
                'type': 'threat_feed'
            },
            'verdict': 'malicious' if iocs else 'unknown',
            'c2_domains': self._extract_by_type(iocs, 'domain'),
            'c2_ips': self._extract_by_type(iocs, 'ip'),
            'dropped_files': [],
            'download_urls': self._extract_by_type(iocs, 'url'),
            'processes': [],
            'network_connections': [],
            'registry_modifications': [],
            'mitre_techniques': self._extract_mitre_from_iocs(iocs),
            'file_hashes': self._extract_hashes(iocs),
            'malware_families': self._extract_tags(iocs, exclude=['#phishing', '#scam']),
            'threat_actors': [],  # Would need campaign enrichment
            'cves': [],  # Not directly in IOC records
            'sentiment': self._analyze_severity(iocs)
        }

        logger.info(f"Parsed {len(iocs)} IOCs: "
                   f"{len(analysis['c2_domains'])} domains, "
                   f"{len(analysis['c2_ips'])} IPs, "
                   f"{len(analysis['file_hashes'])} hashes")

        return self.standardize_analysis(analysis)

    def _extract_by_type(self, iocs: List[Dict], ioc_type: str) -> List[str]:
        """Extract IOCs of a specific type"""
        values = []
        for ioc in iocs:
            if ioc.get('type') == ioc_type:
                value = ioc.get('value', '').lower()
                if value and value != '0.0.0.0':
                    values.append(value)
        return list(set(values))

    def _extract_hashes(self, iocs: List[Dict]) -> List[Dict]:
        """Extract hash IOCs with type information"""
        hashes = []
        for ioc in iocs:
            ioc_type = ioc.get('type', '')
            if ioc_type in ['md5', 'sha256', 'sha1']:
                hashes.append({
                    'hash': ioc.get('value', ''),
                    'type': ioc_type
                })
        return hashes

    def _extract_tags(self, iocs: List[Dict], exclude: Optional[List[str]] = None) -> List[str]:
        """Extract unique tags from IOCs"""
        tags = set()
        exclude = exclude or []

        for ioc in iocs:
            ioc_tags = ioc.get('tags', [])
            for tag in ioc_tags:
                if tag not in exclude:
                    # Remove leading # and add to set
                    clean_tag = tag.lstrip('#')
                    tags.add(clean_tag)

        return list(tags)

    def _extract_mitre_from_iocs(self, iocs: List[Dict]) -> List[str]:
        """Extract MITRE ATT&CK techniques from IOC tags"""
        techniques = set()

        for ioc in iocs:
            tags = ioc.get('tags', [])
            for tag in tags:
                # Look for patterns like #T1486, #T1547.001, etc.
                match = re.search(r'T\d{4}(?:\.\d{3})?', tag)
                if match:
                    techniques.add(match.group())

        return list(techniques)

    def _analyze_severity(self, iocs: List[Dict]) -> str:
        """Analyze severity based on IOC tags and types"""
        severity_keywords = {
            'critical': ['zero-day', '0day', 'rce', 'wormable', 'exploit'],
            'high': ['ransomware', 'malware', 'trojan', 'c2', 'botnet'],
            'medium': ['phishing', 'scam', 'suspicious']
        }

        all_tags = ' '.join([
            tag.lower() for ioc in iocs
            for tag in ioc.get('tags', [])
        ])

        for severity, keywords in severity_keywords.items():
            if any(kw in all_tags for kw in keywords):
                if severity == 'critical':
                    return 'critical'
                elif severity == 'high':
                    return 'high'

        return 'medium'

    def get_status(self) -> Dict:
        """
        Check TweetFeed API pipeline freshness

        Returns:
            Status info: whether pipeline is fresh, age of data, etc.
        """
        endpoint = f"{self.api_base}/status"

        try:
            logger.info("Checking TweetFeed API status")
            headers = {
                'User-Agent': 'ThreatIntelCollector/1.0 (Python requests)'
            }
            response = requests.get(endpoint, headers=headers, timeout=15)
            response.raise_for_status()

            data = response.json()

            if data.get('stale'):
                logger.warning("TweetFeed API pipeline is STALE")
            else:
                logger.info("TweetFeed API pipeline is FRESH")

            return data

        except requests.RequestException as e:
            logger.error(f"Failed to check API status: {e}")
            return {}

    def get_trends(self) -> Dict:
        """
        Get threat trends: volume, top tags, trending IOCs

        Returns:
            31-day analytics, tag movers, top TLDs, novelty rate
        """
        endpoint = f"{self.api_base}/trends"

        try:
            logger.info("Fetching threat trends from TweetFeed API")
            headers = {
                'User-Agent': 'ThreatIntelCollector/1.0 (Python requests)'
            }
            response = requests.get(endpoint, headers=headers, timeout=15)
            response.raise_for_status()

            data = response.json()
            logger.info(f"Fetched trends data")
            return data

        except requests.RequestException as e:
            logger.error(f"Failed to fetch trends: {e}")
            return {}

    def save_analysis(self, analysis: Dict, output_file: str):
        """Save analysis to JSON file"""
        with open(output_file, 'w') as f:
            json.dump(analysis, f, indent=2)
        logger.info(f"Analysis saved to {output_file}")
