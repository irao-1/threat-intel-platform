"""
Unit42 Threat Intelligence Collector

Integrates with Palo Alto Networks Unit42 threat intelligence published on GitHub:
https://github.com/PaloAltoNetworks/Unit42-timely-threat-intel

Unit42 is Palo Alto Networks' threat intelligence team that publishes:
- Threat reports with IOCs (domains, IPs, hashes, URLs)
- Malware family analysis
- Campaign tracking
- APT intelligence

This collector provides FREE threat intelligence without requiring paid subscriptions,
replacing the paid AutoFocus integration.

File format:
- GitHub repository contains .txt files named like:
  * 2020-08-20-IOCs-for-Emotet-infection-with...
  * 2020-11-16-IOCs-for-Cobalt-Strike-activity.txt
- Each file contains IOCs in text format (domains, IPs, hashes, URLs)
"""

import requests
import re
import os
from typing import Dict, List, Optional, Set, Tuple
from datetime import datetime, timedelta
import logging
import json
from pathlib import Path

from .base_collector import SandboxCollector

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class Unit42Collector(SandboxCollector):
    """
    Collect FREE threat intelligence from Palo Alto Networks Unit42

    Replaces paid AutoFocus integration with public Unit42 GitHub feeds.

    Sources:
    - GitHub: https://github.com/PaloAltoNetworks/Unit42-timely-threat-intel
    - Threat reports with IOC indicators
    - No API key required (free public data)

    Extracted IOCs:
    - Domains (C2, phishing, malware hosting)
    - IP Addresses (C2 infrastructure)
    - File Hashes (MD5, SHA1, SHA256)
    - URLs (malware distribution, C2 callbacks)
    """

    def __init__(self, github_token: Optional[str] = None, cache_dir: Optional[str] = None):
        """
        Initialize Unit42 collector

        Args:
            github_token: Optional GitHub API token for higher rate limits
                         (Set GITHUB_TOKEN env var or pass here)
            cache_dir: Optional directory to cache downloaded files
                      (Set UNIT42_CACHE_DIR env var or pass here)
        """
        self.github_token = github_token or os.getenv('GITHUB_TOKEN')
        self.cache_dir = cache_dir or os.getenv('UNIT42_CACHE_DIR', '/tmp/unit42_cache')
        self.source = "Palo Alto Networks Unit42"

        # Unit42 repository on GitHub
        self.repo_owner = "PaloAltoNetworks"
        self.repo_name = "Unit42-timely-threat-intel"
        self.repo_url = f"https://github.com/{self.repo_owner}/{self.repo_name}"
        self.api_base = f"https://api.github.com/repos/{self.repo_owner}/{self.repo_name}"

        # Create cache directory
        Path(self.cache_dir).mkdir(parents=True, exist_ok=True)

        # IOC patterns for extraction
        self.ioc_patterns = {
            'ipv4': r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b',
            'ipv6': r'(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}',
            'domain': r'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b',
            'url': r'https?://[^\s<>"{}|\\^`\[\]]*',
            'md5': r'\b[a-fA-F0-9]{32}\b',
            'sha1': r'\b[a-fA-F0-9]{40}\b',
            'sha256': r'\b[a-fA-F0-9]{64}\b',
            'email': r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
        }

    def get_analysis(self, days_back: int = 30, limit: int = 10) -> Dict:
        """
        Fetch and parse threat data from Unit42

        Args:
            days_back: Number of days to look back for threat reports
            limit: Maximum number of files to process

        Returns:
            Standardized threat analysis dict with IOCs
        """
        try:
            logger.info(f"Fetching Unit42 threat reports from last {days_back} days (limit: {limit})")

            # Get list of threat report files from GitHub
            files = self._list_threat_files(days_back=days_back, limit=limit)

            if not files:
                logger.warning("No Unit42 threat files found")
                return self._empty_analysis()

            logger.info(f"Found {len(files)} Unit42 threat report files")

            # Parse each file and extract IOCs
            all_iocs = {
                'domains': set(),
                'ips': set(),
                'urls': set(),
                'hashes': [],
                'threat_names': []
            }

            for file_info in files:
                try:
                    iocs = self._parse_threat_file(file_info)
                    all_iocs['domains'].update(iocs.get('domains', []))
                    all_iocs['ips'].update(iocs.get('ips', []))
                    all_iocs['urls'].update(iocs.get('urls', []))
                    all_iocs['hashes'].extend(iocs.get('hashes', []))

                    # Extract threat name from filename
                    threat_name = self._extract_threat_name(file_info['name'])
                    if threat_name:
                        all_iocs['threat_names'].append(threat_name)

                except Exception as e:
                    logger.warning(f"Error parsing file {file_info.get('name')}: {e}")
                    continue

            # Build standardized analysis
            analysis = self._build_analysis(all_iocs)

            logger.info(f"Extracted {len(analysis['c2_domains'])} domains, "
                       f"{len(analysis['c2_ips'])} IPs, "
                       f"{len(analysis['file_hashes'])} hashes from Unit42")

            return self.standardize_analysis(analysis)

        except Exception as e:
            logger.error(f"Error fetching Unit42 data: {e}")
            return self._empty_analysis()

    def _list_threat_files(self, days_back: int = 30, limit: int = 10) -> List[Dict]:
        """
        List Unit42 threat report files from GitHub

        Args:
            days_back: Number of days to look back
            limit: Maximum number of files to return

        Returns:
            List of file info dicts with name, download_url, path
        """
        try:
            # GitHub API endpoint to list repository contents
            endpoint = f"{self.api_base}/contents"

            headers = {'Accept': 'application/vnd.github.v3+json'}
            if self.github_token:
                headers['Authorization'] = f'token {self.github_token}'

            logger.info(f"Querying Unit42 GitHub repository: {self.repo_url}")

            response = requests.get(endpoint, headers=headers, timeout=30)
            response.raise_for_status()

            contents = response.json()

            # Filter for .txt files (threat reports)
            txt_files = [item for item in contents
                        if item['type'] == 'file' and item['name'].endswith('.txt')]

            # Sort by name (descending - most recent first)
            txt_files = sorted(txt_files, key=lambda x: x['name'], reverse=True)[:limit]

            logger.info(f"Found {len(txt_files)} threat report files in Unit42")

            return txt_files

        except requests.RequestException as e:
            logger.error(f"Failed to list Unit42 files: {e}")
            if "403" in str(e) and "rate limit" in str(e).lower():
                logger.error("\n⚠️  GitHub Rate Limit Exceeded (60 requests/hour for unauthenticated)")
                logger.error("📌 Quick Fix: Set a GitHub personal access token")
                logger.error("\n   1. Go to: https://github.com/settings/tokens")
                logger.error("   2. Generate new token (classic) with 'public_repo' scope")
                logger.error("   3. Set environment variable: export GITHUB_TOKEN='your_token'")
                logger.error("   4. Run again: python -m examples.unit42_integration\n")
            return []

    def _parse_threat_file(self, file_info: Dict) -> Dict:
        """
        Parse a Unit42 threat report file and extract IOCs

        Args:
            file_info: File info dict from GitHub API with 'download_url'

        Returns:
            Dict with extracted IOCs (domains, ips, urls, hashes)
        """
        cache_path = os.path.join(self.cache_dir, file_info['name'])

        # Try to get from cache first
        content = None
        if os.path.exists(cache_path):
            try:
                with open(cache_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                logger.debug(f"Loaded {file_info['name']} from cache")
            except Exception as e:
                logger.debug(f"Cache read failed for {file_info['name']}: {e}")

        # Download if not in cache
        if not content:
            try:
                logger.debug(f"Downloading {file_info['name']} from GitHub")
                response = requests.get(file_info['download_url'], timeout=15)
                response.raise_for_status()
                content = response.text

                # Save to cache
                try:
                    with open(cache_path, 'w', encoding='utf-8') as f:
                        f.write(content)
                except Exception as e:
                    logger.debug(f"Cache write failed: {e}")

            except requests.RequestException as e:
                logger.warning(f"Failed to download {file_info['name']}: {e}")
                return {'domains': [], 'ips': [], 'urls': [], 'hashes': []}

        # Extract IOCs from content
        return self._extract_iocs(content)

    def _extract_iocs(self, content: str) -> Dict:
        """
        Extract IOCs from threat report text content

        Supports multiple IOC types:
        - IPv4 and IPv6 addresses
        - Domains
        - URLs
        - File hashes (MD5, SHA1, SHA256)

        Automatically skips non-indicator sections:
        - REFERENCES (blog posts, articles)
        - ADDITIONAL RESOURCES (links)
        - HTTP headers (not supported as IOC fields)

        Args:
            content: Raw text content from threat report

        Returns:
            Dict with lists of extracted IOCs
        """
        # Remove reference sections (they contain links, not IOCs)
        content = self._remove_reference_sections(content)

        iocs = {
            'domains': [],
            'ips': [],
            'urls': [],
            'hashes': [],
            'emails': []
        }

        # Convert to lowercase for matching (but preserve original for hashes)
        content_lower = content.lower()

        # Extract IPv4 addresses
        ipv4_matches = re.findall(self.ioc_patterns['ipv4'], content)
        iocs['ips'].extend([ip for ip in ipv4_matches if not self._is_private_ip(ip)])

        # Extract IPv6 addresses
        ipv6_matches = re.findall(self.ioc_patterns['ipv6'], content)
        iocs['ips'].extend(ipv6_matches)

        # Extract domains (case-insensitive)
        domain_matches = re.findall(self.ioc_patterns['domain'], content_lower)
        # Filter out common false positives and private TLDs
        valid_domains = [d for d in domain_matches
                        if not self._is_false_positive_domain(d)]
        iocs['domains'].extend(valid_domains)

        # Extract URLs from INDICATORS section only, not REFERENCES
        url_matches = re.findall(self.ioc_patterns['url'], content)
        # Filter out false positives (article links, common files)
        valid_urls = [url for url in url_matches if self._is_valid_indicator_url(url)]
        iocs['urls'].extend(valid_urls)

        # Extract file hashes (SHA256, SHA1, MD5 - in that order for priority)
        sha256_matches = re.findall(self.ioc_patterns['sha256'], content)
        for h in sha256_matches:
            iocs['hashes'].append({'hash': h, 'type': 'sha256'})

        sha1_matches = re.findall(self.ioc_patterns['sha1'], content)
        for h in sha1_matches:
            # Avoid duplicates with SHA256
            if h not in [x['hash'] for x in iocs['hashes']]:
                iocs['hashes'].append({'hash': h, 'type': 'sha1'})

        md5_matches = re.findall(self.ioc_patterns['md5'], content)
        for h in md5_matches:
            # Avoid duplicates
            if h not in [x['hash'] for x in iocs['hashes']]:
                iocs['hashes'].append({'hash': h, 'type': 'md5'})

        # Note: Email addresses in canary/placeholder values (e.g., zz_no_such_user_9f3a@domain) are kept
        # These are actual test/canary IOCs used by attackers, not contact addresses

        # Remove duplicates while preserving order
        iocs['domains'] = list(dict.fromkeys(iocs['domains']))
        iocs['ips'] = list(dict.fromkeys(iocs['ips']))
        iocs['urls'] = list(dict.fromkeys(iocs['urls']))

        logger.debug(f"Extracted: {len(iocs['domains'])} domains, "
                    f"{len(iocs['ips'])} IPs, "
                    f"{len(iocs['urls'])} URLs, "
                    f"{len(iocs['hashes'])} hashes")

        return iocs

    def _remove_reference_sections(self, content: str) -> str:
        """
        Remove REFERENCES and ADDITIONAL RESOURCES sections from content

        These sections contain article links, blog posts, etc. - not actual IOCs.

        Args:
            content: Full threat report text

        Returns:
            Content with reference sections removed
        """
        # Remove REFERENCES section
        content = re.sub(
            r'REFERENCES:?\s*\n.*?(?=\n[A-Z]+:|\Z)',
            '',
            content,
            flags=re.IGNORECASE | re.DOTALL
        )

        # Remove ADDITIONAL RESOURCES section
        content = re.sub(
            r'ADDITIONAL RESOURCES:?\s*\n.*?(?=\n[A-Z]+:|\Z)',
            '',
            content,
            flags=re.IGNORECASE | re.DOTALL
        )

        # Remove HTTP headers/signatures (like WWW-Authenticate: Basic realm="ARTEX")
        # These don't have IOC fields in our schema
        content = re.sub(
            r'WWW-Authenticate:.*',
            '',
            content,
            flags=re.IGNORECASE
        )

        return content

    def _extract_threat_name(self, filename: str) -> Optional[str]:
        """
        Extract threat name from Unit42 filename

        Examples:
        - 2020-08-20-IOCs-for-Emotet-infection-with... -> Emotet
        - 2020-11-16-IOCs-for-Cobalt-Strike-activity.txt -> Cobalt-Strike

        Args:
            filename: Unit42 threat report filename

        Returns:
            Threat name or None
        """
        try:
            # Pattern: DATE-IOCs-for-THREATNAME-description.txt
            match = re.search(r'IOCs-for-([A-Za-z0-9\-]+)', filename)
            if match:
                threat_name = match.group(1)
                # Clean up: replace hyphens with spaces, capitalize
                threat_name = threat_name.replace('-', ' ').title()
                return threat_name
            return None
        except Exception as e:
            logger.debug(f"Error extracting threat name from {filename}: {e}")
            return None

    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is in private range"""
        private_ranges = [
            ('10.0.0.0', '10.255.255.255'),
            ('172.16.0.0', '172.31.255.255'),
            ('192.168.0.0', '192.168.255.255'),
            ('127.0.0.0', '127.255.255.255'),
            ('169.254.0.0', '169.254.255.255'),
        ]

        try:
            import ipaddress
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_private or ip_obj.is_loopback
        except:
            # Fallback to simple check
            return any(ip.startswith(r[0].split('.')[0]) for r in private_ranges)

    def _is_valid_indicator_url(self, url: str) -> bool:
        """
        Filter out false positive URLs (article links, common files)

        Args:
            url: URL to validate

        Returns:
            True if valid threat indicator, False if false positive
        """
        # Article/blog domains to exclude
        article_domains = [
            'microsoft.com/en-us/security/blog',
            'crowdstrike.com/en-us/blog',
            'zscaler.com/blogs',
            'wiz.io/blog',
            'quartz.com', 'qz.com',
            'linkedin.com',
            'x.com', 'twitter.com',
            'medium.com',
            'bleepingcomputer.com',
            'securityaffairs.com',
        ]

        url_lower = url.lower()

        # Check if it's an article link
        for domain in article_domains:
            if domain in url_lower:
                return False

        # Common false positive files
        false_positive_files = [
            'index.php', 'index.html', 'index.htm',
            'bundle.js', 'main.js', 'app.js',
            'style.css', 'bundle.css',
            'favicon.ico',
            'robots.txt',
            'sitemap.xml',
            '/readme',
            '/license',
            '/changelog'
        ]

        for pattern in false_positive_files:
            if pattern.lower() in url_lower:
                return False

        # Must have a suspicious pattern to be valid IOC
        # (not just a normal website homepage)
        suspicious_patterns = [
            '/admin', '/backdoor', '/shell', '/upload',
            '/malware', '/payload', '/c2', '/beacon',
            '/command', '/exec', '/eval',
            '?cmd=', '?shell=', '?exec=',
            '.php?', '.asp?', '.jsp?'
        ]

        has_suspicious = any(p.lower() in url_lower for p in suspicious_patterns)

        # If it has no suspicious pattern, might be false positive
        return has_suspicious

    def _is_false_positive_domain(self, domain: str) -> bool:
        """Filter out common false positives"""
        # Common false positives in IOC extraction
        false_positives = [
            'example.com', 'test.com', 'localhost',
            'github.com', 'google.com', 'microsoft.com',
            'instagram.com', 'twitter.com', 'facebook.com',
            'amazon.com', 'apple.com', 'adobe.com',
            'readme', 'version', 'license', 'changelog'
        ]

        domain_lower = domain.lower()

        # Check exact matches
        if domain_lower in false_positives:
            return True

        # Filter very short domains (likely false positives)
        if len(domain_lower) < 5:
            return True

        # Filter domains with too many dots (malformed)
        if domain_lower.count('.') > 3:
            return True

        return False

    def _build_analysis(self, all_iocs: Dict) -> Dict:
        """
        Build standardized analysis from extracted IOCs

        Args:
            all_iocs: Dict with all extracted IOCs

        Returns:
            Standardized analysis dict
        """
        threat_names = ', '.join(all_iocs['threat_names'][:3])
        if len(all_iocs['threat_names']) > 3:
            threat_names += f" + {len(all_iocs['threat_names']) - 3} more"

        analysis = {
            'task_id': f'unit42-' + datetime.now().isoformat(),
            'source': self.source,
            'file': {
                'name': f'Unit42 Threat Reports',
                'type': 'threat_feed',
                'threats': threat_names or 'Multiple threats'
            },
            'verdict': 'malicious' if all_iocs['domains'] or all_iocs['ips'] else 'unknown',
            'c2_domains': list(all_iocs['domains']),
            'c2_ips': list(all_iocs['ips']),
            'dropped_files': [],
            'download_urls': list(all_iocs['urls']),
            'processes': [],
            'network_connections': [],
            'registry_modifications': [],
            'mitre_techniques': [],
            'file_hashes': all_iocs['hashes'],
            'malware_families': all_iocs['threat_names'],
            'threat_actors': [],
            'cves': [],
            'sentiment': 'high'  # Unit42 reports are typically high-severity
        }

        return analysis

    def _empty_analysis(self) -> Dict:
        """Return empty analysis structure"""
        return {
            'task_id': f'unit42-empty-' + datetime.now().isoformat(),
            'source': self.source,
            'file': {'name': 'Unit42 Empty', 'type': 'threat_feed'},
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
        try:
            with open(output_file, 'w') as f:
                json.dump(analysis, f, indent=2)
            logger.info(f"Analysis saved to {output_file}")
        except Exception as e:
            logger.error(f"Failed to save analysis: {e}")


# Example usage and testing
if __name__ == '__main__':
    collector = Unit42Collector()
    analysis = collector.get_analysis(days_back=30, limit=5)
    print(json.dumps(analysis, indent=2))
