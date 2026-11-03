"""
ThreatFox IOC Collector from abuse.ch

Free community API for querying recent IOCs:
- Domains, IPs, URLs, hashes
- Malware family info
- Threat type classification
- Fair use: No registration required, free tier available
"""

import requests
import logging
import os
from typing import List, Dict, Optional
from datetime import datetime

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ThreatFoxCollector:
    """
    Collects IOCs from ThreatFox (abuse.ch community API)

    Free for community use - no rate limiting for reasonable queries
    Queries: get_iocs (recent IOCs from last 1-7 days)
    """

    def __init__(self, auth_key: Optional[str] = None):
        """
        Initialize ThreatFox collector

        Args:
            auth_key: ThreatFox Auth-Key from https://threatfox.abuse.ch
                     Optional - can query without auth but with limitations
        """
        self.auth_key = auth_key or os.getenv('THREATFOX_AUTH_KEY')
        self.api_url = "https://threatfox-api.abuse.ch/api/v1/"
        self.headers = {
            'Content-Type': 'application/json'
        }
        if self.auth_key:
            self.headers['Auth-Key'] = self.auth_key

    def get_recent_iocs(self, days: int = 7) -> Dict:
        """
        Get recent IOCs from ThreatFox

        Args:
            days: Number of days to look back (1-7, default 7)

        Returns:
            Dict with IOC data and metadata
        """
        if days < 1 or days > 7:
            days = 7
            logger.warning(f"Days must be 1-7, using 7")

        logger.info(f"📡 Fetching ThreatFox IOCs from last {days} days...")

        payload = {
            "query": "get_iocs",
            "days": days
        }

        try:
            response = requests.post(
                self.api_url,
                json=payload,
                headers=self.headers,
                timeout=15
            )
            response.raise_for_status()

            data = response.json()

            if data.get('query_status') == 'ok':
                iocs = data.get('data', [])
                logger.info(f"✅ Found {len(iocs)} IOCs from ThreatFox")
                return {
                    'success': True,
                    'iocs': iocs,
                    'count': len(iocs),
                    'source': 'ThreatFox',
                    'fetched_at': datetime.now().isoformat()
                }
            else:
                error_msg = data.get('error', 'Unknown error')
                logger.error(f"❌ ThreatFox error: {error_msg}")
                return {
                    'success': False,
                    'error': error_msg,
                    'iocs': []
                }

        except Exception as e:
            logger.error(f"❌ Failed to fetch ThreatFox IOCs: {e}")
            return {
                'success': False,
                'error': str(e),
                'iocs': []
            }

    def parse_iocs(self, threatfox_data: Dict) -> List[Dict]:
        """
        Parse ThreatFox response into standardized IOC format

        Args:
            threatfox_data: Raw response from get_recent_iocs()

        Returns:
            List of standardized IOC dicts
        """
        iocs = []

        if not threatfox_data.get('success'):
            return iocs

        for ioc_record in threatfox_data.get('iocs', []):
            try:
                ioc_value = ioc_record.get('ioc', '')
                ioc_type_desc = ioc_record.get('ioc_type_desc', '')
                threat_type = ioc_record.get('threat_type', 'unknown')
                malware = ioc_record.get('malware_printable', 'Unknown')
                confidence = ioc_record.get('confidence_level', 0)
                first_seen = ioc_record.get('first_seen', '')

                # Standardize IOC type
                ioc_type = self._map_ioc_type(ioc_record.get('ioc_type', ''))

                if not ioc_value or not ioc_type:
                    continue

                iocs.append({
                    'ioc': ioc_value,
                    'type': ioc_type,
                    'threat_type': threat_type,
                    'threat_type_desc': ioc_record.get('threat_type_desc', ''),
                    'malware': malware,
                    'malware_alias': ioc_record.get('malware_alias'),
                    'confidence': confidence,
                    'first_seen': first_seen,
                    'last_seen': ioc_record.get('last_seen'),
                    'reporter': ioc_record.get('reporter', 'abuse_ch'),
                    'reference': ioc_record.get('reference'),
                    'tags': ioc_record.get('tags', []),
                    'source': 'ThreatFox',
                    'source_id': ioc_record.get('id')
                })

            except Exception as e:
                logger.debug(f"Failed to parse IOC: {e}")
                continue

        return iocs

    def _map_ioc_type(self, threatfox_type: str) -> str:
        """Map ThreatFox IOC type to standard format"""
        mapping = {
            'domain': 'domain',
            'url': 'url',
            'ip:port': 'ip',
            'ipv4': 'ip',
            'ipv6': 'ip',
            'email': 'email',
            'file_hash': 'hash',
            'md5_hash': 'hash',
            'sha256_hash': 'hash',
        }
        return mapping.get(threatfox_type, threatfox_type)

    def search_ioc(self, search_term: str, exact_match: bool = True) -> Dict:
        """
        Search for a specific IOC on ThreatFox

        Args:
            search_term: IOC to search (domain, IP, URL, hash)
            exact_match: If True, exact match; False for wildcard

        Returns:
            Dict with search results
        """
        logger.info(f"🔍 Searching ThreatFox for: {search_term}")

        payload = {
            "query": "search_ioc",
            "search_term": search_term,
            "exact_match": exact_match
        }

        try:
            response = requests.post(
                self.api_url,
                json=payload,
                headers=self.headers,
                timeout=15
            )
            response.raise_for_status()

            data = response.json()

            if data.get('query_status') == 'ok':
                iocs = data.get('data', [])
                logger.info(f"✅ Found {len(iocs)} results for '{search_term}'")
                return {
                    'success': True,
                    'iocs': iocs,
                    'count': len(iocs)
                }
            else:
                logger.warning(f"No results found for '{search_term}'")
                return {
                    'success': True,
                    'iocs': [],
                    'count': 0
                }

        except Exception as e:
            logger.error(f"Search failed: {e}")
            return {
                'success': False,
                'error': str(e),
                'iocs': []
            }

    def get_malware_info(self, malware_family: str, limit: int = 100) -> Dict:
        """
        Get all IOCs associated with a malware family

        Args:
            malware_family: Malware name (e.g., 'Cobalt Strike')
            limit: Max results (default 100, max 1000)

        Returns:
            Dict with IOCs for that malware
        """
        logger.info(f"🦠 Fetching IOCs for malware: {malware_family}")

        payload = {
            "query": "malwareinfo",
            "malware": malware_family,
            "limit": min(limit, 1000)
        }

        try:
            response = requests.post(
                self.api_url,
                json=payload,
                headers=self.headers,
                timeout=15
            )
            response.raise_for_status()

            data = response.json()

            if data.get('query_status') == 'ok':
                iocs = data.get('data', [])
                logger.info(f"✅ Found {len(iocs)} IOCs for {malware_family}")
                return {
                    'success': True,
                    'malware': malware_family,
                    'iocs': iocs,
                    'count': len(iocs)
                }
            else:
                logger.warning(f"No data for malware: {malware_family}")
                return {
                    'success': True,
                    'malware': malware_family,
                    'iocs': [],
                    'count': 0
                }

        except Exception as e:
            logger.error(f"Failed to get malware info: {e}")
            return {
                'success': False,
                'error': str(e),
                'iocs': []
            }


if __name__ == '__main__':
    # Test the collector
    collector = ThreatFoxCollector()

    print("\n" + "="*70)
    print("🦊 THREATFOX COLLECTOR TEST")
    print("="*70 + "\n")

    # Get recent IOCs
    print("📡 Fetching recent IOCs (last 7 days)...")
    result = collector.get_recent_iocs(days=7)

    if result['success']:
        print(f"✅ Found {result['count']} IOCs\n")

        # Parse and show sample
        iocs = collector.parse_iocs(result)
        print(f"Sample IOCs (first 5):\n")
        for ioc in iocs[:5]:
            print(f"  • {ioc['ioc']} ({ioc['type']})")
            print(f"    Threat: {ioc['threat_type']}")
            print(f"    Malware: {ioc['malware']}")
            print(f"    Confidence: {ioc['confidence']}%\n")
    else:
        print(f"❌ Error: {result.get('error')}\n")
