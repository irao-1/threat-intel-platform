"""
Unit tests for Unit42Collector

Tests IOC extraction, threat name parsing, and data validation
"""

import unittest
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from collectors.unit42_collector import Unit42Collector


class TestUnit42CollectorIOCExtraction(unittest.TestCase):
    """Test IOC extraction from threat report text"""

    def setUp(self):
        self.collector = Unit42Collector()

    def test_ipv4_extraction(self):
        """Test IPv4 address extraction"""
        content = """
        The malware communicates with the following C2 servers:
        192.0.2.1
        198.51.100.42
        203.0.113.99
        """
        iocs = self.collector._extract_iocs(content)

        self.assertIn('192.0.2.1', iocs['ips'])
        self.assertIn('198.51.100.42', iocs['ips'])
        self.assertIn('203.0.113.99', iocs['ips'])

    def test_ipv4_private_filtering(self):
        """Test that private IPs are filtered out"""
        content = """
        C2 infrastructure:
        192.0.2.1        (public)
        10.0.0.1         (private - should be filtered)
        172.16.0.1       (private - should be filtered)
        192.168.1.1      (private - should be filtered)
        127.0.0.1        (loopback - should be filtered)
        """
        iocs = self.collector._extract_iocs(content)

        self.assertIn('192.0.2.1', iocs['ips'])
        self.assertNotIn('10.0.0.1', iocs['ips'])
        self.assertNotIn('172.16.0.1', iocs['ips'])
        self.assertNotIn('192.168.1.1', iocs['ips'])
        self.assertNotIn('127.0.0.1', iocs['ips'])

    def test_domain_extraction(self):
        """Test domain name extraction"""
        content = """
        Malware domains:
        malware.example.com
        trojan.evil.net
        botnet.badactor.org
        """
        iocs = self.collector._extract_iocs(content)

        self.assertIn('malware.example.com', iocs['domains'])
        self.assertIn('trojan.evil.net', iocs['domains'])
        self.assertIn('botnet.badactor.org', iocs['domains'])

    def test_domain_false_positive_filtering(self):
        """Test filtering of false positive domains"""
        content = """
        Mentioned in report:
        example.com         (false positive - should be filtered)
        github.com          (false positive - should be filtered)
        google.com          (false positive - should be filtered)
        malware-c2.com      (legitimate IOC)
        """
        iocs = self.collector._extract_iocs(content)

        self.assertNotIn('example.com', iocs['domains'])
        self.assertNotIn('github.com', iocs['domains'])
        self.assertNotIn('google.com', iocs['domains'])
        self.assertIn('malware-c2.com', iocs['domains'])

    def test_url_extraction(self):
        """Test URL extraction"""
        content = """
        Distribution URLs:
        https://malware-server.com/payload.exe
        http://trojan.evil.net/dropper
        https://botnet.net/c2/callback
        """
        iocs = self.collector._extract_iocs(content)

        self.assertIn('https://malware-server.com/payload.exe', iocs['urls'])
        self.assertIn('http://trojan.evil.net/dropper', iocs['urls'])
        self.assertIn('https://botnet.net/c2/callback', iocs['urls'])

    def test_md5_extraction(self):
        """Test MD5 hash extraction"""
        content = """
        File hashes:
        MD5: 5d41402abc4b2a76b9719d911017c592
        d41d8cd98f00b204e9800998ecf8427e
        """
        iocs = self.collector._extract_iocs(content)

        hashes = [h['hash'] for h in iocs['hashes']]
        self.assertIn('5d41402abc4b2a76b9719d911017c592', hashes)
        self.assertIn('d41d8cd98f00b204e9800998ecf8427e', hashes)

    def test_sha1_extraction(self):
        """Test SHA1 hash extraction"""
        content = """
        SHA1: da39a3ee5e6b4b0d3255bfef95601890afd80709
        356a192b7913b04c54574d18c28d46e6395428ab
        """
        iocs = self.collector._extract_iocs(content)

        hashes = [h['hash'] for h in iocs['hashes']]
        self.assertIn('da39a3ee5e6b4b0d3255bfef95601890afd80709', hashes)
        self.assertIn('356a192b7913b04c54574d18c28d46e6395428ab', hashes)

    def test_sha256_extraction(self):
        """Test SHA256 hash extraction"""
        content = """
        SHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        4e07408fb8d1f27360afe4323205dd402985d89519213efc52f517853701415
        """
        iocs = self.collector._extract_iocs(content)

        hashes = [h['hash'] for h in iocs['hashes']]
        self.assertIn('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', hashes)
        self.assertIn('4e07408fb8d1f27360afe4323205dd402985d89519213efc52f517853701415', hashes)

    def test_deduplication(self):
        """Test that duplicate IOCs are removed"""
        content = """
        Malware domains:
        malware.com
        malware.com
        evil.net
        evil.net
        evil.net
        """
        iocs = self.collector._extract_iocs(content)

        # Count occurrences
        malware_count = iocs['domains'].count('malware.com')
        evil_count = iocs['domains'].count('evil.net')

        self.assertEqual(malware_count, 1, "Duplicates should be removed")
        self.assertEqual(evil_count, 1, "Duplicates should be removed")

    def test_mixed_ioc_types(self):
        """Test extraction of multiple IOC types from single content"""
        content = """
        THREAT REPORT: Emotet Campaign

        C2 Infrastructure:
        - IP: 192.0.2.1
        - Domain: emotet-c2.net
        - URL: https://emotet-c2.net/api/endpoint

        Malware Hashes:
        - MD5: 5d41402abc4b2a76b9719d911017c592
        - SHA1: da39a3ee5e6b4b0d3255bfef95601890afd80709
        - SHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        """
        iocs = self.collector._extract_iocs(content)

        # Verify all types are extracted
        self.assertTrue(len(iocs['ips']) > 0)
        self.assertTrue(len(iocs['domains']) > 0)
        self.assertTrue(len(iocs['urls']) > 0)
        self.assertTrue(len(iocs['hashes']) > 0)


class TestUnit42CollectorThreatNameExtraction(unittest.TestCase):
    """Test threat name extraction from filenames"""

    def setUp(self):
        self.collector = Unit42Collector()

    def test_emotet_extraction(self):
        """Test Emotet threat name extraction"""
        filename = "2020-08-20-IOCs-for-Emotet-infection-with-spam.txt"
        threat_name = self.collector._extract_threat_name(filename)
        self.assertEqual(threat_name, "Emotet")

    def test_cobalt_strike_extraction(self):
        """Test Cobalt Strike threat name extraction"""
        filename = "2020-11-16-IOCs-for-Cobalt-Strike-activity.txt"
        threat_name = self.collector._extract_threat_name(filename)
        self.assertEqual(threat_name, "Cobalt Strike")

    def test_apt_extraction(self):
        """Test APT threat name extraction"""
        filename = "2023-06-15-IOCs-for-APT28-campaign-targeting-ukraine.txt"
        threat_name = self.collector._extract_threat_name(filename)
        self.assertIn("Apt28", threat_name)

    def test_ransomware_extraction(self):
        """Test ransomware threat name extraction"""
        filename = "2023-05-20-IOCs-for-LockBit-ransomware-attack.txt"
        threat_name = self.collector._extract_threat_name(filename)
        self.assertEqual(threat_name, "Lockbit")


class TestUnit42CollectorValidation(unittest.TestCase):
    """Test private IP and false positive filtering"""

    def setUp(self):
        self.collector = Unit42Collector()

    def test_private_ip_detection(self):
        """Test private IP detection"""
        # Private IPs
        self.assertTrue(self.collector._is_private_ip('10.0.0.1'))
        self.assertTrue(self.collector._is_private_ip('172.16.0.1'))
        self.assertTrue(self.collector._is_private_ip('192.168.1.1'))
        self.assertTrue(self.collector._is_private_ip('127.0.0.1'))

        # Public IPs
        self.assertFalse(self.collector._is_private_ip('8.8.8.8'))
        self.assertFalse(self.collector._is_private_ip('1.1.1.1'))

    def test_false_positive_domain_detection(self):
        """Test false positive domain detection"""
        # False positives
        self.assertTrue(self.collector._is_false_positive_domain('example.com'))
        self.assertTrue(self.collector._is_false_positive_domain('github.com'))
        self.assertTrue(self.collector._is_false_positive_domain('google.com'))
        self.assertTrue(self.collector._is_false_positive_domain('readme'))

        # Legitimate IOCs
        self.assertFalse(self.collector._is_false_positive_domain('malware.com'))
        self.assertFalse(self.collector._is_false_positive_domain('emotet-c2.net'))


class TestUnit42CollectorOutput(unittest.TestCase):
    """Test standardized output format"""

    def setUp(self):
        self.collector = Unit42Collector()

    def test_empty_analysis_structure(self):
        """Test empty analysis returns proper structure"""
        analysis = self.collector._empty_analysis()

        # Verify all required fields exist
        required_fields = [
            'task_id', 'source', 'file', 'verdict',
            'c2_domains', 'c2_ips', 'file_hashes', 'download_urls',
            'malware_families', 'sentiment'
        ]

        for field in required_fields:
            self.assertIn(field, analysis, f"Missing field: {field}")

    def test_analysis_standardization(self):
        """Test that analysis is standardized properly"""
        iocs = {
            'domains': ['malware.com'],
            'ips': ['192.0.2.1'],
            'urls': ['https://malware.com/payload'],
            'hashes': [{'hash': 'abc123', 'type': 'md5'}],
            'threat_names': ['Emotet']
        }

        analysis = self.collector._build_analysis(iocs)

        # Verify analysis structure
        self.assertEqual(analysis['c2_domains'], ['malware.com'])
        self.assertEqual(analysis['c2_ips'], ['192.0.2.1'])
        self.assertEqual(analysis['download_urls'], ['https://malware.com/payload'])
        self.assertEqual(len(analysis['file_hashes']), 1)
        self.assertEqual(analysis['verdict'], 'malicious')


if __name__ == '__main__':
    unittest.main()
