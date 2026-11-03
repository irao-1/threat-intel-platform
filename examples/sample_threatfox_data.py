"""
Generate sample ThreatFox IOCs for dashboard testing

This creates mock ThreatFox data so we can test the dashboard
without waiting for live API calls to complete.
"""

import json
from datetime import datetime, timedelta

# Sample ThreatFox IOCs
SAMPLE_THREATFOX_IOCS = [
    {
        "ioc": "malware-c2.com",
        "ioc_type": "domain",
        "threat_type": "malware_c2",
        "malware_family": "Emotet",
        "malware_printable": "Emotet",
        "confidence_level": 95,
        "first_seen": (datetime.now() - timedelta(days=3)).isoformat(),
        "last_seen": (datetime.now() - timedelta(hours=2)).isoformat(),
        "tags": ["emotet", "trojan", "banking"],
        "reference": "https://threatfox.abuse.ch/ioc/abc123"
    },
    {
        "ioc": "192.168.1.100",
        "ioc_type": "ip",
        "threat_type": "malware_c2",
        "malware_family": "Cobalt Strike",
        "malware_printable": "Cobalt Strike",
        "confidence_level": 92,
        "first_seen": (datetime.now() - timedelta(days=5)).isoformat(),
        "last_seen": (datetime.now() - timedelta(hours=1)).isoformat(),
        "tags": ["cobalt-strike", "apt", "c2"],
        "reference": "https://threatfox.abuse.ch/ioc/def456"
    },
    {
        "ioc": "http://ransomware-payment.ru/pay",
        "ioc_type": "url",
        "threat_type": "malware_download",
        "malware_family": "LockBit",
        "malware_printable": "LockBit Ransomware",
        "confidence_level": 98,
        "first_seen": (datetime.now() - timedelta(days=2)).isoformat(),
        "last_seen": datetime.now().isoformat(),
        "tags": ["ransomware", "lockbit", "payment"],
        "reference": "https://threatfox.abuse.ch/ioc/ghi789"
    },
    {
        "ioc": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
        "ioc_type": "hash",
        "threat_type": "malware_sample",
        "malware_family": "TrickBot",
        "malware_printable": "TrickBot Banking Trojan",
        "confidence_level": 91,
        "first_seen": (datetime.now() - timedelta(days=7)).isoformat(),
        "last_seen": (datetime.now() - timedelta(hours=12)).isoformat(),
        "tags": ["trickbot", "banker", "trojan"],
        "reference": "https://threatfox.abuse.ch/ioc/jkl012"
    },
    {
        "ioc": "phishing-kit.onion",
        "ioc_type": "domain",
        "threat_type": "phishing",
        "malware_family": "Phishing Kit",
        "malware_printable": "Generic Phishing Kit",
        "confidence_level": 87,
        "first_seen": (datetime.now() - timedelta(days=1)).isoformat(),
        "last_seen": datetime.now().isoformat(),
        "tags": ["phishing", "credential-theft"],
        "reference": "https://threatfox.abuse.ch/ioc/mno345"
    },
    {
        "ioc": "45.142.120.1",
        "ioc_type": "ip",
        "threat_type": "malware_c2",
        "malware_family": "Conti",
        "malware_printable": "Conti Ransomware",
        "confidence_level": 96,
        "first_seen": (datetime.now() - timedelta(days=4)).isoformat(),
        "last_seen": (datetime.now() - timedelta(hours=3)).isoformat(),
        "tags": ["conti", "ransomware", "apt"],
        "reference": "https://threatfox.abuse.ch/ioc/pqr678"
    },
    {
        "ioc": "e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
        "ioc_type": "hash",
        "threat_type": "malware_sample",
        "malware_family": "Qbot",
        "malware_printable": "Qbot Worm",
        "confidence_level": 89,
        "first_seen": (datetime.now() - timedelta(days=6)).isoformat(),
        "last_seen": (datetime.now() - timedelta(hours=6)).isoformat(),
        "tags": ["qbot", "worm", "loader"],
        "reference": "https://threatfox.abuse.ch/ioc/stu901"
    },
    {
        "ioc": "https://malware-dist.net/payload.exe",
        "ioc_type": "url",
        "threat_type": "malware_download",
        "malware_family": "Dridex",
        "malware_printable": "Dridex Banking Malware",
        "confidence_level": 93,
        "first_seen": (datetime.now() - timedelta(days=3)).isoformat(),
        "last_seen": (datetime.now() - timedelta(hours=4)).isoformat(),
        "tags": ["dridex", "banking", "malware"],
        "reference": "https://threatfox.abuse.ch/ioc/vwx234"
    }
]

def get_sample_threatfox_iocs():
    """Return sample ThreatFox IOCs for testing"""
    return SAMPLE_THREATFOX_IOCS

def print_sample_iocs():
    """Display sample IOCs in human-readable format"""
    print("\n📊 Sample ThreatFox IOCs for Testing\n")
    print("=" * 80)

    for i, ioc in enumerate(SAMPLE_THREATFOX_IOCS, 1):
        print(f"\n{i}. {ioc['ioc_type'].upper()}: {ioc['ioc']}")
        print(f"   Threat: {ioc['malware_printable']}")
        print(f"   Confidence: {ioc['confidence_level']}%")
        print(f"   Tags: {', '.join(ioc['tags'])}")
        print(f"   Seen: {ioc['first_seen'][:10]} → {ioc['last_seen'][:10]}")

    print("\n" + "=" * 80)
    print(f"\n✅ Total: {len(SAMPLE_THREATFOX_IOCS)} sample IOCs ready for testing")

if __name__ == "__main__":
    print_sample_iocs()

    # Also save as JSON for reference
    with open('/tmp/threatfox_sample_iocs.json', 'w') as f:
        json.dump(SAMPLE_THREATFOX_IOCS, f, indent=2)
    print("\n💾 Saved to: /tmp/threatfox_sample_iocs.json")
