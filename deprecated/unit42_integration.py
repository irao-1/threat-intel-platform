"""
Unit42 Threat Intelligence Integration Example

Fetch FREE threat data from Palo Alto Networks Unit42 GitHub repository
and correlate with TweetFeed

This replaces the paid AutoFocus integration entirely.

Repository: https://github.com/PaloAltoNetworks/Unit42-timely-threat-intel

Usage:
  python -m examples.unit42_integration [--days-back DAYS] [--limit FILES] [--correlate]

Features:
  - No API key required (free public GitHub data)
  - Automatic IOC extraction (domains, IPs, hashes, URLs)
  - Integration with TweetFeed for threat correlation
  - STIX export support
  - Local caching for performance

Examples:
  # Fetch Unit42 reports from last 30 days (top 5 files)
  python -m examples.unit42_integration

  # Fetch from last 60 days, process up to 10 files
  python -m examples.unit42_integration --days-back 60 --limit 10

  # Correlate with TweetFeed and export as STIX
  python -m examples.unit42_integration --correlate --format stix --output unit42_correlation.json

  # Use custom GitHub token for higher API rate limits
  export GITHUB_TOKEN="your_token_here"
  python -m examples.unit42_integration --limit 20
"""

import argparse
import sys
from pathlib import Path
import os

sys.path.insert(0, str(Path(__file__).parent.parent))

from collectors.unit42_collector import Unit42Collector
from collectors.tweet_parser_collector import TweetParserCollector
from converters.threat_to_stix import ThreatToSTIX
from db.threat_history import ThreatHistory
import json


def parse_arguments():
    """Parse command-line arguments"""
    parser = argparse.ArgumentParser(
        description='Unit42 FREE Threat Intelligence Integration',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Setup:

  1. No API key required! Unit42 publishes threat reports on GitHub:
     https://github.com/PaloAltoNetworks/Unit42-timely-threat-intel

  2. (Optional) For higher GitHub API rate limits, get a personal access token:
     https://github.com/settings/tokens

  3. Set environment variable (optional):
     export GITHUB_TOKEN="your_github_token"

  4. Set cache directory (optional):
     export UNIT42_CACHE_DIR="/path/to/cache"

Examples:

  # Fetch recent Unit42 threat reports and extract IOCs
  python -m examples.unit42_integration

  # Fetch from last 60 days with more files
  python -m examples.unit42_integration --days-back 60 --limit 10

  # Correlate Unit42 intelligence with TweetFeed for confidence scoring
  python -m examples.unit42_integration --correlate

  # Export as STIX format for integration with other systems
  python -m examples.unit42_integration --format stix --output unit42_threats.json

  # Full workflow: fetch, correlate, and export
  python -m examples.unit42_integration --correlate --format stix --output results.json

Threat Intelligence:

  Unit42 covers:
  - APT campaigns and actor intelligence
  - Malware family analysis (Emotet, Cobalt Strike, etc.)
  - Ransomware threat indicators
  - C2 infrastructure IOCs
  - Malware distribution networks

  IOCs Extracted:
  - Domains (C2, phishing, malware hosting)
  - IP Addresses (C2 infrastructure, command servers)
  - File Hashes (MD5, SHA1, SHA256)
  - URLs (malware distribution, C2 callbacks)

Cost Comparison:

  Palo Alto AutoFocus (Paid):
  - $$$$ per year
  - Requires API key and subscription
  - Advanced features (campaigns, signatures, etc.)

  Unit42 (Free):
  - FREE
  - No API key required
  - Public GitHub repository
  - IOC extraction and basic analysis
  - Perfect for threat hunting and detection engineering
        """
    )

    parser.add_argument(
        '--days-back',
        type=int,
        default=30,
        help='Number of days to look back for threat reports (default: 30)'
    )

    parser.add_argument(
        '--limit',
        type=int,
        default=5,
        help='Maximum number of threat report files to process (default: 5)'
    )

    parser.add_argument(
        '--correlate',
        action='store_true',
        help='Correlate with TweetFeed threats for confidence scoring'
    )

    parser.add_argument(
        '--format',
        choices=['json', 'stix'],
        default='json',
        help='Output format (default: json)'
    )

    parser.add_argument(
        '--output',
        type=str,
        help='Output file (if not specified, prints to stdout)'
    )

    return parser.parse_args()


def fetch_unit42_threats(days_back, limit):
    """Fetch threats from Unit42"""
    print("\n" + "="*70)
    print("FREE THREAT INTELLIGENCE: PALO ALTO NETWORKS UNIT42")
    print("="*70 + "\n")

    collector = Unit42Collector()

    print(f"📡 Fetching Unit42 threat reports from last {days_back} days...")
    print(f"   Repository: https://github.com/PaloAltoNetworks/Unit42-timely-threat-intel")
    print(f"   Processing up to {limit} files...\n")

    analysis = collector.get_analysis(days_back=days_back, limit=limit)

    # Display results
    print(f"✅ Analysis Complete!\n")
    print(f"Source: {analysis.get('source')}")
    print(f"Timestamp: {analysis.get('task_id')}\n")

    print(f"📊 EXTRACTED THREAT INDICATORS:\n")

    print(f"   🌐 C2 Domains: {len(analysis['c2_domains'])}")
    if analysis['c2_domains']:
        for domain in analysis['c2_domains'][:5]:
            # Show threat context from malware_families if available
            threat_context = ""
            if analysis.get('malware_families'):
                threat_context = f" [{analysis['malware_families'][0]}]"
            print(f"      - {domain}{threat_context}")
        if len(analysis['c2_domains']) > 5:
            print(f"      ... and {len(analysis['c2_domains']) - 5} more")
    else:
        print(f"      (none found)")

    print(f"\n   🖥️  C2 IP Addresses: {len(analysis['c2_ips'])}")
    if analysis['c2_ips']:
        for ip in analysis['c2_ips'][:5]:
            threat_context = ""
            if analysis.get('malware_families'):
                threat_context = f" [{analysis['malware_families'][0]}]"
            print(f"      - {ip}{threat_context}")
        if len(analysis['c2_ips']) > 5:
            print(f"      ... and {len(analysis['c2_ips']) - 5} more")
    else:
        print(f"      (none found)")

    print(f"\n   🔗 Malicious URLs: {len(analysis['download_urls'])}")
    if analysis['download_urls']:
        for url in analysis['download_urls'][:3]:
            threat_context = ""
            if analysis.get('malware_families'):
                threat_context = f" [{analysis['malware_families'][0]}]"
            print(f"      - {url}{threat_context}")
        if len(analysis['download_urls']) > 3:
            print(f"      ... and {len(analysis['download_urls']) - 3} more (malware hosting/distribution)")
    else:
        print(f"      (none found)")

    print(f"\n   🔐 File Hashes: {len(analysis['file_hashes'])}")
    if analysis['file_hashes']:
        hash_types = {}
        for h in analysis['file_hashes']:
            hash_type = h.get('type', 'unknown').upper()
            hash_types[hash_type] = hash_types.get(hash_type, 0) + 1

        for hash_type, count in hash_types.items():
            print(f"      - {hash_type}: {count}")

        print(f"\n      Sample hashes:")
        for h in analysis['file_hashes'][:3]:
            print(f"      - {h['hash'][:16]}... ({h['type']})")
        if len(analysis['file_hashes']) > 3:
            print(f"      ... and {len(analysis['file_hashes']) - 3} more")
    else:
        print(f"      (none found)")

    print(f"\n   ⚔️  Malware Families: {len(analysis['malware_families'])}")
    if analysis['malware_families']:
        for malware in analysis['malware_families'][:5]:
            print(f"      - {malware}")
        if len(analysis['malware_families']) > 5:
            print(f"      ... and {len(analysis['malware_families']) - 5} more")
    else:
        print(f"      (none identified)")

    print(f"\n   🎚️  Severity: {analysis['sentiment']}\n")

    return analysis


def correlate_with_tweetfeed(unit42_analysis):
    """Correlate Unit42 threats with TweetFeed"""
    print("\n" + "="*70)
    print("THREAT CORRELATION: UNIT42 + TWEETFEED")
    print("="*70 + "\n")

    # Fetch TweetFeed data
    print("📡 Fetching TweetFeed data for correlation...")
    tweetfeed_collector = TweetParserCollector()
    tweetfeed_analysis = tweetfeed_collector.get_analysis(time_window='week')

    # Find overlaps
    unit42_domains = set(unit42_analysis.get('c2_domains', []))
    tweetfeed_domains = set(tweetfeed_analysis.get('c2_domains', []))
    overlap_domains = unit42_domains & tweetfeed_domains

    unit42_ips = set(unit42_analysis.get('c2_ips', []))
    tweetfeed_ips = set(tweetfeed_analysis.get('c2_ips', []))
    overlap_ips = unit42_ips & tweetfeed_ips

    unit42_hashes = set(h['hash'] for h in unit42_analysis.get('file_hashes', []))
    tweetfeed_hashes = set(h['hash'] for h in tweetfeed_analysis.get('file_hashes', []))
    overlap_hashes = unit42_hashes & tweetfeed_hashes

    print(f"\n✅ Correlation Results:\n")

    print(f"Unit42 Indicators:")
    print(f"   🌐 Domains: {len(unit42_domains)}")
    print(f"   🖥️  IPs: {len(unit42_ips)}")
    print(f"   🔐 Hashes: {len(unit42_hashes)}\n")

    print(f"TweetFeed Indicators:")
    print(f"   🌐 Domains: {len(tweetfeed_domains)}")
    print(f"   🖥️  IPs: {len(tweetfeed_ips)}")
    print(f"   🔐 Hashes: {len(tweetfeed_hashes)}\n")

    print(f"📊 OVERLAPPING IOCs (Reported by Both Sources):")
    print(f"   🌐 Domains: {len(overlap_domains)}")
    if overlap_domains:
        for domain in list(overlap_domains)[:5]:
            print(f"      - {domain}")
        if len(overlap_domains) > 5:
            print(f"      ... and {len(overlap_domains) - 5} more")
    else:
        print(f"      (no overlaps)")

    print(f"\n   🖥️  IPs: {len(overlap_ips)}")
    if overlap_ips:
        for ip in list(overlap_ips)[:5]:
            print(f"      - {ip}")
        if len(overlap_ips) > 5:
            print(f"      ... and {len(overlap_ips) - 5} more")
    else:
        print(f"      (no overlaps)")

    print(f"\n   🔐 Hashes: {len(overlap_hashes)}")
    if overlap_hashes:
        for h in list(overlap_hashes)[:3]:
            print(f"      - {h}")
        if len(overlap_hashes) > 3:
            print(f"      ... and {len(overlap_hashes) - 3} more")
    else:
        print(f"      (no overlaps)")

    print(f"\n💡 Threat Intelligence Insights:")

    total_overlaps = len(overlap_domains) + len(overlap_ips) + len(overlap_hashes)
    total_unit42 = len(unit42_domains) + len(unit42_ips) + len(unit42_hashes)
    total_tweetfeed = len(tweetfeed_domains) + len(tweetfeed_ips) + len(tweetfeed_hashes)

    if total_overlaps > 0:
        confidence = (total_overlaps / max(total_unit42, total_tweetfeed)) * 100
        print(f"   ✓ HIGH CONFIDENCE: {total_overlaps} IOCs corroborated by both sources")
        print(f"   ✓ Confidence Score: {confidence:.1f}%")
        print(f"   ✓ Recommendation: These IOCs are suitable for:")
        print(f"      - Firewall/IDS blocking rules")
        print(f"      - SIEM alerts and monitoring")
        print(f"      - Threat hunting campaigns")
    else:
        print(f"   ✓ UNIQUE INTELLIGENCE from each source")
        print(f"   ✓ Unit42: {total_unit42} IOCs (formal threat reports)")
        print(f"   ✓ TweetFeed: {total_tweetfeed} IOCs (active threat discussions)")
        print(f"   ✓ Recommendation: Use combined intelligence for comprehensive coverage")

    print()

    return {
        'unit42': unit42_analysis,
        'tweetfeed': tweetfeed_analysis,
        'overlaps': {
            'domains': list(overlap_domains),
            'ips': list(overlap_ips),
            'hashes': list(overlap_hashes)
        },
        'correlation_metadata': {
            'timestamp': str(datetime.utcnow()),
            'unit42_indicators': total_unit42,
            'tweetfeed_indicators': total_tweetfeed,
            'overlapping_indicators': total_overlaps
        }
    }


def export_results(analysis, fmt, output_file):
    """Export correlated results"""
    if fmt == 'stix':
        # Create STIX bundle
        stix_data = ThreatToSTIX.convert(analysis)
        output = json.dumps(stix_data, indent=2)
    else:
        output = json.dumps(analysis, indent=2)

    if output_file:
        try:
            with open(output_file, 'w') as f:
                f.write(output)
            print(f"\n✅ Results exported to: {output_file}\n")
        except Exception as e:
            print(f"\n❌ Error writing to {output_file}: {e}\n")
    else:
        print(f"\n📄 Results:\n{output}\n")


def main():
    args = parse_arguments()

    # Fetch Unit42 threats
    unit42_analysis = fetch_unit42_threats(args.days_back, args.limit)

    # Correlate with TweetFeed if requested
    if args.correlate:
        correlated = correlate_with_tweetfeed(unit42_analysis)
        export_results(correlated, args.format, args.output)
    else:
        export_results(unit42_analysis, args.format, args.output)

    print("\n" + "="*70)
    print("Unit42 Threat Intelligence Collection Complete")
    print("="*70 + "\n")

    print("Next Steps:")
    print("  1. Review extracted IOCs above")
    print("  2. Use domains/IPs for firewall blocking rules")
    print("  3. Use hashes for YARA/signature generation")
    print("  4. Create SIEM alerts for URL patterns")
    print("  5. Research threat actors and malware families")
    print()


if __name__ == '__main__':
    from datetime import datetime
    main()
