"""
Palo Alto Networks Integration Example

Fetch threat data from Palo Alto and correlate with TweetFeed

Usage:
  python -m examples.paloalto_integration [--api-key KEY] [--source autofocus|wildfire|unit42]

Set PALO_ALTO_API_KEY environment variable or pass --api-key
"""

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from collectors.paloalto_collector import PaloAltoCollector
from collectors.tweet_parser_collector import TweetParserCollector
from converters.threat_to_stix import ThreatToSTIX
from db.threat_history import ThreatHistory
import json


def parse_arguments():
    """Parse command-line arguments"""
    parser = argparse.ArgumentParser(
        description='Palo Alto Networks Threat Intelligence Integration',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Setup:
  1. Get Palo Alto AutoFocus API key from:
     https://autofocus.paloaltonetworks.com/api/

  2. Set environment variable:
     export PALO_ALTO_API_KEY="your_api_key_here"

  3. Or pass via command line:
     python -m examples.paloalto_integration --api-key "your_key"

Examples:
  # Fetch AutoFocus threats from last 7 days
  python -m examples.paloalto_integration --source autofocus

  # Fetch WildFire verdicts
  python -m examples.paloalto_integration --source wildfire

  # Fetch Unit42 public intelligence
  python -m examples.paloalto_integration --source unit42

  # Custom AutoFocus query
  python -m examples.paloalto_integration --source autofocus --query "file_type:PE"
        """
    )

    parser.add_argument(
        '--api-key',
        type=str,
        help='Palo Alto AutoFocus API key (or set PALO_ALTO_API_KEY env var)'
    )

    parser.add_argument(
        '--source',
        choices=['autofocus', 'wildfire', 'unit42'],
        default='autofocus',
        help='Palo Alto source (default: autofocus)'
    )

    parser.add_argument(
        '--query',
        type=str,
        help='AutoFocus query (e.g., "file_type:PE")'
    )

    parser.add_argument(
        '--correlate',
        action='store_true',
        help='Correlate with TweetFeed threats'
    )

    parser.add_argument(
        '--format',
        choices=['json', 'stix'],
        default='json',
        help='Output format'
    )

    parser.add_argument(
        '--output',
        type=str,
        help='Output file'
    )

    return parser.parse_args()


def fetch_paloalto_threats(api_key, source, query):
    """Fetch threats from Palo Alto"""
    print("\n" + "="*70)
    print("🔐 PALO ALTO NETWORKS THREAT INTELLIGENCE")
    print("="*70 + "\n")

    collector = PaloAltoCollector(api_key=api_key)

    print(f"📡 Fetching from Palo Alto {source.upper()}...")

    if source == 'autofocus':
        analysis = collector.get_analysis(source=source, query=query)
    else:
        analysis = collector.get_analysis(source=source)

    # Display results
    print(f"\n✅ Analysis Complete!\n")
    print(f"Source: {analysis.get('source')}")
    print(f"Timestamp: {analysis.get('task_id')}\n")

    print(f"📊 EXTRACTED INDICATORS:")
    print(f"   🌐 Domains: {len(analysis['c2_domains'])}")
    if analysis['c2_domains']:
        for domain in analysis['c2_domains'][:5]:
            print(f"      - {domain}")
        if len(analysis['c2_domains']) > 5:
            print(f"      ... and {len(analysis['c2_domains']) - 5} more")

    print(f"\n   🖥️  IPs: {len(analysis['c2_ips'])}")
    if analysis['c2_ips']:
        for ip in analysis['c2_ips'][:5]:
            print(f"      - {ip}")
        if len(analysis['c2_ips']) > 5:
            print(f"      ... and {len(analysis['c2_ips']) - 5} more")

    print(f"\n   🔗 URLs: {len(analysis['download_urls'])}")
    if analysis['download_urls']:
        for url in analysis['download_urls'][:3]:
            print(f"      - {url}")
        if len(analysis['download_urls']) > 3:
            print(f"      ... and {len(analysis['download_urls']) - 3} more")

    print(f"\n   🔐 Hashes: {len(analysis['file_hashes'])}")
    if analysis['file_hashes']:
        for h in analysis['file_hashes'][:3]:
            print(f"      - {h['hash'][:16]}... ({h['type']})")
        if len(analysis['file_hashes']) > 3:
            print(f"      ... and {len(analysis['file_hashes']) - 3} more")

    print(f"\n   ⚔️  Malware Families: {len(analysis['malware_families'])}")
    if analysis['malware_families']:
        for malware in analysis['malware_families'][:3]:
            print(f"      - {malware}")

    print(f"\n   🕵️  Threat Actors: {len(analysis['threat_actors'])}")
    if analysis['threat_actors']:
        for actor in analysis['threat_actors'][:3]:
            print(f"      - {actor}")

    print(f"\n   🎯 MITRE Techniques: {len(analysis['mitre_techniques'])}")
    if analysis['mitre_techniques']:
        for tech in analysis['mitre_techniques'][:3]:
            print(f"      - {tech}")

    print(f"\n   🚨 CVEs: {len(analysis['cves'])}")
    if analysis['cves']:
        for cve in analysis['cves'][:3]:
            print(f"      - {cve}")

    print(f"\n   🎚️  Severity: {analysis['sentiment']}\n")

    return analysis


def correlate_with_tweetfeed(paloalto_analysis):
    """Correlate Palo Alto threats with TweetFeed"""
    print("\n" + "="*70)
    print("🔄 CORRELATION: PALO ALTO + TWEETFEED")
    print("="*70 + "\n")

    # Fetch TweetFeed data
    print("📡 Fetching TweetFeed data for correlation...")
    tweetfeed_collector = TweetParserCollector()
    tweetfeed_analysis = tweetfeed_collector.get_analysis(time_window='week')

    # Find overlaps
    pao_domains = set(paloalto_analysis.get('c2_domains', []))
    tweetfeed_domains = set(tweetfeed_analysis.get('c2_domains', []))
    overlap_domains = pao_domains & tweetfeed_domains

    pao_ips = set(paloalto_analysis.get('c2_ips', []))
    tweetfeed_ips = set(tweetfeed_analysis.get('c2_ips', []))
    overlap_ips = pao_ips & tweetfeed_ips

    pao_hashes = set(h['hash'] for h in paloalto_analysis.get('file_hashes', []))
    tweetfeed_hashes = set(h['hash'] for h in tweetfeed_analysis.get('file_hashes', []))
    overlap_hashes = pao_hashes & tweetfeed_hashes

    print(f"✅ Correlation Results:\n")
    print(f"Palo Alto Indicators:")
    print(f"   🌐 Domains: {len(pao_domains)}")
    print(f"   🖥️  IPs: {len(pao_ips)}")
    print(f"   🔐 Hashes: {len(pao_hashes)}\n")

    print(f"TweetFeed Indicators:")
    print(f"   🌐 Domains: {len(tweetfeed_domains)}")
    print(f"   🖥️  IPs: {len(tweetfeed_ips)}")
    print(f"   🔐 Hashes: {len(tweetfeed_hashes)}\n")

    print(f"📊 OVERLAPS (Both sources report same IOCs):")
    print(f"   🌐 Domains: {len(overlap_domains)}")
    if overlap_domains:
        for domain in list(overlap_domains)[:5]:
            print(f"      - {domain}")
        if len(overlap_domains) > 5:
            print(f"      ... and {len(overlap_domains) - 5} more")

    print(f"\n   🖥️  IPs: {len(overlap_ips)}")
    if overlap_ips:
        for ip in list(overlap_ips)[:5]:
            print(f"      - {ip}")
        if len(overlap_ips) > 5:
            print(f"      ... and {len(overlap_ips) - 5} more")

    print(f"\n   🔐 Hashes: {len(overlap_hashes)}")
    if overlap_hashes:
        for h in list(overlap_hashes)[:3]:
            print(f"      - {h}")
        if len(overlap_hashes) > 3:
            print(f"      ... and {len(overlap_hashes) - 3} more")

    print(f"\n💡 Interpretation:")
    print(f"   - HIGH CONFIDENCE: IOCs reported by both Palo Alto and TweetFeed")
    print(f"   - Confidence Score: {len(overlap_domains) + len(overlap_ips) + len(overlap_hashes)} overlaps = high confidence")
    print(f"   - Recommendation: These IOCs suitable for blocklists/alerts\n")

    return {
        'paloalto': paloalto_analysis,
        'tweetfeed': tweetfeed_analysis,
        'overlaps': {
            'domains': list(overlap_domains),
            'ips': list(overlap_ips),
            'hashes': list(overlap_hashes)
        }
    }


def export_results(analysis, fmt, output_file):
    """Export correlated results"""
    if fmt == 'stix':
        # Create STIX bundle with both sources
        stix_data = ThreatToSTIX.convert(analysis)
        output = json.dumps(stix_data, indent=2)
    else:
        output = json.dumps(analysis, indent=2)

    if output_file:
        with open(output_file, 'w') as f:
            f.write(output)
        print(f"\n✅ Results exported to {output_file}\n")
    else:
        print(f"\n📄 Results:\n{output}\n")


def main():
    args = parse_arguments()

    # Fetch Palo Alto threats
    paloalto_analysis = fetch_paloalto_threats(args.api_key, args.source, args.query)

    # Correlate with TweetFeed if requested
    if args.correlate:
        correlated = correlate_with_tweetfeed(paloalto_analysis)
        export_results(correlated, args.format, args.output)
    else:
        export_results(paloalto_analysis, args.format, args.output)


if __name__ == '__main__':
    main()
