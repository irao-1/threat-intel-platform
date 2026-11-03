#!/usr/bin/env python3
"""
STIX/TAXII Converter - TweetFeed to STIX
Fetches from TweetFeed Live, converts to STIX 2.1, saves locally
Incremental sync - only fetches new data on subsequent runs
"""

import json
import sys
from pathlib import Path
from datetime import datetime
from uuid import uuid4

sys.path.insert(0, str(Path(__file__).parent.parent))

from collectors.tweet_parser_collector import TweetParserCollector


class STIXTAXIIConverter:
    """Convert TweetFeed IOCs to STIX 2.1 format for TIP"""

    def __init__(self, output_file="threat-intel-stix.json"):
        self.collector = TweetParserCollector()
        self.output_file = output_file
        self.last_sync_file = output_file.replace(".json", ".sync")
        self.iocs = []

    def get_last_sync_time(self):
        """Get timestamp of last sync"""
        if Path(self.last_sync_file).exists():
            with open(self.last_sync_file, 'r') as f:
                return f.read().strip()
        return None

    def save_sync_time(self):
        """Save current sync timestamp"""
        with open(self.last_sync_file, 'w') as f:
            f.write(datetime.utcnow().isoformat() + "Z")

    def fetch_from_tweetfeed(self):
        """Fetch IOCs from TweetFeed Live"""
        print("\n⏳ Fetching from TweetFeed Live...")

        try:
            data = self.collector.get_analysis(
                time_window='week',
                filter_type=None,
                filter_tag=None
            )

            iocs = []

            # Domains
            for domain in data.get('c2_domains', []):
                iocs.append({
                    'value': domain,
                    'type': 'domain',
                    'category': 'C2 Infrastructure',
                    'source': 'TweetFeed Live'
                })

            # IPs
            for ip in data.get('c2_ips', []):
                iocs.append({
                    'value': ip,
                    'type': 'ip',
                    'category': 'C2 Infrastructure',
                    'source': 'TweetFeed Live'
                })

            # URLs
            for url in data.get('download_urls', []):
                iocs.append({
                    'value': url,
                    'type': 'url',
                    'category': 'Malware Distribution',
                    'source': 'TweetFeed Live'
                })

            # Hashes
            for hash_val in data.get('file_hashes', []):
                iocs.append({
                    'value': hash_val,
                    'type': 'hash',
                    'category': 'Malware Sample',
                    'source': 'TweetFeed Live'
                })

            print(f"✅ Fetched {len(iocs)} IOCs from TweetFeed\n")
            self.iocs = iocs
            return True

        except Exception as e:
            print(f"❌ Error fetching TweetFeed: {e}\n")
            return False

    def create_stix_bundle(self, iocs):
        """Create STIX 2.1 bundle from IOCs"""
        objects = []

        # Add Identity object (source)
        identity = {
            "type": "identity",
            "id": f"identity--{uuid4()}",
            "created": datetime.utcnow().isoformat() + "Z",
            "modified": datetime.utcnow().isoformat() + "Z",
            "name": "TweetFeed Live Threat Intelligence",
            "identity_class": "organization"
        }
        objects.append(identity)

        # Convert each IOC to STIX indicators
        for ioc in iocs:
            ioc_value = ioc.get('value', '')
            ioc_type = ioc.get('type', 'unknown')
            category = ioc.get('category', 'Unknown')

            # Map IOC type to STIX pattern
            if ioc_type == 'domain':
                pattern = f"[domain-name:value = '{ioc_value}']"
            elif ioc_type == 'ip':
                pattern = f"[ipv4-addr:value = '{ioc_value}']"
            elif ioc_type == 'url':
                pattern = f"[url:value = '{ioc_value}']"
            elif ioc_type == 'hash':
                pattern = f"[file:hashes.MD5 = '{ioc_value}']"
            else:
                continue

            # Create STIX indicator
            indicator = {
                "type": "indicator",
                "id": f"indicator--{uuid4()}",
                "created": datetime.utcnow().isoformat() + "Z",
                "modified": datetime.utcnow().isoformat() + "Z",
                "pattern": pattern,
                "pattern_type": "stix",
                "valid_from": datetime.utcnow().isoformat() + "Z",
                "labels": ["malicious-activity"],
                "name": f"{category} - {ioc_type}",
                "confidence": 80,
                "object_marking_refs": ["marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da"],
                "source": ioc.get('source', 'TweetFeed Live')
            }
            objects.append(indicator)

        # Create bundle
        bundle = {
            "type": "bundle",
            "id": f"bundle--{uuid4()}",
            "created": datetime.utcnow().isoformat() + "Z",
            "objects": objects
        }

        return bundle

    def load_existing_bundle(self):
        """Load existing STIX bundle if it exists"""
        if Path(self.output_file).exists():
            try:
                with open(self.output_file, 'r') as f:
                    return json.load(f)
            except Exception as e:
                print(f"⚠️  Could not load existing file: {e}")
        return None

    def merge_bundles(self, existing_bundle, new_bundle):
        """Merge new IOCs into existing bundle"""
        if not existing_bundle:
            return new_bundle

        # Extract IOC values from existing bundle
        existing_ioc_values = set()
        for obj in existing_bundle.get('objects', []):
            if obj.get('type') == 'indicator':
                # Extract value from pattern
                pattern = obj.get('pattern', '')
                if "'" in pattern:
                    value = pattern.split("'")[1]
                    existing_ioc_values.add(value)

        # Only add new indicators that aren't already in bundle
        new_objects = existing_bundle.get('objects', [])

        for obj in new_bundle.get('objects', []):
            if obj.get('type') == 'indicator':
                pattern = obj.get('pattern', '')
                if "'" in pattern:
                    value = pattern.split("'")[1]
                    if value not in existing_ioc_values:
                        new_objects.append(obj)

        return {
            "type": "bundle",
            "id": existing_bundle.get('id', f"bundle--{uuid4()}"),
            "created": existing_bundle.get('created', datetime.utcnow().isoformat() + "Z"),
            "objects": new_objects
        }

    def save_stix_bundle(self):
        """Save STIX bundle to file"""
        if not self.iocs:
            print("❌ No IOCs to save\n")
            return False

        try:
            # Create new bundle
            new_bundle = self.create_stix_bundle(self.iocs)

            # Load existing bundle if it exists
            existing_bundle = self.load_existing_bundle()

            # Merge or use new
            if existing_bundle:
                merged_bundle = self.merge_bundles(existing_bundle, new_bundle)
                num_indicators = len([o for o in merged_bundle.get('objects', []) if o.get('type') == 'indicator'])
                print(f"📦 Merged {len(self.iocs)} new IOCs (total: {num_indicators})")
            else:
                merged_bundle = new_bundle
                print(f"📦 Created new STIX bundle with {len(self.iocs)} IOCs")

            # Save
            with open(self.output_file, 'w') as f:
                json.dump(merged_bundle, f, indent=2)

            # Save sync timestamp
            self.save_sync_time()

            print(f"✅ Saved to: {self.output_file}\n")
            return True

        except Exception as e:
            print(f"❌ Error saving bundle: {e}\n")
            return False

    def show_bundle_stats(self):
        """Show stats about current bundle"""
        bundle = self.load_existing_bundle()

        if not bundle:
            print("❌ No STIX bundle found\n")
            return

        indicators = [o for o in bundle.get('objects', []) if o.get('type') == 'indicator']

        print("\n" + "-"*50)
        print("📊 STIX BUNDLE STATISTICS")
        print("-"*50)
        print(f"Total indicators: {len(indicators)}")

        # By type
        by_type = {}
        for ind in indicators:
            pattern = ind.get('pattern', '')
            if 'domain-name' in pattern:
                ioc_type = 'domain'
            elif 'ipv4-addr' in pattern:
                ioc_type = 'ip'
            elif 'url:value' in pattern:
                ioc_type = 'url'
            elif 'file:hashes' in pattern:
                ioc_type = 'hash'
            else:
                ioc_type = 'unknown'

            by_type[ioc_type] = by_type.get(ioc_type, 0) + 1

        print("\nBy Type:")
        for ioc_type, count in sorted(by_type.items()):
            print(f"  {ioc_type}: {count}")

        last_sync = self.get_last_sync_time()
        if last_sync:
            print(f"\nLast sync: {last_sync}")

        print("-"*50 + "\n")

    def print_stix_bundle(self):
        """Print STIX bundle to console"""
        bundle = self.load_existing_bundle()

        if not bundle:
            print("❌ No STIX bundle found\n")
            return

        print("\n" + json.dumps(bundle, indent=2))

    def main_menu(self):
        """Main menu"""
        while True:
            print("\n" + "="*70)
            print("🔄 STIX/TAXII CONVERTER - TweetFeed to STIX")
            print("="*70)
            print("\nOptions:")
            print("  1. Fetch from TweetFeed & save as STIX")
            print("  2. Show STIX bundle statistics")
            print("  3. View STIX bundle (console)")
            print("  0. Exit\n")

            try:
                choice = input("Enter choice (0-3): ").strip()

                if choice == "0":
                    print("\n👋 Goodbye!\n")
                    break
                elif choice == "1":
                    if self.fetch_from_tweetfeed():
                        self.save_stix_bundle()
                elif choice == "2":
                    self.show_bundle_stats()
                elif choice == "3":
                    self.print_stix_bundle()
                else:
                    print("❌ Invalid choice\n")
            except KeyboardInterrupt:
                print("\n\n👋 Interrupted. Goodbye!\n")
                break


def main():
    print("\n" + "="*70)
    print("🔄 STIX/TAXII CONVERTER")
    print("="*70)
    print("Convert TweetFeed IOCs to STIX 2.1 for TIP integration")
    print("Incremental sync - saves locally, only fetches new data\n")

    converter = STIXTAXIIConverter()
    converter.main_menu()


if __name__ == '__main__':
    main()
