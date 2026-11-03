"""
Unit42 Sync Manager CLI

Manage incremental sync of Unit42 threat reports, similar to yarafy.com

Usage:
  python -m examples.unit42_sync_manager sync           # Sync new/updated files
  python -m examples.unit42_sync_manager sync --force   # Force full re-sync
  python -m examples.unit42_sync_manager list           # List stored reports
  python -m examples.unit42_sync_manager history        # Show sync history
  python -m examples.unit42_sync_manager status         # Show sync status
"""

import sys
from pathlib import Path
import argparse

sys.path.insert(0, str(Path(__file__).parent.parent))

from collectors.unit42_sync import Unit42SyncManager
import json


def main():
    parser = argparse.ArgumentParser(
        description='Unit42 Incremental Sync Manager',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:

  # Incremental sync (only new/updated files)
  python -m examples.unit42_sync_manager sync

  # Force full re-sync (download all files)
  python -m examples.unit42_sync_manager sync --force

  # List all stored reports
  python -m examples.unit42_sync_manager list

  # Show sync history
  python -m examples.unit42_sync_manager history

  # Show current status
  python -m examples.unit42_sync_manager status
        """
    )

    subparsers = parser.add_subparsers(dest='command', help='Command to run')

    # Sync command
    sync_parser = subparsers.add_parser('sync', help='Sync Unit42 threat reports')
    sync_parser.add_argument('--force', action='store_true', help='Force full re-sync')
    sync_parser.add_argument('--quiet', action='store_true', help='Quiet mode (minimal output)')

    # List command
    subparsers.add_parser('list', help='List all stored reports')

    # History command
    history_parser = subparsers.add_parser('history', help='Show sync history')
    history_parser.add_argument('--limit', type=int, default=10, help='Number of syncs to show')

    # Status command
    subparsers.add_parser('status', help='Show current sync status')

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return

    sync_manager = Unit42SyncManager()

    if args.command == 'sync':
        quiet = args.quiet if hasattr(args, 'quiet') else False

        if not quiet:
            print("\n" + "="*70)
            print("🔄 UNIT42 INCREMENTAL SYNC")
            print("="*70 + "\n")

        result = sync_manager.sync(force_full=args.force)

        if result['success']:
            if quiet:
                # Quiet mode: just show essential info
                print(f"✅ Sync: {result['new_files']} new, {result['updated_files']} updated ({result['duration_seconds']:.1f}s)")
            else:
                print(f"\n✅ Sync successful!")
                print(f"   📊 Total files in repo: {result['total_files']}")
                print(f"   ➕ New files added: {result['new_files']}")
                print(f"   🔄 Updated files: {result['updated_files']}")
                print(f"   ⏱️  Duration: {result['duration_seconds']:.1f}s\n")
        else:
            error_msg = result['error']
            if quiet:
                print(f"❌ Sync failed: {error_msg}")
            else:
                print(f"\n❌ Sync failed: {error_msg}\n")

            # Show helpful message for rate limit
            if "403" in str(error_msg) and "rate" in str(error_msg).lower():
                print("="*70)
                print("🔐 GITHUB RATE LIMIT - QUICK FIX (30 seconds)")
                print("="*70)
                print("\n1️⃣  Go to: https://github.com/settings/tokens")
                print("2️⃣  Click 'Generate new token (classic)'")
                print("3️⃣  Select scope: 'public_repo' (read-only)")
                print("4️⃣  Copy the token (starts with 'ghp_')")
                print("\n5️⃣  Set environment variable:")
                print('   export GITHUB_TOKEN="ghp_your_token_here"')
                print("\n6️⃣  Run again:")
                print("   python -m examples.unit42_sync_manager sync")
                print("\n💡 This gives you 5,000 API calls/hour instead of 60")
                print("="*70 + "\n")

    elif args.command == 'list':
        print("\n" + "="*70)
        print("📋 STORED UNIT42 THREAT REPORTS")
        print("="*70 + "\n")

        reports = sync_manager.get_all_reports()

        if not reports:
            print("No reports stored yet. Run: python -m examples.unit42_sync_manager sync\n")
        else:
            print(f"Total stored reports: {len(reports)}\n")
            for i, report in enumerate(reports, 1):
                print(f"{i:2d}. {report['filename']}")
                print(f"    Threat: {report['threat_name']}")
                print(f"    Updated: {report['updated_at']}\n")

    elif args.command == 'history':
        print("\n" + "="*70)
        print("📈 SYNC HISTORY")
        print("="*70 + "\n")

        history = sync_manager.get_sync_history(limit=args.limit)

        if not history:
            print("No sync history yet.\n")
        else:
            for i, sync in enumerate(history, 1):
                print(f"{i}. {sync['sync_time']}")
                print(f"   📊 Total: {sync['total_files']} | ➕ New: {sync['new_files']} | 🔄 Updated: {sync['updated_files']}")
                print(f"   ⏱️  Duration: {sync['duration_seconds']:.1f}s\n")

    elif args.command == 'status':
        print("\n" + "="*70)
        print("📊 UNIT42 SYNC STATUS")
        print("="*70 + "\n")

        reports = sync_manager.get_all_reports()
        history = sync_manager.get_sync_history(limit=1)

        print(f"📁 Database: {sync_manager.db_path}")
        print(f"📥 Total reports stored: {len(reports)}\n")

        if history:
            last_sync = history[0]
            print(f"🕐 Last sync: {last_sync['sync_time']}")
            print(f"   New files: {last_sync['new_files']}")
            print(f"   Updated files: {last_sync['updated_files']}")
            print(f"   Total files: {last_sync['total_files']}")
            print(f"   Duration: {last_sync['duration_seconds']:.1f}s\n")
        else:
            print("No sync history. Run: python -m examples.unit42_sync_manager sync\n")


if __name__ == '__main__':
    main()
