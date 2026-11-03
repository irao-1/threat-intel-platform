"""
Unit42 Incremental Sync Manager

Like yarafy.com, this maintains a local database of Unit42 threat reports
and only syncs new/updated files from GitHub.

First run: Downloads all Unit42 files
Next runs: Only fetches files modified after last_run_time

Database schema:
  - unit42_reports: Stores threat reports (filename, content, timestamps)
  - sync_metadata: Tracks last sync time and state
"""

import sqlite3
import requests
import os
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from pathlib import Path
import json

logging.basicConfig(level=logging.WARNING)  # Changed from INFO to WARNING for quiet operation
logger = logging.getLogger(__name__)


class Unit42SyncManager:
    """
    Manages incremental sync of Unit42 threat reports to local SQLite database

    Similar to: yarafy.com, apt-notes, YARA rule repositories
    - First sync: Clone all files
    - Subsequent syncs: Only fetch what's new/updated
    - Automatic timestamp tracking
    """

    def __init__(self, db_path: str = "/tmp/unit42_sync.db", github_token: Optional[str] = None):
        """
        Initialize Unit42 sync manager

        Args:
            db_path: Path to SQLite database
            github_token: Optional GitHub API token (for higher rate limits)
        """
        self.db_path = db_path
        self.github_token = github_token or os.getenv('GITHUB_TOKEN')

        self.repo_owner = "PaloAltoNetworks"
        self.repo_name = "Unit42-timely-threat-intel"
        self.api_base = f"https://api.github.com/repos/{self.repo_owner}/{self.repo_name}"

        # Create database
        self._init_database()

    def _init_database(self):
        """Initialize SQLite database schema"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Main table: Unit42 threat reports
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS unit42_reports (
                id INTEGER PRIMARY KEY,
                filename TEXT UNIQUE NOT NULL,
                content TEXT NOT NULL,
                threat_name TEXT,
                github_modified_at TEXT,
                downloaded_at TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                file_hash TEXT
            )
        """)

        # Metadata table: Sync state
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS sync_metadata (
                id INTEGER PRIMARY KEY,
                last_sync_time TEXT,
                last_sync_status TEXT,
                total_files INTEGER,
                new_files INTEGER,
                updated_files INTEGER,
                sync_duration_seconds REAL
            )
        """)

        # IOCs cache: Pre-parsed indicators
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS unit42_iocs (
                id INTEGER PRIMARY KEY,
                report_filename TEXT NOT NULL,
                ioc_type TEXT NOT NULL,  -- 'domain', 'ip', 'url', 'hash'
                ioc_value TEXT NOT NULL,
                hash_type TEXT,  -- For hashes: md5, sha1, sha256
                extracted_at TEXT NOT NULL,
                FOREIGN KEY (report_filename) REFERENCES unit42_reports(filename)
            )
        """)

        # Create indexes for fast queries
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_reports_filename ON unit42_reports(filename)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_iocs_type ON unit42_iocs(ioc_type)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_iocs_value ON unit42_iocs(ioc_value)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_iocs_report ON unit42_iocs(report_filename)")

        conn.commit()
        conn.close()

        logger.info(f"✅ Unit42 sync database initialized: {self.db_path}")

    def sync(self, force_full: bool = False) -> Dict:
        """
        Sync Unit42 threat reports from GitHub

        First run: Downloads all files (full sync)
        Subsequent runs: Only fetches new/updated files (incremental)

        Args:
            force_full: Force full re-sync (ignore last_sync_time)

        Returns:
            Dict with sync results: total_files, new_files, updated_files, etc.
        """
        logger.info("🔄 Starting Unit42 sync...")
        start_time = datetime.now()

        # Get last sync time
        last_sync_time = None if force_full else self._get_last_sync_time()

        if last_sync_time:
            logger.info(f"📌 Last sync: {last_sync_time}")
            logger.info("⚡ Running incremental sync (only new/updated files)")
        else:
            logger.info("📥 First sync: Downloading all Unit42 threat reports")

        # Fetch file list from GitHub
        try:
            files = self._list_unit42_files()
            logger.info(f"📂 Found {len(files)} files in Unit42 repository")
        except Exception as e:
            logger.error(f"❌ Failed to list Unit42 files: {e}")
            return {"success": False, "error": str(e)}

        # Determine which files to download
        files_to_download = []
        for file_info in files:
            should_download = False

            if not last_sync_time:
                # First sync: Download all files
                should_download = True
            else:
                # Incremental sync: Only download if modified after last_sync_time
                github_modified = file_info.get('last_modified')
                if github_modified and github_modified > last_sync_time:
                    should_download = True

            if should_download:
                files_to_download.append(file_info)

        logger.info(f"📥 Downloading {len(files_to_download)} files...")

        # Download and store files
        new_files = 0
        updated_files = 0

        for file_info in files_to_download:
            try:
                result = self._download_and_store_file(file_info)
                if result == "new":
                    new_files += 1
                elif result == "updated":
                    updated_files += 1
            except Exception as e:
                logger.warning(f"⚠️  Failed to download {file_info['name']}: {e}")
                continue

        # Update sync metadata
        sync_duration = (datetime.now() - start_time).total_seconds()
        self._update_sync_metadata(
            total_files=len(files),
            new_files=new_files,
            updated_files=updated_files,
            duration=sync_duration
        )

        logger.info(f"✅ Sync complete!")
        logger.info(f"   📊 Total files in repo: {len(files)}")
        logger.info(f"   ➕ New files: {new_files}")
        logger.info(f"   🔄 Updated files: {updated_files}")
        logger.info(f"   ⏱️  Duration: {sync_duration:.1f}s")

        return {
            "success": True,
            "total_files": len(files),
            "new_files": new_files,
            "updated_files": updated_files,
            "duration_seconds": sync_duration
        }

    def _list_unit42_files(self) -> List[Dict]:
        """
        List Unit42 threat report files from GitHub

        Only returns files from the last 2 years (not all 4420)
        Tries: API pagination → Web scraping (no rate limit)
        Returns: List of file info dicts
        """
        try:
            logger.info("📡 Fetching Unit42 file list from GitHub (API pagination, last 2 years)...")
            files = self._list_files_github_api_pagination()

            # Filter to last 2 years only
            files = self._filter_by_date(files, years=2)
            logger.info(f"📅 After 2-year filter: {len(files)} files")

            return files

        except Exception as api_error:
            logger.warning(f"⚠️  API pagination failed: {api_error}")
            logger.info("💡 Falling back to web scraping (no rate limit)...")
            try:
                files = self._list_files_from_web_scrape()
                files = self._filter_by_date(files, years=2)
                return files
            except Exception as scrape_error:
                logger.error(f"Web scraping also failed: {scrape_error}")
                raise

    def _parse_api_response(self, contents: List[Dict]) -> List[Dict]:
        """Parse GitHub API response"""
        files = []
        for item in contents:
            if item['type'] == 'file' and item['name'].endswith('.txt'):
                files.append({
                    'name': item['name'],
                    'download_url': item['download_url'],
                    'last_modified': item.get('updated_at', datetime.now().isoformat())
                })
        files = sorted(files, key=lambda x: x['name'], reverse=True)
        logger.info(f"✅ Found {len(files)} threat reports via API")
        return files

    def _list_files_from_web_scrape(self) -> List[Dict]:
        """
        Fetch file list by scraping GitHub repo page (no rate limit)

        GitHub doesn't rate-limit web scraping, only API calls.
        Finds all threat report files (.txt) across the repository.
        """
        try:
            import re

            repo_url = "https://github.com/PaloAltoNetworks/Unit42-timely-threat-intel"
            raw_base = "https://raw.githubusercontent.com/PaloAltoNetworks/Unit42-timely-threat-intel/main"

            logger.info(f"Fetching repo listing: {repo_url}...")
            response = requests.get(repo_url, timeout=15)
            response.raise_for_status()

            html = response.text

            # Pattern to match ALL file links, including subdirectories
            # Matches: href="/PaloAltoNetworks/Unit42-timely-threat-intel/blob/main/FILENAME.txt"
            # Also matches nested: href=".../blob/main/subdir/FILENAME.txt"
            pattern = r'href="[^"]*blob/main/([^"]+\.txt)"'
            matches = re.findall(pattern, html)

            if not matches:
                logger.warning("⚠️  No .txt files found in scrape")
                raise Exception("No files found in web scrape")

            # Deduplicate
            files = []
            seen = set()
            for filename in matches:
                if filename not in seen:
                    seen.add(filename)
                    files.append({
                        'name': filename,
                        'download_url': f"{raw_base}/{filename}",
                        'last_modified': datetime.now().isoformat()
                    })

            files = sorted(files, key=lambda x: x['name'], reverse=True)
            logger.info(f"✅ Found {len(files)} threat reports via web scraping")

            if len(files) < 50:
                logger.warning(f"⚠️  Only found {len(files)} files (expected more due to pagination limits)")

            return files

        except Exception as e:
            logger.error(f"Web scrape failed: {e}")
            raise

    def _list_files_github_api_pagination(self) -> List[Dict]:
        """
        Use GitHub API with pagination to get ALL 449 files

        Key: GitHub only shows ~99 files on web page
        But API returns paginated results (100 per page)
        So we need to fetch pages 1, 2, 3, 4, 5... until all 449 are fetched

        Rate limit: 60/hour unauthenticated, 5,000/hour with token
        We need only 5 API calls (5 pages × 100 files = 500 > 449)
        """
        try:
            api_base = "https://api.github.com/repos/PaloAltoNetworks/Unit42-timely-threat-intel/contents"
            files = []
            page = 1
            per_page = 100

            headers = {}
            if self.github_token and self.github_token != "ghp_your_token_here":
                headers['Authorization'] = f'token {self.github_token}'
                logger.info("Using GitHub token for higher rate limits (5,000/hour)")
            else:
                logger.info("No token, using basic auth (60/hour - but we only need 5 calls)")

            while page <= 10:  # Max 10 pages (covers 1000 files, we need ~450)
                logger.info(f"   Fetching page {page}... (expecting ~{per_page} files per page)")
                params = {'per_page': per_page, 'page': page}

                try:
                    response = requests.get(api_base, params=params, headers=headers, timeout=15)

                    if response.status_code == 403:
                        logger.error("❌ API rate-limited (403 Forbidden)")
                        logger.error("   To fix: Set GitHub token")
                        logger.error("   export GITHUB_TOKEN=\"your_real_token\"")
                        raise Exception("Rate limited - need token for full sync")

                    response.raise_for_status()
                    items = response.json()

                    if not items:
                        logger.info(f"   No more files (reached end at page {page})")
                        break

                    page_files = 0
                    for item in items:
                        if item['type'] == 'file' and item['name'].endswith('.txt'):
                            files.append({
                                'name': item['name'],
                                'download_url': item['download_url'],
                                'last_modified': item.get('updated_at', datetime.now().isoformat())
                            })
                            page_files += 1

                    logger.info(f"   ✅ Page {page}: Found {page_files} .txt files (total: {len(files)})")

                    if len(items) < per_page:
                        logger.info(f"Last page reached (only {len(items)} items < {per_page})")
                        break

                    page += 1

                except requests.exceptions.HTTPError as e:
                    if "403" in str(e):
                        logger.error(f"Rate limit reached at page {page}")
                        break
                    raise

            logger.info(f"\n✅ Total fetched: {len(files)} threat reports via API pagination")
            files = sorted(files, key=lambda x: x['name'], reverse=True)
            return files

        except Exception as e:
            logger.error(f"API pagination failed: {e}")
            raise

    def _download_and_store_file(self, file_info: Dict) -> str:
        """
        Download file from GitHub and store in database

        Returns: 'new', 'updated', or 'skipped'
        """
        filename = file_info['name']
        download_url = file_info['download_url']
        github_modified = file_info.get('last_modified')

        # Download file
        response = requests.get(download_url, timeout=15)
        response.raise_for_status()
        content = response.text

        # Calculate file hash
        import hashlib
        file_hash = hashlib.sha256(content.encode()).hexdigest()

        # Extract threat name
        threat_name = self._extract_threat_name(filename)

        # Check if file already exists
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute("SELECT file_hash FROM unit42_reports WHERE filename = ?", (filename,))
        existing = cursor.fetchone()

        result = "skipped"

        if existing:
            # File exists, check if updated
            existing_hash = existing[0]
            if existing_hash != file_hash:
                # File was updated
                cursor.execute("""
                    UPDATE unit42_reports
                    SET content = ?, file_hash = ?, github_modified_at = ?, updated_at = ?
                    WHERE filename = ?
                """, (content, file_hash, github_modified, datetime.now().isoformat(), filename))
                result = "updated"
        else:
            # New file
            cursor.execute("""
                INSERT INTO unit42_reports
                (filename, content, threat_name, github_modified_at, downloaded_at, created_at, updated_at, file_hash)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (filename, content, threat_name, github_modified, datetime.now().isoformat(),
                  datetime.now().isoformat(), datetime.now().isoformat(), file_hash))
            result = "new"

        conn.commit()
        conn.close()

        logger.debug(f"   {filename}: {result}")
        return result

    def _get_last_sync_time(self) -> Optional[str]:
        """Get last sync timestamp"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute("SELECT last_sync_time FROM sync_metadata ORDER BY id DESC LIMIT 1")
            result = cursor.fetchone()
            conn.close()
            return result[0] if result else None
        except:
            return None

    def _update_sync_metadata(self, total_files: int, new_files: int, updated_files: int, duration: float):
        """Update sync metadata"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute("""
            INSERT INTO sync_metadata
            (last_sync_time, last_sync_status, total_files, new_files, updated_files, sync_duration_seconds)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (datetime.now().isoformat(), 'success', total_files, new_files, updated_files, duration))

        conn.commit()
        conn.close()

    def _filter_by_date(self, files: List[Dict], years: int = 2) -> List[Dict]:
        """
        Filter files to keep only those from last N years

        Unit42 filenames start with date: 2024-10-30-IOCs-for-...
        This keeps only recent files (default 2 years)

        Args:
            files: List of file dicts
            years: Number of years to keep (default 2)

        Returns:
            Filtered list of files
        """
        from datetime import datetime, timedelta
        import re

        cutoff_date = datetime.now() - timedelta(days=years * 365)
        logger.info(f"📅 Filtering files from before {cutoff_date.strftime('%Y-%m-%d')}")

        filtered = []
        for file_info in files:
            filename = file_info.get('name', '')

            # Extract date from filename (format: YYYY-MM-DD-IOCs-for-...)
            match = re.match(r'(\d{4})-(\d{2})-(\d{2})', filename)
            if not match:
                # Can't parse date, keep it (might be important)
                filtered.append(file_info)
                continue

            try:
                year = int(match.group(1))
                month = int(match.group(2))
                day = int(match.group(3))
                file_date = datetime(year, month, day)

                if file_date >= cutoff_date:
                    filtered.append(file_info)
                else:
                    logger.debug(f"Skipping old file: {filename} ({file_date.strftime('%Y-%m-%d')})")

            except ValueError:
                # Invalid date, keep it
                filtered.append(file_info)

        logger.info(f"✅ Kept {len(filtered)} files from last {years} years")
        return filtered

    def _extract_threat_name(self, filename: str) -> Optional[str]:
        """Extract threat name from filename"""
        import re
        match = re.search(r'IOCs-for-([A-Za-z0-9\-]+)', filename)
        if match:
            threat_name = match.group(1).replace('-', ' ').title()
            return threat_name
        return None

    def get_all_reports(self) -> List[Dict]:
        """Get all stored threat reports"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute("""
            SELECT filename, threat_name, downloaded_at, updated_at
            FROM unit42_reports
            ORDER BY updated_at DESC
        """)

        reports = []
        for row in cursor.fetchall():
            reports.append({
                'filename': row[0],
                'threat_name': row[1],
                'downloaded_at': row[2],
                'updated_at': row[3]
            })

        conn.close()
        return reports

    def get_sync_history(self, limit: int = 10) -> List[Dict]:
        """Get sync history"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute("""
            SELECT last_sync_time, total_files, new_files, updated_files, sync_duration_seconds
            FROM sync_metadata
            ORDER BY id DESC
            LIMIT ?
        """, (limit,))

        history = []
        for row in cursor.fetchall():
            history.append({
                'sync_time': row[0],
                'total_files': row[1],
                'new_files': row[2],
                'updated_files': row[3],
                'duration_seconds': row[4]
            })

        conn.close()
        return history


if __name__ == '__main__':
    # Example usage
    sync_manager = Unit42SyncManager()
    result = sync_manager.sync()

    print("\n📊 Stored reports:")
    for report in sync_manager.get_all_reports()[:5]:
        print(f"  - {report['filename']}: {report['threat_name']}")

    print("\n📈 Sync history:")
    for sync in sync_manager.get_sync_history(3):
        print(f"  - {sync['sync_time']}: {sync['new_files']} new, {sync['updated_files']} updated")
