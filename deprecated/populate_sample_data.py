"""
Populate Unit42 database with sample IOC data for dashboard testing

This creates mock threat reports with IOCs so we can test the dashboard
without waiting for the full GitHub sync to complete.
"""

import sqlite3
from datetime import datetime, timedelta
import random

# Sample threat data
SAMPLE_THREATS = [
    {
        'filename': '2026-10-30-IOCs-for-Emotet-activity.txt',
        'threat_name': 'Emotet Activity',
        'content': '''
        EMOTET THREAT REPORT

        IOCs associated with recent Emotet activity:

        C2 Domains:
        emotet-c2-1.com
        emotet-c2-2.com
        emotet-cc.ru

        C2 IP Addresses:
        192.168.1.100
        10.0.0.50
        172.16.0.1

        File Hashes:
        a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4
        e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2

        Download URLs:
        http://emotet-malware.com/download
        https://malware-host.ru/payload

        REFERENCES:
        https://www.crowdstrike.com/blog/emotet-analysis
        https://www.microsoft.com/security/blog/emotet
        '''
    },
    {
        'filename': '2026-10-28-IOCs-for-Cobalt-Strike-activity.txt',
        'threat_name': 'Cobalt Strike Activity',
        'content': '''
        COBALT STRIKE THREAT REPORT

        IOCs from Cobalt Strike beacon activity:

        C2 Domains:
        cobalt-c2.com
        strike-beacon.net

        C2 IP Addresses:
        203.0.113.1
        198.51.100.5

        File Hashes:
        b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5
        f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3

        Suspicious URLs:
        http://cobalt-c2.com/admin/upload
        https://strike-beacon.net/shell?cmd=whoami
        '''
    },
    {
        'filename': '2026-10-25-IOCs-for-Ransomware-campaign.txt',
        'threat_name': 'Ransomware Campaign',
        'content': '''
        RANSOMWARE THREAT REPORT

        IOCs for active ransomware campaign:

        C2 Domains:
        ransomware-gate.onion
        ransom-payment.ru

        C2 IP Addresses:
        45.142.120.1
        185.220.101.5

        File Hashes:
        c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6
        d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1

        Payload URLs:
        http://ransom-payment.ru/pay
        https://ransomware-gate.onion/negotiate
        '''
    },
    {
        'filename': '2026-10-22-IOCs-for-APT28-activity.txt',
        'threat_name': 'APT28 Activity',
        'content': '''
        APT28 THREAT REPORT

        IOCs associated with APT28:

        C2 Domains:
        apt28-c2.ru
        fancy-bear.ru

        C2 IP Addresses:
        212.129.32.1
        91.199.119.5

        File Hashes:
        e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2
        f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3

        Infrastructure URLs:
        http://apt28-c2.ru/admin
        https://fancy-bear.ru/implant
        '''
    },
    {
        'filename': '2026-10-20-IOCs-for-Lazarus-group.txt',
        'threat_name': 'Lazarus Group',
        'content': '''
        LAZARUS GROUP THREAT REPORT

        IOCs from Lazarus operations:

        C2 Domains:
        lazarus-ops.cn
        nk-malware.ru

        C2 IP Addresses:
        202.131.246.1
        119.235.237.5

        File Hashes:
        a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4
        b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5

        Attack Infrastructure:
        http://lazarus-ops.cn/payload
        https://nk-malware.ru/backdoor
        '''
    }
]

def populate_sample_data(db_path='/tmp/unit42_sync.db'):
    """Insert sample threat data into database"""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    now = datetime.now().isoformat()

    for threat in SAMPLE_THREATS:
        filename = threat['filename']
        threat_name = threat['threat_name']
        content = threat['content']

        # Calculate SHA256 hash of content
        import hashlib
        file_hash = hashlib.sha256(content.encode()).hexdigest()

        try:
            cursor.execute("""
                INSERT INTO unit42_reports
                (filename, content, threat_name, github_modified_at, downloaded_at, created_at, updated_at, file_hash)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (filename, content, threat_name, now, now, now, now, file_hash))
            print(f"✅ Inserted: {filename}")
        except sqlite3.IntegrityError:
            print(f"⚠️  Already exists: {filename}")

    conn.commit()

    # Verify
    cursor.execute("SELECT COUNT(*) FROM unit42_reports")
    count = cursor.fetchone()[0]
    print(f"\n📊 Total reports in database: {count}")

    conn.close()
    print("\n✅ Sample data loaded successfully!")
    print("   Now you can test the dashboard with real IOCs")

if __name__ == '__main__':
    populate_sample_data()
