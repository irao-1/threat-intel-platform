# Threat Intelligence Platform - STIX/TAXII Converter 🚀

**⚠️ DEMO PROJECT - NOT PRODUCTION READY**

### What It Does
Fetches real threat IOCs from **TweetFeed Live**, converts to **STIX 2.1**, saves locally for **TIP/TAXII** integration.

### One-Liner
```bash
python -m examples.stix_taxii_converter
# Fetch 1000+ IOCs → Convert to STIX → Save as JSON → Ready for TIP
```

### Tech Stack
- **Language:** Python 3.9+
- **Format:** STIX 2.1 (JSON)
- **Sync:** Incremental (no duplicates)
- **Storage:** Local JSON file
- **Dependencies:** requests only

---

---

## ⚠️ What This Project IS NOT

❌ NOT a sandbox analyzer (no ANY.RUN, VirusTotal, Cuckoo integration)  
❌ NOT a graph database (no Neo4j)  
❌ NOT a complex dashbaord  
❌ NOT for behavioral analysis or execution chain tracking  
❌ NOT production-ready  

**Why the scope changed:**
- Sandbox integration = complex + requires external APIs + expensive
- Neo4j = infrastructure overhead for demo project
- Better to focus on core: IOC standardization for enterprises

---

## What This Project IS

✅ Simple, focused IOC aggregator  
✅ Converts threat data to STIX 2.1 (industry standard)  
✅ Lightweight local persistence (no database)  
✅ Real data from TweetFeed Live (not samples)  
✅ Incremental sync (prevents duplicates)  
✅ Ready for TIP/TAXII import  

---

## Project Evolution

**Versions Attempted → Archived:**
- ❌ ANY.RUN sandbox (too complex, requires enterprise account)
- ❌ VirusTotal (API limits, expensive)
- ❌ Neo4j threat hunting (infrastructure overhead)
- ❌ Complex dashboard (not needed for TIP)
- ❌ Unit42 GitHub feeds (rate limited, unreliable)

**Current Focus:**
- ✅ Single trusted source (TweetFeed Live)
- ✅ Clean STIX 2.1 conversion
- ✅ Incremental sync (no duplicates)
- ✅ Local persistence (no external DB)
- ✅ Ready for TIP/TAXII import

**Future:** Multi-source aggregation (abuse.ch, URLhaus, OpenPhish)

---

## What This Is

A **STIX/TAXII converter** that:
- Fetches real threat IOCs from **TweetFeed Live** API
- Converts to **STIX 2.1 format** (ready for TIP integration)
- Saves locally as **threat-intel-stix.json**
- **Incremental sync** — only fetches new data, no duplicates
- Ready to import into TAXII servers

**Workflow:**
```
TweetFeed Live API
        ↓
   Fetch IOCs
        ↓
   Convert to STIX 2.1
        ↓
   Save locally (threat-intel-stix.json)
        ↓
   Import to TIP/TAXII
```

---

## Quick Start (2 minutes)

### 1. Install
```bash
pip install requests
```

### 2. Run Converter
```bash
python -m examples.stix_taxii_converter
```

### 3. Fetch & Save
```
Options:
  1. Fetch from TweetFeed & save as STIX
  2. Show STIX bundle statistics
  3. View STIX bundle (console)
  0. Exit

Enter choice: 1
⏳ Fetching from TweetFeed Live...
✅ Fetched 1022 IOCs from TweetFeed
📦 Created new STIX bundle with 1022 IOCs
✅ Saved to: threat-intel-stix.json
```

### 4. Next Time (Incremental Sync)
```
Enter choice: 1
⏳ Fetching from TweetFeed Live...
✅ Fetched 1022 IOCs from TweetFeed
📦 Merged 12 new IOCs (total: 1034)
✅ Saved to: threat-intel-stix.json
```

---

## What You Can Do

✅ **Fetch from TweetFeed Live** — ~1000 real threat IOCs per week  
✅ **Convert to STIX 2.1** — Industry-standard threat intelligence format  
✅ **Save Locally** — No need to fetch every time (threat-intel-stix.json)  
✅ **Incremental Updates** — Only new IOCs, zero duplicates  
✅ **View Statistics** — Breakdown by type, source, confidence  
✅ **Ready for TIP** — Import into Threat Intelligence Platform/TAXII server  
✅ **Extensible Design** — Easy to add more sources (abuse.ch, URLhaus, etc.)  

---

## How It Works

### First Run (Fresh Fetch)
1. **Fetch** → Calls TweetFeed Live API, gets ~1000 IOCs
2. **Convert** → Maps to STIX 2.1 indicator patterns
3. **Save** → Creates `threat-intel-stix.json` locally
4. **Timestamp** → Records sync time in `.sync` file

### Subsequent Runs (Incremental)
1. **Fetch** → Gets fresh IOCs from TweetFeed
2. **Deduplicate** → Compares with existing bundle
3. **Merge** → Only adds new IOCs (no duplicates)
4. **Save** → Updates `threat-intel-stix.json`

### Output - STIX Format
```json
{
  "type": "bundle",
  "id": "bundle--550e8400-e29b-41d4-a716-446655440000",
  "created": "2026-11-03T12:00:00Z",
  "objects": [
    {
      "type": "identity",
      "name": "TweetFeed Live Threat Intelligence"
    },
    {
      "type": "indicator",
      "pattern": "[domain-name:value = 'malware-c2.com']",
      "labels": ["malicious-activity"],
      "name": "C2 Infrastructure - domain",
      "confidence": 80,
      "source": "TweetFeed Live"
    }
  ]
}
```

### No Need to Fetch Again
Once saved, you have:
- ✅ Local copy of threat IOCs
- ✅ Ready to import into TIP/TAXII
- ✅ No API calls on subsequent access
- ✅ Only fetches when you run option 1

---

## Project Structure

```
threat-intel-platform/
│
├── examples/
│   ├── stix_taxii_converter.py     ← Main converter
│   ├── sample_threatfox_data.py    ← Sample IOCs
│   ├── threat_intel_live.py        ← Live API collector
│   └── threat_intel_cli.py         ← CLI interface
│
├── collectors/
│   ├── threatfox_collector.py
│   ├── tweet_parser_collector.py
│   └── base_collector.py
│
├── README.md                        (this file)
└── deprecated/                      (archived code)
```

---

## Data Sources

### Sample Data
- 8 realistic threat IOCs included
- Malware families: Emotet, Cobalt Strike, LockBit, TrickBot, Qbot, Conti, Dridex
- Confidence levels: 87-98%
- Types: domains, IPs, URLs, file hashes

### Live Sources (Optional)
- **TweetFeed Live** — Real-time security researcher tweets
- **ThreatFox (abuse.ch)** — Community threat submissions

---

## STIX/TAXII Overview

### STIX (Structured Threat Information Expression)
- Standard format for threat intelligence
- Version: 2.1
- Used by: MITRE, government agencies, enterprises
- Contains: Indicators, malware, attack patterns, etc.

### TAXII (Trusted Automated Exchange)
- Protocol for sharing STIX data
- Client-server model
- Automated threat intelligence distribution
- Compatible with STIX bundles

---

## Sample STIX Output

```json
{
  "type": "bundle",
  "id": "bundle--550e8400-e29b-41d4-a716-446655440000",
  "objects": [
    {
      "type": "identity",
      "id": "identity--550e8400-e29b-41d4-a716-446655440001",
      "name": "Threat Intelligence Platform",
      "identity_class": "organization"
    },
    {
      "type": "indicator",
      "id": "indicator--550e8400-e29b-41d4-a716-446655440002",
      "pattern": "[domain-name:value = 'malware-c2.com']",
      "labels": ["malicious-activity"],
      "name": "Emotet - domain",
      "confidence": 95,
      "valid_from": "2026-11-03T12:00:00Z"
    }
  ]
}
```

---

## Features

### Conversion
- **Domain** → `[domain-name:value = '...']`
- **IP Address** → `[ipv4-addr:value = '...']`
- **URL** → `[url:value = '...']`
- **Hash** → `[file:hashes.MD5 = '...']`

### Metadata
- Malware family names
- Confidence levels
- Created/modified timestamps
- Source attribution

### Export Formats
- **JSON** — Human-readable STIX bundles
- **Console** — View bundle directly

---

## Limitations (By Design)

This is a **demo** — not production:

❌ Small sample dataset (8 IOCs)  
❌ No real-time API integration  
❌ No TAXII server integration  
❌ No database persistence  
❌ No authentication  

---

## Usage Examples

### Example 1: First Run - Fetch & Save
```bash
python -m examples.stix_taxii_converter

Options:
  1. Fetch from TweetFeed & save as STIX
  2. Show STIX bundle statistics
  3. View STIX bundle (console)

Enter choice: 1
⏳ Fetching from TweetFeed Live...
✅ Fetched 1022 IOCs from TweetFeed
📦 Created new STIX bundle with 1022 IOCs
✅ Saved to: threat-intel-stix.json
```

**Files created:**
- `threat-intel-stix.json` — Ready for TIP import
- `threat-intel-stix.sync` — Timestamp of last fetch

### Example 2: Check Stats (No Fetch)
```bash
python -m examples.stix_taxii_converter

Enter choice: 2
📊 STIX BUNDLE STATISTICS
Total indicators: 1022

By Type:
  domain: 309
  ip: 127
  url: 256
  hash: 330

Last sync: 2026-11-03T12:00:00Z
```

### Example 3: View Bundle
```bash
python -m examples.stix_taxii_converter

Enter choice: 3
# Prints full STIX bundle (JSON) to console
```

### Example 4: Incremental Update
```bash
# Run again later...
python -m examples.stix_taxii_converter

Enter choice: 1
⏳ Fetching from TweetFeed Live...
✅ Fetched 1022 IOCs from TweetFeed
📦 Merged 12 new IOCs (total: 1034)
✅ Saved to: threat-intel-stix.json
```

---

## Requirements

- Python 3.9+
- No external dependencies (JSON is built-in)

---

## AI-Assisted Project

**This project was AI-assisted using Claude AI.**

- Designed to demonstrate threat intelligence standardization
- STIX/TAXII conversion patterns
- Sample data for testing
- Fully documented

Use as reference for:
- STIX 2.1 implementation
- Threat intelligence workflows
- Indicator standardization
- TAXII integration patterns

---

## Next Steps

### To Use Now
```bash
python -m examples.stix_taxii_converter
# Choose option 2 to export STIX JSON
```

### To Extend
1. Add more IOC sources
2. Integrate with TAXII servers
3. Add STIX extension objects
4. Build STIX validation

### For Production
1. Add real API integration (TweetFeed, ThreatFox, VirusTotal)
2. Build TAXII server integration
3. Add database for persistence
4. Implement authentication
5. Add STIX validation

---

## Summary

**What you have:**
- ✅ Fetches from **TweetFeed Live** API (~1000 IOCs/week)
- ✅ Converts to **STIX 2.1** format
- ✅ Saves locally as **threat-intel-stix.json**
- ✅ **Incremental sync** — only new IOCs on updates
- ✅ **No duplicate IOCs** — deduplication built-in
- ✅ **Ready for TIP** — import JSON into your TAXII server
- ✅ **Fast access** — check stats without fetching

**Workflow:**
1. Run: `python -m examples.stix_taxii_converter`
2. Choose: `1` (Fetch & Save)
3. Get: `threat-intel-stix.json` (ready for TIP)
4. Next time: Only fetches new data (incremental)

---

## Future Scope & Roadmap

### Phase 1: Multi-Source Aggregation (Q1 2027)
Expand beyond TweetFeed to include multiple free threat intelligence sources:

```
Current:  TweetFeed Live (~1000 IOCs/week)
+
Phase 1:  + ThreatFox/abuse.ch (500 IOCs/week)
          + URLhaus (2000 URLs/week)
          + OpenPhish (1500 phishing URLs/week)
          
Result:   5000+ IOCs from diverse sources
```

**Implementation:**
- Add `abuse_ch_collector.py` for ThreatFox
- Add `urlhaus_collector.py` for URL threats
- Add `openphish_collector.py` for phishing
- Parallel fetching for all sources
- Advanced deduplication across sources

### Phase 2: Automated Scheduling (Q2 2027)
Eliminate manual fetching with automatic updates:

```
Setup:    cron job or systemd timer
          
Schedule: Daily 9:00 AM
          Weekly 12:00 PM
          Or: Custom intervals
          
Result:   Always up-to-date threat intelligence
```

**Implementation:**
```bash
# Cron job
0 9 * * * /usr/bin/python3 /path/to/stix_taxii_converter.py --auto-fetch

# Or systemd timer
systemctl enable threat-intel-sync.timer
```

### Phase 3: Database Backend (Q3 2027)
Move from JSON file to proper database:

```
Current:  JSON file
          - Good: Simple, self-contained
          - Bad: No queries, no indexes, limited to ~100k IOCs

Phase 3:  SQLite (development)
          - Good: Structured data, queries, indexes
          - Supports: 1-10 million IOCs

Production: PostgreSQL
          - Good: Horizontal scaling, replication
          - Supports: 100M+ IOCs, multi-user
```

**Schema:**
```sql
CREATE TABLE iocs (
  id INTEGER PRIMARY KEY,
  value TEXT UNIQUE,
  type TEXT,           -- domain, ip, url, hash
  category TEXT,       -- C2, malware, phishing
  source TEXT,         -- TweetFeed, ThreatFox, etc.
  confidence INT,
  first_seen TIMESTAMP,
  last_seen TIMESTAMP,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_value ON iocs(value);
CREATE INDEX idx_type ON iocs(type);
CREATE INDEX idx_source ON iocs(source);
```

### Phase 4: TAXII Server Integration (Q4 2027)
Push IOCs to TAXII 2.1 servers for automated sharing:

```
Current:  Save locally (manual import to TIP)

Phase 4:  Auto-push to TAXII
          - STIX Bundles API
          - Collection management
          - Subscription handling
          
Result:   Real-time threat intel sharing with enterprise
```

**Features:**
- Automatic STIX bundle creation
- Push to TAXII collection endpoints
- Handle TAXII authentication
- Track push status/errors
- Support multiple TAXII servers

### Phase 5: Enterprise Features (2028)
Advanced threat intelligence capabilities:

**5A: STIX Enrichment**
- Malware objects
- Attack pattern mappings
- Threat actor attribution
- Campaign relationships
- Kill chain phases

**5B: Threat Hunting**
- Full-text search across IOCs
- Filter by date range, source, confidence
- Group by malware family
- Trend analysis
- Time-series queries

**5C: SIEM Integration**
- Export to Splunk lookups
- Elasticsearch bulk ingestion
- Zeek/Suricata rule generation
- Firewall blocklists (CSV, XML)
- SIEM-specific formats

**5D: Machine Learning** (Optional)
- Anomaly detection for new malware
- Confidence score prediction
- IOC type classification
- Trend forecasting

---

## How to Add New Threat Sources

### Quick Start: Add abuse.ch ThreatFox

**Step 1: Create collector**
```python
# collectors/threatfox_collector.py

class ThreatFoxCollector:
    def __init__(self, api_key=None):
        self.api_key = api_key
        self.base_url = "https://api.abuse.ch/api/v1/"
    
    def fetch_recent(self, days=7):
        """Fetch recent IOCs"""
        response = requests.post(
            f"{self.base_url}threatfox/recent/",
            json={"days": days}
        )
        return self.parse(response.json())
    
    def parse(self, data):
        """Convert to standard format"""
        iocs = []
        for item in data.get('data', []):
            iocs.append({
                'value': item['ioc'],
                'type': self._map_type(item['ioc_type']),
                'category': 'C2 Infrastructure',
                'source': 'ThreatFox/abuse.ch',
                'confidence': item.get('confidence_level', 75)
            })
        return iocs
    
    def _map_type(self, ioc_type):
        type_map = {
            'domain': 'domain',
            'ip:port': 'ip',
            'url': 'url',
            'file_hash': 'hash'
        }
        return type_map.get(ioc_type, 'unknown')
```

**Step 2: Add to converter**
```python
# examples/stix_taxii_converter.py

from collectors.threatfox_collector import ThreatFoxCollector

class STIXConverter:
    def __init__(self):
        self.sources = [
            TweetParserCollector(),      # Existing
            ThreatFoxCollector(),        # New
        ]
    
    def fetch_all_sources(self):
        all_iocs = []
        for source in self.sources:
            try:
                iocs = source.fetch()
                all_iocs.extend(iocs)
                print(f"✅ Fetched from {source.__class__.__name__}")
            except Exception as e:
                print(f"⚠️ Error from {source.__class__.__name__}: {e}")
        return all_iocs
```

**Step 3: Test**
```bash
python -m examples.stix_taxii_converter

# Should now show:
# ✅ Fetched from TweetParserCollector
# ✅ Fetched from ThreatFoxCollector
# 📦 Merged 1534 IOCs from 2 sources
```

### Template for Custom Collector

```python
# collectors/your_source_collector.py

class YourSourceCollector:
    def __init__(self, api_key=None):
        self.api_key = api_key
        self.base_url = "https://api.your-source.com"
    
    def fetch(self, **kwargs):
        """Fetch IOCs from your source"""
        try:
            response = requests.get(
                f"{self.base_url}/iocs",
                headers=self._get_headers(),
                timeout=10
            )
            response.raise_for_status()
            return self.parse(response.json())
        except Exception as e:
            print(f"❌ Error fetching from {self.__class__.__name__}: {e}")
            return []
    
    def parse(self, data):
        """Convert to standard IOC format"""
        iocs = []
        for item in data:
            iocs.append({
                'value': item['indicator'],      # Required
                'type': self._get_type(item),    # domain, ip, url, hash
                'category': item.get('category', 'Unknown'),
                'source': 'YourSource',
                'confidence': item.get('confidence', 75)
            })
        return iocs
    
    def _get_headers(self):
        """API authentication"""
        if self.api_key:
            return {"Authorization": f"Bearer {self.api_key}"}
        return {}
    
    def _get_type(self, item):
        """Map to standard types"""
        ioc_type = item.get('type', '').lower()
        type_map = {
            'domain': 'domain',
            'host': 'domain',
            'ip': 'ip',
            'ipv4': 'ip',
            'url': 'url',
            'link': 'url',
            'hash': 'hash',
            'md5': 'hash',
            'sha256': 'hash'
        }
        return type_map.get(ioc_type, 'unknown')
```

---

## Sources to Add Later

| Source | Type | Free? | IOCs/Week | Status |
|--------|------|-------|-----------|--------|
| TweetFeed Live | ✅ Implemented | Yes | ~1000 | Active |
| ThreatFox (abuse.ch) | 📋 Planned | Yes | ~500 | Phase 1 |
| URLhaus (abuse.ch) | 📋 Planned | Yes | ~2000 | Phase 1 |
| OpenPhish | 📋 Planned | Yes | ~1500 | Phase 1 |
| PhishTank | 📋 Planned | Yes | ~500 | Future |
| Shodan/Censys | ❌ Paid | Partial | ~500 | Future |
| VirusTotal | ❌ Limited | Partial | ~1000 | Future |

---

## Disclaimers

**This is an educational demo** — Use for learning only.

Sample IOCs are **realistic but fabricated** for testing purposes.

For production threat intelligence, use:
- Professional threat feeds
- Verified IOC indicators
- Established threat intelligence platforms
- Proper validation workflows

---

## Questions?

This is a demo for learning STIX/TAXII concepts:
1. Review the code comments
2. Check STIX 2.1 specification
3. Test with sample data first
4. Extend incrementally

---

**Made with Claude AI. Demo only.** 🤖

Start with: `python -m examples.stix_taxii_converter`
