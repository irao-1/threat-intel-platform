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
