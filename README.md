# Python + Cyber Labs

## 📌 — Python + APIs

### 🔹 Goals 
- Practice API calls for security use cases.  
- Work with VirusTotal and WHOIS data.  

---

### 📝 Script 1: VirusTotal Lookup
**File:** `virustotal_lookup.py`  

- Queries [VirusTotal API](https://developers.virustotal.com/reference) for file hashes.  
- Input: hash value(s).  
- Output: JSON summary (malicious/benign/undetected).  

**Example Run:**  
```bash
python virustotal_lookup.py --hash d41d8cd98f00b204e9800998ecf8427e

{
  "hash": "d41d8cd98f00b204e9800998ecf8427e",
  "detections": 0,
  "status": "benign"
}
```

### 📝 Script 2: Whois Lookup
**File:** `whois_lookup.py`  

- Queries [IPINFO API](https://ipinfo.io/.com/) for ip info.  
- Input: ip(s).  
- Output: JSON summary (ip/country/org).  

**Example Run:**  
```bash
python whois_lookup.py --ip 8.8.8.8


{
  "ip": "8.8.8.8",
  "org": "Google LLC",
  "country": "US"
}
