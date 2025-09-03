import requests
import argparse
import os
from dotenv import load_dotenv

load_dotenv()

API_KEY = os.getenv("VT_API_KEY") 
BASE_URL = "https://www.virustotal.com/api/v3/files/"

def vt_lookup(file_hash):
    headers = {"x-apikey": API_KEY}
    url = BASE_URL + file_hash
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        return response.json()
    else:
        return {"error": response.status_code, "message": response.text}

def print_summary(data, file_hash):
    if "error" in data:
        print(f"[!] Error: {data['message']}")
        return

    attributes = data.get("data", {}).get("attributes", {})
    stats = attributes.get("last_analysis_stats", {})

    print(f"\n🔍 VirusTotal Report for hash: {file_hash}\n")
    print(f"✅ Harmless:   {stats.get('harmless', 0)}")
    print(f"⚠️ Suspicious: {stats.get('suspicious', 0)}")
    print(f"❌ Malicious:  {stats.get('malicious', 0)}")
    print(f"❓ Undetected: {stats.get('undetected', 0)}")

    if stats.get("malicious", 0) > 0:
        print("\n⚠️ This file is flagged as MALICIOUS!")
    elif stats.get("suspicious", 0) > 0:
        print("\n⚠️ This file is flagged as SUSPICIOUS!")
    else:
        print("\n✅ No malicious activity detected.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="VirusTotal hash lookup")
    parser.add_argument("--hash", required=True, help="File hash to check on VirusTotal")
    args = parser.parse_args()

    result = vt_lookup(args.hash)
    print_summary(result, args.hash)