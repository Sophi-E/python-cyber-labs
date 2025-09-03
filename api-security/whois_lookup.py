import argparse
import requests
import os
from dotenv import load_dotenv

load_dotenv()

API_KEY = os.getenv("IPINFO_API_KEY")
BASE_URL = "https://ipinfo.io/"


def whois_lookup(ip: str):
    headers = {"Authorization": f"Bearer {API_KEY}"}
    url = BASE_URL + ip + "/json"
    response = requests.get(url, headers=headers)  

    if response.status_code == 200: 
        return response.json()
    else:
        return {"error": response.status_code, "message": response.text}

def print_summary(data):
    if "error" in data:
        print(f"[!] Error: {data['message']}")
        return
    
    print("\n🔍 WHOIS Lookup Result:\n")
    for key, value in data.items():
        print(f"{key.capitalize()}: {value}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Perform WHOIS lookup for an IP")
    parser.add_argument("--ip", required=True, help="IP address to query")
    args = parser.parse_args()

    result = whois_lookup(args.ip)
    print_summary(result)
