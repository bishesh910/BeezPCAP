import os
import json
import requests
from dotenv import load_dotenv
from time import sleep

load_dotenv()

VT_API_KEY = os.getenv("VT_API_KEY")
ABUSE_API_KEY = os.getenv("ABUSE_API_KEY")

CACHE_FILE = "ioc_cache.json"

def load_iocs():
    with open(CACHE_FILE, "r") as f:
        return json.load(f)

def vt_check_ip(ip):
    try:
        r = requests.get(
            f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
            headers={"x-apikey": VT_API_KEY}
        )
        if r.ok:
            data = r.json()["data"]["attributes"]
            malicious = data.get("last_analysis_stats", {}).get("malicious", 0)
            return malicious
        else:
            return f"VT Error {r.status_code}"
    except Exception as e:
        return f"VT Exception: {e}"

def abuseipdb_check(ip):
    try:
        headers = {
            "Key": ABUSE_API_KEY,
            "Accept": "application/json"
        }
        url = f"https://api.abuseipdb.com/api/v2/check"
        params = {
            "ipAddress": ip,
            "maxAgeInDays": 90
        }
        r = requests.get(url, headers=headers, params=params)
        if r.ok:
            data = r.json()["data"]
            return data.get("abuseConfidenceScore", 0)
        else:
            print(f"[!] AbuseIPDB error {r.status_code}: {r.text}")
            return f"AbuseIPDB Error {r.status_code}"
    except Exception as e:
        return f"AbuseIPDB Exception: {e}"



def main():
    iocs = load_iocs()
    ips = iocs.get("ips", {})

    for ip in ips:
        print(f"\n🔍 Checking IP: {ip}")
        vt_score = vt_check_ip(ip)
        abuse_score = abuseipdb_check(ip)
        print(f"   🔸 VirusTotal Malicious: {vt_score}")
        print(f"   🔸 AbuseIPDB Score: {abuse_score}")
        sleep(15)  # Respect VT free-tier rate limits

if __name__ == "__main__":
    main()
