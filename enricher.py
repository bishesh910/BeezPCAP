import os
import json
import requests
from time import sleep
from dotenv import load_dotenv

load_dotenv()

CACHE_FILE = "ioc_cache.json"
VT_API_KEY = os.getenv("VT_API_KEY")
ABUSE_API_KEY = os.getenv("ABUSE_API_KEY")

def load_cache():
    if os.path.exists(CACHE_FILE):
        with open(CACHE_FILE, "r") as f:
            return json.load(f)
    return {"ips": {}, "hashes": {}}

def save_cache(cache):
    with open(CACHE_FILE, "w") as f:
        json.dump(cache, f, indent=2)

def enrich_ip(ip, cache):
    if ip in cache["ips"] and cache["ips"][ip]:
        print(f"[cache] IP {ip} already enriched.")
        return cache["ips"][ip]

    print(f"[>] Enriching IP: {ip}")
    info = {}

    # VirusTotal enrichment
    if VT_API_KEY:
        try:
            r = requests.get(
                f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
                headers={"x-apikey": VT_API_KEY}
            )
            if r.ok:
                data = r.json()["data"]["attributes"]
                stats = data.get("last_analysis_stats", {})
                info["malicious"] = stats.get("malicious", 0) > 0
                info["vt_positives"] = stats.get("malicious", 0)
                info["vt_total"] = sum(stats.values())
            else:
                print(f"  [!] VT Error {r.status_code}: {r.text}")
        except Exception as e:
            print(f"  [!] VT Exception: {e}")

    # AbuseIPDB enrichment
    if ABUSE_API_KEY:
        try:
            r = requests.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers={"Key": ABUSE_API_KEY, "Accept": "application/json"},
                params={"ipAddress": ip, "maxAgeInDays": 90}
            )
            if r.ok:
                data = r.json()["data"]
                info["abuse_score"] = data.get("abuseConfidenceScore", 0)
                info["isp"] = data.get("isp")
                info["country"] = data.get("countryCode")
                info["usage"] = data.get("usageType")
            else:
                print(f"  [!] AbuseIPDB Error {r.status_code}: {r.text}")
        except Exception as e:
            print(f"  [!] AbuseIPDB Exception: {e}")

    cache["ips"][ip] = info
    save_cache(cache)
    sleep(15)  # VT rate limit
    return info

def enrich_hash(sha1, cache):
    if sha1 in cache["hashes"]:
        print(f"[cache] Hash {sha1} already enriched.")
        return cache["hashes"][sha1]

    print(f"[>] Enriching hash: {sha1}")
    info = {}

    if VT_API_KEY:
        try:
            r = requests.get(
                f"https://www.virustotal.com/api/v3/files/{sha1}",
                headers={"x-apikey": VT_API_KEY}
            )
            if r.ok:
                data = r.json()["data"]["attributes"]
                stats = data.get("last_analysis_stats", {})
                info["malicious"] = stats.get("malicious", 0) > 0
                info["positives"] = stats.get("malicious", 0)
                info["total"] = sum(stats.values())
                info["link"] = f"https://www.virustotal.com/gui/file/{sha1}"
                print(f"    Hash {sha1}: {info['positives']} / {info['total']}")
            else:
                print(f"    VT response error: {r.status_code}")
        except Exception as e:
            print(f"[!] VT hash error for {sha1}: {e}")

    cache["hashes"][sha1] = info
    save_cache(cache)
    sleep(15)
    return info

def enrich_all(ips, file_hashes):
    cache = load_cache()
    enriched_ips = []
    enriched_hashes = []

    for ip in ips:
        info = enrich_ip(ip, cache)
        enriched_ips.append({"ip": ip, **info})

    for sha1 in file_hashes:
        info = enrich_hash(sha1, cache)
        enriched_hashes.append({"sha1": sha1, **info})

    return enriched_ips, enriched_hashes
