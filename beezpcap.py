import os
import sys
import subprocess
from datetime import datetime
from rich.console import Console
from reporter import generate_html_report
from enricher import enrich_all
from dotenv import load_dotenv
load_dotenv()
import ipaddress

from parsers import (
    parse_suricata_alerts,
    parse_suricata_http_tls,
    parse_zeek_dns,
    parse_zeek_conn,
    parse_zeek_http,
    parse_zeek_dhcp,
    parse_zeek_files,
    parse_zeek_ssl,
    parse_zeek_notice,
    parse_zeek_weird,
    parse_zeek_kerberos,
    parse_zeek_smb,
    parse_zeek_rdp
)

console = Console()
REPORTS_DIR = "reports"

def generate_ai_summary(alerts, files, enriched):
    import os
    import subprocess

    prompt = "You are a SOC analyst. Summarize the following findings from Suricata and Zeek network analysis tools:\n\n"

    if alerts:
        prompt += "Suricata Alerts:\n" + "\n".join(
            f"{a['timestamp']} | {a['src_ip']} → {a['dest_ip']} | {a['signature']}" for a in alerts[:8]
        ) + "\n\n"
    else:
        prompt += "Suricata Alerts:\nNo alerts found.\n\n"

    if enriched:
        prompt += "Enriched IOCs (IP reputation results from VirusTotal and AbuseIPDB):\n"
        for e in enriched:
            if e.get("malicious") or (e.get("abuse_score") and e["abuse_score"] >= 25):
                prompt += (
                    f"{e['ip']} - VirusTotal Malicious: {e.get('malicious', 'N/A')} | "
                    f"AbuseIPDB Score: {e.get('abuse_score', 'N/A')} | "
                    f"ISP: {e.get('isp', 'Unknown')} | "
                    f"Usage: {e.get('usage', 'Unknown')} | "
                    f"Country: {e.get('country', 'Unknown')}\n"
                )
        prompt += "\n"
    else:
        prompt += "Enriched IOCs:\nNo public indicators flagged.\n\n"

    filtered_files = [f for f in files if f["file_type"] in ['exe', 'ps1', 'dll']]
    if filtered_files:
        prompt += "Suspicious Files:\n" + "\n".join(
            f"{f['filename']} ({f['file_type']})" for f in filtered_files
        )
    else:
        prompt += "Suspicious Files:\nNone detected.\n"

    # Write prompt to file
    with open("summary_prompt.txt", "w") as f:
        f.write(prompt)

    print("[🧠] Prompt written to summary_prompt.txt")
    print("[🧠] Running AI summary using Ollama...\n")

    try:
        process = subprocess.Popen(
            ["ollama", "run", "mistral"],
            stdin=open("summary_prompt.txt", "r"),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1
        )

        summary_lines = []
        for line in process.stdout:
            print("   📝", line.strip())
            summary_lines.append(line.strip())

        process.wait(timeout=180)

        if process.returncode != 0:
            err = process.stderr.read()
            print(f"[!] Ollama error:\n{err.strip()}")
            return "Ollama failed with error."

        summary = "\n".join(summary_lines).strip()
        return summary if summary else "No summary was generated."

    except subprocess.TimeoutExpired:
        print("[!] Ollama run timed out.")
        return "Ollama summary timed out."
    except Exception as e:
        print(f"[!] Exception while running Ollama: {e}")
        return "Ollama summary failed due to unexpected error."



def run_beezpcap(pcap_file):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    pcap_name = os.path.splitext(os.path.basename(pcap_file))[0]
    output_path = os.path.join("output", f"{pcap_name}_{timestamp}")
    report_ext = ".pdf" if os.getenv("REPORT_FORMAT", "").lower() == "pdf" else ".html"
    report_name = f"report_{pcap_name}_{timestamp}{report_ext}"

    os.makedirs(output_path, exist_ok=True)
    os.makedirs(REPORTS_DIR, exist_ok=True)

    console.rule("[bold yellow]🐝 BeezPCAP – Packet Capture Analysis Starting")
    console.print(f"[blue]Loaded PCAP:[/blue] {pcap_file}")
    console.print(f"[green]Timestamp:[/green] {timestamp}")
    console.print(f"[green]Output Directory:[/green] {output_path}")
    console.print(f"[green]Report Will Be:[/green] {REPORTS_DIR}/{report_name}")
    console.print("[yellow]Starting analysis...[/yellow]")

    console.print("[cyan]Running Zeek...[/cyan]")
    subprocess.run([
        "docker", "run", "--rm",
        "-v", f"{os.getcwd()}:/pcap",
        "-w", f"/pcap/{output_path}",
        "blacktop/zeek",
        "-r", f"/pcap/{pcap_file}"
    ], stdout=sys.stdout, stderr=sys.stderr)

    console.print("[cyan]Running Suricata...[/cyan]")
    subprocess.run([
        "docker", "run", "--rm",
        "-v", f"{os.getcwd()}:/pcap",
        "-w", f"/pcap/{output_path}",
        "jasonish/suricata",
        "-r", f"/pcap/{pcap_file}",
        "-l", f"/pcap/{output_path}"
    ], stdout=sys.stdout, stderr=sys.stderr)

    # Parse logs
    eve = os.path.join(output_path, "eve.json")
    alerts, _ = parse_suricata_alerts(eve)
    suri_http, suri_tls = parse_suricata_http_tls(eve)
    domains = parse_zeek_dns(os.path.join(output_path, "dns.log"))
    http_reqs = parse_zeek_http(os.path.join(output_path, "http.log"))
    dhcp_hosts = parse_zeek_dhcp(os.path.join(output_path, "dhcp.log"))
    files = parse_zeek_files(os.path.join(output_path, "files.log"))
    ssl = parse_zeek_ssl(os.path.join(output_path, "ssl.log"))
    notices = parse_zeek_notice(os.path.join(output_path, "notice.log"))
    weirds = parse_zeek_weird(os.path.join(output_path, "weird.log"))
    kerberos = parse_zeek_kerberos(os.path.join(output_path, "kerberos.log"))
    smb = parse_zeek_smb(os.path.join(output_path, "smb.log"))
    rdp = parse_zeek_rdp(os.path.join(output_path, "rdp.log"))

    console.rule("[bold green]🧪 Analysis Summary")

    # Show alerts in CLI
    if alerts:
        console.print("\n[bold red]🚨 Suricata Alerts:")
        for a in alerts:
            console.print(f"🔔 {a['timestamp']} | {a['src_ip']} → {a['dest_ip']} | {a['proto']} | {a['signature']}")




    def is_public_ip(val):
        try:
            ip = ipaddress.ip_address(val)
            return not (ip.is_private or ip.is_loopback or ip.is_multicast or ip.is_reserved or ip.is_link_local)
        except:
            return False

    all_ips = set()
    for a in alerts:
        all_ips.update(i for i in [a.get("src_ip"), a.get("dest_ip")] if is_public_ip(i))
    for s in ssl:
        all_ips.update(i for i in [s.get("ip")] if is_public_ip(i))
    for h in dhcp_hosts:
        all_ips.update(i for i in [h.get("assigned_ip")] if is_public_ip(i))
    for n in notices:
        all_ips.update(i for i in [n.get("src_ip"), n.get("dest_ip")] if is_public_ip(i))
    for w in weirds:
        all_ips.update(i for i in [w.get("id_orig_h"), w.get("id_resp_h")] if is_public_ip(i))
    for k in kerberos:
        all_ips.update(i for i in [k.get("client")] if is_public_ip(i))
    for s in smb:
        all_ips.update(i for i in [s.get("id_orig_h"), s.get("id_resp_h")] if is_public_ip(i))
    for r in rdp:
        all_ips.update(i for i in [r.get("src_ip"), r.get("dest_ip")] if is_public_ip(i))
    all_ips = list(all_ips)


    hashes = [f["sha1"] for f in files if f["sha1"] and f["sha1"] != "F" and len(f["sha1"]) >= 32]
    console.print(f"[bold cyan]IPs to enrich:[/bold cyan] {all_ips}")
    console.print(f"[bold cyan]Hashes to enrich:[/bold cyan] {hashes}")
    console.print(f"[cyan]Enriching {len(all_ips)} IPs and {len(hashes)} file hashes...[/cyan]")
    enriched_ips, enriched_hashes = enrich_all(all_ips, hashes)

    USE_AI_SUMMARY = os.getenv("AIMODULE", "").upper() != "DISABLE"


    # summary = generate_ai_summary(alerts, files, enriched_ips)
    summary = generate_ai_summary(alerts, files, enriched_ips) if USE_AI_SUMMARY else "AI summary generation is disabled."

    # Final HTML output
    generate_html_report({
        "alerts": alerts,
        "dns": domains,
        "http_zeek": http_reqs,
        "http_suri": suri_http,
        "dhcp": dhcp_hosts,
        "files": files,
        "ssl_zeek": ssl,
        "ssl_suri": suri_tls,
        "notices": notices,
        "weird": weirds,
        "kerberos": kerberos,
        "smb": smb,
        "rdp": rdp,
        "enriched": enriched_ips,
        "hashes": enriched_hashes,
        "summary": summary
    }, pcap_name, timestamp, os.path.join(REPORTS_DIR, report_name))


if __name__ == "__main__":
    if len(sys.argv) != 2:
        console.print("[red]Usage:[/red] python beezpcap.py <file.pcap>")
        sys.exit(1)
    run_beezpcap(sys.argv[1])
