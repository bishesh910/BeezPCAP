import os
from jinja2 import Environment, FileSystemLoader

def generate_html_report(data, pcap_name, timestamp, output_file):
    env = Environment(loader=FileSystemLoader('templates'))
    template = env.get_template('report_template.html')

    def fmt_alert(a):
        return f"🔔 <strong>{a['timestamp']}</strong> | {a['src_ip']} → {a['dest_ip']} | <em>{a['proto']}</em> | {a['signature']}"

    def fmt_http(h):
        return f"🌐 {h.get('host', '')}{h.get('uri', h.get('url', ''))} | UA: <code>{h.get('user_agent', '')}</code>"

    def fmt_dns(d):
        return f"🔎 <code>{d}</code>"

    def fmt_file(f):
        return f"📁 <code>{f['filename']}</code> | Type: {f['file_type']} | SHA1: <code>{f['sha1']}</code>"

    def fmt_ssl(s):
        return f"🔑 SNI: <code>{s.get('sni')}</code> | Subject: <code>{s.get('cert_subject', s.get('subject', ''))}</code>"

    def fmt_notice(n):
        return f"⚠️  <strong>{n['note']}</strong> | {n['msg']} | {n['src_ip']} → {n['dest_ip']}"

    def fmt_weird(w):
        return f"❓ <strong>{w['name']}</strong> | {w['id_orig_h']} → {w['id_resp_h']}"

    def fmt_kerberos(k):
        return f"🎫 <code>{k['client']}</code> → <code>{k['service']}@{k['realm']}</code> | Success: {k['success']}"

    def fmt_smb(s):
        return f"📂 User: <code>{s['user']}</code> | Path: {s['path']} | {s['id_orig_h']} → {s['id_resp_h']}"

    def fmt_rdp(r):
        return f"🖥️ <code>{r['src_ip']}</code> → <code>{r['dest_ip']}</code> | Result: {r['result']}"

    def fmt_enriched(e):
        tags = []

        vt_malicious = e.get("malicious", False)
        abuse_score = e.get("abuse_score", 0)

        if vt_malicious:
            tags.append('<span style="color: red; font-weight: bold;">VT: Malicious</span>')
        else:
            tags.append('<span style="color: green;">VT: Clean</span>')

        if abuse_score >= 80:
            tags.append(f'<span style="color: red; font-weight: bold;">AbuseIPDB Score: {abuse_score}</span>')
        elif abuse_score >= 25:
            tags.append(f'<span style="color: orange;">AbuseIPDB Score: {abuse_score}</span>')
        elif abuse_score:
            tags.append(f'<span style="color: green;">AbuseIPDB Score: {abuse_score}</span>')

        if e.get("isp"):
            tags.append(f"ISP: {e['isp']}")
        if e.get("country"):
            tags.append(f"Country: {e['country']}")
        if e.get("usage"):
            tags.append(f"Usage: {e['usage']}")

        return f"🧠 <code>{e['ip']}</code> | " + " | ".join(tags)

    enriched_iocs = sorted(
        [fmt_enriched(i) for i in data["enriched"]],
        key=lambda x: ("VT: Malicious" not in x and "AbuseIPDB Score" not in x, x)
    )

    sections = [
        {"title": "🚨 Suricata Alerts", "entries": [fmt_alert(a) for a in data["alerts"]], "css": "alert"},
        {"title": "🌐 DNS Queries", "entries": [fmt_dns(d) for d in data["dns"]], "css": "dns"},
        {"title": "📡 Zeek HTTP Requests", "entries": [fmt_http(h) for h in data["http_zeek"]], "css": "http"},
        {"title": "🌐 Suricata HTTP Requests", "entries": [fmt_http(h) for h in data["http_suri"]], "css": "http"},
        {"title": "💻 DHCP Hostnames", "entries": [f"🖥️ {h['hostname']} | {h['mac']} → {h['assigned_ip']}" for h in data["dhcp"]], "css": "dns"},
        {"title": "📦 Transferred Files", "entries": [fmt_file(f) for f in data["files"]], "css": "file"},
        {"title": "🔐 SSL/TLS Sessions (Zeek)", "entries": [fmt_ssl(s) for s in data["ssl_zeek"]], "css": "ssl"},
        {"title": "🔐 TLS Sessions (Suricata)", "entries": [fmt_ssl(s) for s in data["ssl_suri"]], "css": "ssl"},
        {"title": "📢 Zeek Notices", "entries": [fmt_notice(n) for n in data["notices"]], "css": "alert"},
        {"title": "🌀 Zeek Weird Events", "entries": [fmt_weird(w) for w in data["weird"]], "css": "weird"},
        {"title": "👤 Kerberos Auth Logs", "entries": [fmt_kerberos(k) for k in data["kerberos"]], "css": "http"},
        {"title": "📂 SMB Access Logs", "entries": [fmt_smb(s) for s in data["smb"]], "css": "file"},
        {"title": "🖥️ RDP Sessions", "entries": [fmt_rdp(r) for r in data["rdp"]], "css": "dns"},
    ]

    html = template.render(
        pcap_name=pcap_name,
        timestamp=timestamp,
        summary=data.get("summary", "No AI summary was generated."),
        enriched_iocs=enriched_iocs,
        sections=sections
    )

    with open(output_file, 'w') as f:
        f.write(html)

