import json
import os

def parse_suricata_alerts(eve_file):
    alerts = []
    src_ips = set()
    dst_ips = set()

    with open(eve_file, 'r') as f:
        for line in f:
            try:
                event = json.loads(line)
                if event.get("event_type") == "alert":
                    alerts.append({
                        "signature": event["alert"]["signature"],
                        "src_ip": event.get("src_ip"),
                        "dest_ip": event.get("dest_ip"),
                        "proto": event.get("proto"),
                        "timestamp": event.get("timestamp")
                    })
                    src_ips.add(event.get("src_ip"))
                    dst_ips.add(event.get("dest_ip"))
            except json.JSONDecodeError:
                continue

    return alerts, list(src_ips.union(dst_ips))


def parse_zeek_dns(dns_log):
    domains = set()
    try:
        with open(dns_log, 'r') as f:
            for line in f:
                if not line.startswith("#"):
                    parts = line.strip().split('\t')
                    if len(parts) >= 5:
                        domains.add(parts[4])
    except FileNotFoundError:
        pass
    return list(domains)


def parse_zeek_conn(conn_log):
    conns = []
    try:
        with open(conn_log, 'r') as f:
            for line in f:
                if not line.startswith("#"):
                    parts = line.strip().split('\t')
                    if len(parts) >= 9:
                        conns.append({
                            "ts": parts[0],
                            "uid": parts[1],
                            "src_ip": parts[2],
                            "src_port": parts[3],
                            "dest_ip": parts[4],
                            "dest_port": parts[5],
                            "proto": parts[6],
                            "service": parts[7],
                            "duration": parts[8]
                        })
    except FileNotFoundError:
        pass
    return conns


def parse_zeek_http(http_log):
    requests = []
    try:
        with open(http_log, 'r') as f:
            for line in f:
                if not line.startswith("#"):
                    parts = line.strip().split('\t')
                    if len(parts) >= 10:
                        requests.append({
                            "ts": parts[0],
                            "uid": parts[1],
                            "method": parts[5],
                            "host": parts[6],
                            "uri": parts[7],
                            "user_agent": parts[9]
                        })
    except FileNotFoundError:
        pass
    return requests


def parse_zeek_dhcp(dhcp_log):
    hosts = []
    try:
        with open(dhcp_log, 'r') as f:
            for line in f:
                if not line.startswith("#"):
                    parts = line.strip().split('\t')
                    if len(parts) >= 8:
                        hosts.append({
                            "ts": parts[0],
                            "mac": parts[1],
                            "assigned_ip": parts[2],
                            "hostname": parts[3],
                            "client_fqdn": parts[7]
                        })
    except FileNotFoundError:
        pass
    return hosts


def parse_zeek_files(files_log):
    files = []
    try:
        with open(files_log, 'r') as f:
            for line in f:
                if not line.startswith("#"):
                    parts = line.strip().split('\t')
                    if len(parts) >= 13:
                        files.append({
                            "ts": parts[0],
                            "source": parts[2],
                            "dest": parts[3],
                            "filename": parts[8],
                            "file_type": parts[9],
                            "sha1": parts[12]
                        })
    except FileNotFoundError:
        pass
    return files


def parse_zeek_ssl(ssl_log):
    ssl_sessions = []
    try:
        with open(ssl_log, 'r') as f:
            for line in f:
                if not line.startswith("#"):
                    parts = line.strip().split('\t')
                    if len(parts) >= 10:
                        ssl_sessions.append({
                            "ts": parts[0],
                            "uid": parts[1],
                            "ip": parts[2],
                            "sni": parts[8],
                            "cert_subject": parts[9]
                        })
    except FileNotFoundError:
        pass
    return ssl_sessions


def parse_zeek_notice(notice_log):
    notices = []
    try:
        with open(notice_log, 'r') as f:
            for line in f:
                if not line.startswith("#"):
                    parts = line.strip().split('\t')
                    if len(parts) >= 8:
                        notices.append({
                            "ts": parts[0],
                            "note": parts[2],
                            "msg": parts[4],
                            "src_ip": parts[5],
                            "dest_ip": parts[6]
                        })
    except FileNotFoundError:
        pass
    return notices


def parse_zeek_weird(weird_log):
    weirds = []
    try:
        with open(weird_log, 'r') as f:
            for line in f:
                if not line.startswith("#"):
                    parts = line.strip().split('\t')
                    if len(parts) >= 5:
                        weirds.append({
                            "ts": parts[0],
                            "uid": parts[1],
                            "id_orig_h": parts[2],
                            "id_resp_h": parts[3],
                            "name": parts[4]
                        })
    except FileNotFoundError:
        pass
    return weirds

def parse_suricata_http_tls(eve_file):
    http_entries = []
    tls_entries = []

    try:
        with open(eve_file, 'r') as f:
            for line in f:
                try:
                    event = json.loads(line)
                    if event.get("event_type") == "http":
                        http_entries.append({
                            "ts": event.get("timestamp"),
                            "src_ip": event.get("src_ip"),
                            "dest_ip": event.get("dest_ip"),
                            "host": event.get("http", {}).get("hostname"),
                            "url": event.get("http", {}).get("url"),
                            "user_agent": event.get("http", {}).get("http_user_agent")
                        })
                    elif event.get("event_type") == "tls":
                        tls_entries.append({
                            "ts": event.get("timestamp"),
                            "src_ip": event.get("src_ip"),
                            "dest_ip": event.get("dest_ip"),
                            "sni": event.get("tls", {}).get("sni"),
                            "subject": event.get("tls", {}).get("subject")
                        })
                except json.JSONDecodeError:
                    continue
    except FileNotFoundError:
        pass

    return http_entries, tls_entries


def parse_zeek_kerberos(kerberos_log):
    entries = []
    try:
        with open(kerberos_log, 'r') as f:
            for line in f:
                if not line.startswith("#"):
                    parts = line.strip().split('\t')
                    if len(parts) >= 8:
                        entries.append({
                            "ts": parts[0],
                            "uid": parts[1],
                            "client": parts[2],
                            "service": parts[4],
                            "realm": parts[5],
                            "success": parts[6],
                            "msg": parts[7]
                        })
    except FileNotFoundError:
        pass
    return entries


def parse_zeek_smb(smb_log):
    entries = []
    try:
        with open(smb_log, 'r') as f:
            for line in f:
                if not line.startswith("#"):
                    parts = line.strip().split('\t')
                    if len(parts) >= 8:
                        entries.append({
                            "ts": parts[0],
                            "uid": parts[1],
                            "id_orig_h": parts[2],
                            "id_resp_h": parts[3],
                            "user": parts[5],
                            "path": parts[6]
                        })
    except FileNotFoundError:
        pass
    return entries


def parse_zeek_rdp(rdp_log):
    entries = []
    try:
        with open(rdp_log, 'r') as f:
            for line in f:
                if not line.startswith("#"):
                    parts = line.strip().split('\t')
                    if len(parts) >= 6:
                        entries.append({
                            "ts": parts[0],
                            "uid": parts[1],
                            "src_ip": parts[2],
                            "dest_ip": parts[3],
                            "cookie": parts[4],
                            "result": parts[5]
                        })
    except FileNotFoundError:
        pass
    return entries
