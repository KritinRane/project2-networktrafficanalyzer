from collections import defaultdict
from app.oui import lookup_oui

SUSPICIOUS_PORTS = {
    4444: "Metasploit default",
    1337: "Common backdoor",
    31337: "Back Orifice",
    6667: "IRC (often malware C2)",
    6666: "IRC",
    9001: "Tor relay",
    9050: "Tor proxy",
    8888: "Common C2 port",
}

KNOWN_SERVICES = {
    "17.": "Apple (iCloud/Push)",
    "2620:149:": "Apple (iCloud)",
    "2607:f8b0:": "Google",
    "2606:4700:": "Cloudflare",
    "2603:": "Microsoft",
    "34.": "Google Cloud",
    "35.": "Google Cloud",
    "142.250.": "Google",
    "140.82.112.": "GitHub",
    "50.19.": "Grammarly (AWS)",
    "54.157.": "Grammarly (AWS)",
    "162.247.": "Fastly CDN",
}


def _get(pkt, *keys):
    cur = pkt
    for k in keys:
        if not isinstance(cur, dict):
            return None
        cur = cur.get(k)
    return cur


def _is_local(ip):
    if not ip:
        return False
    local_prefixes = (
        "192.168.", "10.", "172.16.", "172.17.", "172.18.", "172.19.",
        "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
        "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.",
        "fe80::", "fc", "fd",
    )
    return any(ip.lower().startswith(p) for p in local_prefixes)


def _is_multicast(ip):
    if not ip:
        return False
    return (ip.startswith("224.") or ip.startswith("239.") or
            ip.startswith("ff0") or ip.startswith("ff02") or
            ip == "255.255.255.255" or ip == "192.168.1.255" or
            ip == "0.0.0.0")


def _get_ip_pair(layers):
    """Extract src/dst IP supporting both IPv4 and IPv6."""
    src = _get(layers, "ip", "ip.src") or _get(layers, "ipv6", "ipv6.src")
    dst = _get(layers, "ip", "ip.dst") or _get(layers, "ipv6", "ipv6.dst")
    return src, dst


def _identify_service(ip):
    if not ip:
        return None
    for prefix, name in KNOWN_SERVICES.items():
        if ip.startswith(prefix):
            return name
    return None


def parse_packets(raw_packets: list) -> dict:
    devices = {}
    hostname_map = {}
    protocol_counts = defaultdict(int)
    port_counts = defaultdict(int)
    retransmissions = 0
    dns_failures = 0
    total_bytes = 0
    start_time = None
    end_time = None
    external_services = defaultdict(int)

    for raw in raw_packets:
        layers = _get(raw, "_source", "layers") or {}

        # timing
        epoch = _get(layers, "frame", "frame.time_epoch")
        if epoch:
            try:
                t = float(epoch)
            except (ValueError, TypeError):
                try:
                    from datetime import datetime
                    t = datetime.fromisoformat(str(epoch).replace('Z', '+00:00')).timestamp()
                except Exception:
                    t = None
            if t is not None:
                if start_time is None or t < start_time:
                    start_time = t
                if end_time is None or t > end_time:
                    end_time = t

        frame_len = _get(layers, "frame", "frame.len")
        if frame_len:
            total_bytes += int(frame_len)

        src_ip, dst_ip = _get_ip_pair(layers)
        src_mac = _get(layers, "eth", "eth.src")
        dst_mac = _get(layers, "eth", "eth.dst")

        # extract hostnames from mDNS
        # extract hostnames from mDNS responses
        dns_layer = _get(layers, "dns")
        if dns_layer:
            # look for .local hostnames in any dns field
            for key, val in dns_layer.items() if isinstance(dns_layer, dict) else []:
                if isinstance(val, str) and ".local" in val.lower():
                    name = val.lower()
                    if src_ip and _is_local(src_ip) and not src_ip.startswith("fe80"):
                        clean = val.split(".local")[0].split(".")[-1]
                        if clean:
                            hostname_map[src_ip] = clean
                    break

        # protocol
        proto = _get(layers, "_ws.col.Protocol") or "Other"
        if isinstance(proto, list):
            proto = proto[0]
        protocol_counts[proto] += 1

        # retransmissions
        tcp = _get(layers, "tcp")
        if tcp:
            ta = _get(tcp, "tcp.analysis")
            if ta and _get(ta, "tcp.analysis.retransmission"):
                retransmissions += 1

        # DNS failures
        dns = _get(layers, "dns")
        if dns:
            rcode = _get(dns, "dns.flags_tree", "dns.flags.rcode")
            if rcode and str(rcode) != "0":
                dns_failures += 1

        # ports
        udp = _get(layers, "udp")
        src_port = dst_port = None
        if tcp:
            sp = _get(tcp, "tcp.srcport")
            dp = _get(tcp, "tcp.dstport")
            if sp:
                src_port = int(sp)
            if dp:
                dst_port = int(dp)
        elif udp:
            sp = _get(udp, "udp.srcport")
            dp = _get(udp, "udp.dstport")
            if sp:
                src_port = int(sp)
            if dp:
                dst_port = int(dp)

        if dst_port:
            port_counts[dst_port] += 1

        # track external services
        for ip in [src_ip, dst_ip]:
            if ip and not _is_local(ip) and not _is_multicast(ip):
                svc = _identify_service(ip)
                if svc:
                    external_services[svc] += 1

        # device tracking -- only local IPs
        for ip, mac in [(src_ip, src_mac), (dst_ip, dst_mac)]:
            if not ip or _is_multicast(ip) or not _is_local(ip):
                continue
            if ip.startswith("fe80::"):
                continue  # skip link-local IPv6, too noisy
            if ip not in devices:
                devices[ip] = {
                    "ip": ip,
                    "mac": mac or "",
                    "manufacturer": lookup_oui(mac) if mac else "Unknown",
                    "packets_sent": 0,
                    "packets_recv": 0,
                    "bytes_sent": 0,
                    "bytes_recv": 0,
                    "suspicious_ports": [],
                    "services_contacted": set(),
                }
            d = devices[ip]
            if mac and not d["mac"]:
                d["mac"] = mac
                d["manufacturer"] = lookup_oui(mac)

            pkt_size = int(frame_len) if frame_len else 0
            if ip == src_ip:
                d["packets_sent"] += 1
                d["bytes_sent"] += pkt_size
                if dst_port and dst_port in SUSPICIOUS_PORTS:
                    entry = {"port": dst_port, "reason": SUSPICIOUS_PORTS[dst_port], "dst": dst_ip}
                    if entry not in d["suspicious_ports"]:
                        d["suspicious_ports"].append(entry)
                if dst_ip:
                    svc = _identify_service(dst_ip)
                    if svc:
                        d["services_contacted"].add(svc)
            else:
                d["packets_recv"] += 1
                d["bytes_recv"] += pkt_size

    # build device list with hostnames
    device_list = []
    for ip, d in sorted(devices.items(), key=lambda x: x[1]["packets_sent"] + x[1]["packets_recv"], reverse=True):
        total_pkts = d["packets_sent"] + d["packets_recv"]
        hostname = hostname_map.get(ip, "")

# infer from hostname
        manufacturer = d["manufacturer"]
        if manufacturer == "Unknown":
            hn = hostname.lower()
            if any(x in hn for x in ["iphone", "macbook", "ipad", "imac", "apple"]):
                manufacturer = "Apple"
            elif "android" in hn:
                manufacturer = "Android"
            elif ip == "192.168.1.1":
                manufacturer = "Router (Arcadyan)"

        # fallback: infer from traffic patterns when hostname also missing
        if manufacturer == "Unknown":
            services = list(d["services_contacted"])
            svc_str = " ".join(services).lower()
            if "apple" in svc_str or "icloud" in svc_str:
                manufacturer = "Apple device"
            elif "google" in svc_str and ip != "192.168.1.1":
                manufacturer = "Android device"
        device_list.append({
            "ip": ip,
            "mac": d["mac"],
            "manufacturer": d["manufacturer"],
            "hostname": hostname,
            "packets": total_pkts,
            "bytes": d["bytes_sent"] + d["bytes_recv"],
            "bytes_sent": d["bytes_sent"],
            "bytes_recv": d["bytes_recv"],
            "suspicious_ports": d["suspicious_ports"],
            "services": list(d["services_contacted"]),
            "flagged": d["manufacturer"] == "Unknown" and not hostname and ip != "192.168.1.1",

        })

    total_pkts = sum(protocol_counts.values())
    protocols = sorted(protocol_counts.items(), key=lambda x: x[1], reverse=True)[:8]
    protocol_list = [
        {"name": name, "count": count, "pct": round(count / total_pkts * 100, 1) if total_pkts else 0}
        for name, count in protocols
    ]

    port_list = sorted(port_counts.items(), key=lambda x: x[1], reverse=True)[:10]
    port_summary = [
        {"port": p, "count": c, "suspicious": p in SUSPICIOUS_PORTS, "label": _port_label(p)}
        for p, c in port_list
    ]

    duration_secs = round(end_time - start_time, 1) if start_time and end_time else 0
    tcp_total = protocol_counts.get("TCP", 0)
    retrans_pct = round(retransmissions / tcp_total * 100, 1) if tcp_total else 0

    alerts = []
    for d in device_list:
        if d["flagged"]:
            alerts.append({
                "severity": "high", "type": "unknown_device",
                "title": "Unknown device on network",
                "detail": f"{d['ip']} ({d['mac']}) — unrecognized manufacturer, {d['packets']:,} packets.",
                "ip": d["ip"],
            })
        for sp in d["suspicious_ports"]:
            alerts.append({
                "severity": "high", "type": "suspicious_port",
                "title": f"Traffic on suspicious port {sp['port']}",
                "detail": f"{d['ip']} contacted {sp['dst']} on port {sp['port']} ({sp['reason']}).",
                "ip": d["ip"],
            })

    if retrans_pct > 1.5:
        alerts.append({
            "severity": "medium", "type": "retransmissions",
            "title": "Elevated TCP retransmissions",
            "detail": f"{retransmissions:,} retransmissions ({retrans_pct}% of TCP traffic). Suggests packet loss or an unstable connection.",
        })
    if dns_failures > 10:
        alerts.append({
            "severity": "medium", "type": "dns_failures",
            "title": "DNS resolution failures",
            "detail": f"{dns_failures:,} failed DNS lookups. Could indicate misconfigured DNS or connectivity issues.",
        })

    top_services = sorted(external_services.items(), key=lambda x: x[1], reverse=True)[:5]

    return {
        "summary": {
            "total_packets": total_pkts,
            "total_bytes": total_bytes,
            "duration_secs": duration_secs,
            "unique_hosts": len(device_list),
            "retransmissions": retransmissions,
            "retrans_pct": retrans_pct,
            "dns_failures": dns_failures,
            "alert_count": len(alerts),
        },
        "devices": device_list,
        "protocols": protocol_list,
        "ports": port_summary,
        "alerts": alerts,
        "top_services": [{"name": k, "count": v} for k, v in top_services],
    }


def _port_label(port):
    labels = {
        80: "HTTP", 443: "HTTPS", 53: "DNS", 22: "SSH",
        21: "FTP", 25: "SMTP", 587: "SMTP/TLS", 993: "IMAP",
        995: "POP3", 3389: "RDP", 5900: "VNC", 8080: "HTTP Alt",
        8443: "HTTPS Alt", 123: "NTP", 67: "DHCP", 68: "DHCP",
        5353: "mDNS", 1900: "UPnP", 5223: "Apple Push",
    }
    return labels.get(port, f"Port {port}")