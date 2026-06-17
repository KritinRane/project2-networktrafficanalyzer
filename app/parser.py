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

# Known external IP prefixes -> service name
EXTERNAL_SERVICES = {
    "17.": "Apple (iCloud/Push Notifications)",
    "2620:149:": "Apple (iCloud)",
    "2607:f8b0:": "Google",
    "2606:4700:": "Cloudflare",
    "2603:": "Microsoft 365",
    "2601:": "Comcast (ISP)",
    "34.": "Google Cloud",
    "35.": "Google Cloud",
    "142.250.": "Google",
    "140.82.112.": "GitHub",
    "50.19.": "AWS (Grammarly)",
    "54.": "Amazon AWS",
    "52.": "Amazon AWS",
    "3.": "Amazon AWS",
    "100.": "AWS/Cloudflare",
    "162.247.": "Fastly CDN",
    "130.211.": "Google Cloud",
    "108.139.": "Amazon CloudFront",
    "57.144.": "Apple",
    "57.155.": "Apple (IMAP)",
}

# Known device name patterns from mDNS hostnames seen in traffic
HOSTNAME_DEVICE_MAP = {
    "iphone": ("Apple iPhone", "Apple"),
    "macbook": ("Apple MacBook", "Apple"),
    "ipad": ("Apple iPad", "Apple"),
    "imac": ("Apple iMac", "Apple"),
    "apple": ("Apple Device", "Apple"),
    "android": ("Android Device", "Android"),
    "samsung": ("Samsung Device", "Samsung"),
    "pixel": ("Google Pixel", "Google"),
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
    return any(ip.startswith(p) for p in (
        "192.168.", "10.", "172.16.", "172.17.", "172.18.", "172.19.",
        "172.2", "172.3",
    ))


def _is_skip(ip):
    if not ip:
        return True
    skip = ("224.", "239.", "255.", "0.0.0.0", "ff0", "ff02", "ff05")
    return any(ip.startswith(s) or ip == s for s in skip) or ip.endswith(".255")


def _identify_external(ip):
    if not ip:
        return None
    for prefix, name in EXTERNAL_SERVICES.items():
        if ip.startswith(prefix):
            return name
    return None


def _infer_device(hostname, mac, services_contacted):
    """Infer device type from hostname, MAC, and services it talks to."""
    hn = (hostname or "").lower()
    for keyword, (device_name, manufacturer) in HOSTNAME_DEVICE_MAP.items():
        if keyword in hn:
            return device_name, manufacturer

    # infer from services contacted
    svc_str = " ".join(services_contacted).lower()
    if "apple" in svc_str and "icloud" in svc_str:
        return "Apple Device", "Apple"
    if "apple" in svc_str:
        return "Apple Device", "Apple"
    if "google" in svc_str and "android" in svc_str:
        return "Android Device", "Android"

    # try OUI
    oui = lookup_oui(mac) if mac else "Unknown"
    if oui != "Unknown":
        return oui + " Device", oui

    return "Unknown Device", "Unknown"


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
            try:
                total_bytes += int(frame_len)
            except (ValueError, TypeError):
                pass

        # IPs -- support both IPv4 and IPv6
        src_ip = _get(layers, "ip", "ip.src") or _get(layers, "ipv6", "ipv6.src")
        dst_ip = _get(layers, "ip", "ip.dst") or _get(layers, "ipv6", "ipv6.dst")
        src_mac = _get(layers, "eth", "eth.src")
        dst_mac = _get(layers, "eth", "eth.dst")

        # extract hostnames -- check every layer for .local names
        for layer_name, layer_data in layers.items():
            if not isinstance(layer_data, dict):
                continue
            for field_key, field_val in layer_data.items():
                if isinstance(field_val, str) and ".local" in field_val.lower():
                    name_lower = field_val.lower()
                    # associate with the src IP if it's local
                    if src_ip and _is_local(src_ip):
                        # clean up: take the readable part before .local
                        base = field_val.split(".local")[0]
                        # strip service prefixes like _companion-link._tcp.
                        if "._" in base:
                            parts = base.split("._")
                            base = parts[0]
                        if base and len(base) > 2:
                            existing = hostname_map.get(src_ip, "")
                            # prefer longer/more descriptive hostnames
                            if len(base) > len(existing):
                                hostname_map[src_ip] = base
                    break

        # protocol
        proto = _get(layers, "_ws.col.Protocol") or "Other"
        if isinstance(proto, list):
            proto = proto[0]
        protocol_counts[str(proto)] += 1

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
            try:
                sp = _get(tcp, "tcp.srcport")
                dp = _get(tcp, "tcp.dstport")
                if sp: src_port = int(sp)
                if dp: dst_port = int(dp)
            except (ValueError, TypeError):
                pass
        elif udp:
            try:
                sp = _get(udp, "udp.srcport")
                dp = _get(udp, "udp.dstport")
                if sp: src_port = int(sp)
                if dp: dst_port = int(dp)
            except (ValueError, TypeError):
                pass

        if dst_port:
            port_counts[dst_port] += 1

        # track external services
        for ip in [src_ip, dst_ip]:
            if ip and not _is_local(ip) and not _is_skip(ip):
                svc = _identify_external(ip)
                if svc:
                    external_services[svc] += 1

        # device tracking -- local IPs only, skip link-local IPv6 and multicast
        for ip, mac in [(src_ip, src_mac), (dst_ip, dst_mac)]:
            if not ip or _is_skip(ip) or not _is_local(ip):
                continue
            if ip.startswith("fe80") or ip.startswith("169.254"):
                continue

            if ip not in devices:
                devices[ip] = {
                    "ip": ip,
                    "mac": mac or "",
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

            pkt_size = 0
            try:
                pkt_size = int(frame_len) if frame_len else 0
            except (ValueError, TypeError):
                pass

            if ip == src_ip:
                d["packets_sent"] += 1
                d["bytes_sent"] += pkt_size
                if dst_port and dst_port in SUSPICIOUS_PORTS:
                    entry = {"port": dst_port, "reason": SUSPICIOUS_PORTS[dst_port], "dst": dst_ip}
                    if entry not in d["suspicious_ports"]:
                        d["suspicious_ports"].append(entry)
                if dst_ip:
                    svc = _identify_external(dst_ip)
                    if svc:
                        d["services_contacted"].add(svc)
            else:
                d["packets_recv"] += 1
                d["bytes_recv"] += pkt_size

    # build device list
    import sys
    print("HOSTNAME MAP:", hostname_map, file=sys.stderr)
    device_list = []
    for ip, d in sorted(devices.items(), key=lambda x: x[1]["packets_sent"] + x[1]["packets_recv"], reverse=True):
        total_pkts = d["packets_sent"] + d["packets_recv"]
        hostname = hostname_map.get(ip, "")
        device_name, manufacturer = _infer_device(
            hostname, d["mac"], list(d["services_contacted"])
        )

        # special case: router
        if ip.endswith(".1") and total_pkts > 0:
            device_name = "Network Router"
            manufacturer = lookup_oui(d["mac"]) if d["mac"] else "Router"
            if manufacturer == "Unknown":
                manufacturer = "Router"

        flagged = manufacturer == "Unknown" and not hostname

        device_list.append({
            "ip": ip,
            "mac": d["mac"],
            "manufacturer": manufacturer,
            "hostname": hostname,
            "device_name": device_name,
            "packets": total_pkts,
            "bytes": d["bytes_sent"] + d["bytes_recv"],
            "bytes_sent": d["bytes_sent"],
            "bytes_recv": d["bytes_recv"],
            "suspicious_ports": d["suspicious_ports"],
            "services": list(d["services_contacted"])[:4],
            "flagged": flagged,
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
                "detail": f"{d['ip']} ({d['mac']}) — unrecognized device, {d['packets']:,} packets sent/received.",
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
            "detail": f"{retransmissions:,} retransmissions ({retrans_pct}% of TCP). Suggests packet loss or unstable connection.",
        })
    if dns_failures > 10:
        alerts.append({
            "severity": "medium", "type": "dns_failures",
            "title": "DNS resolution failures",
            "detail": f"{dns_failures:,} failed DNS lookups detected.",
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