from collections import defaultdict
from typing import Optional
from app.oui import lookup_oui
from app.pcap_engine import PcapParser, ProtocolDissector, TrafficAnalyzer, is_private

# ── External service prefix → display name ───────────────────────────────────
EXTERNAL_SERVICES = {
    "17.": "Apple (iCloud/Push)",
    "142.250.": "Google",
    "2607:f8b0:": "Google",
    "2606:4700:": "Cloudflare",
    "2603:": "Microsoft 365",
    "34.": "Google Cloud",
    "35.": "Google Cloud",
    "140.82.112.": "GitHub",
    "54.": "Amazon AWS",
    "52.": "Amazon AWS",
    "3.": "Amazon AWS",
    "162.247.": "Fastly CDN",
    "108.139.": "Amazon CloudFront",
    "57.144.": "Apple",
    "57.155.": "Apple (IMAP)",
}

# ── Hostname keyword → (device label, manufacturer) ──────────────────────────
HOSTNAME_DEVICE_MAP = {
    "iphone":      ("Apple iPhone",       "Apple"),
    "macbook":     ("Apple MacBook",      "Apple"),
    "ipad":        ("Apple iPad",         "Apple"),
    "imac":        ("Apple iMac",         "Apple"),
    "mac mini":    ("Apple Mac Mini",     "Apple"),
    "mac pro":     ("Apple Mac Pro",      "Apple"),
    "macpro":      ("Apple Mac Pro",      "Apple"),
    "macmini":     ("Apple Mac Mini",     "Apple"),
    "appletv":     ("Apple TV",           "Apple"),
    "apple tv":    ("Apple TV",           "Apple"),
    "homepod":     ("Apple HomePod",      "Apple"),
    "applewatch":  ("Apple Watch",        "Apple"),
    "apple":       ("Apple Device",       "Apple"),
    "galaxy":      ("Samsung Galaxy",     "Samsung"),
    "samsung":     ("Samsung Device",     "Samsung"),
    "pixel":       ("Google Pixel",       "Google"),
    "android":     ("Android Device",     "Google"),
    "kindle":      ("Amazon Kindle",      "Amazon"),
    "echo":        ("Amazon Echo",        "Amazon"),
    "firetv":      ("Amazon Fire TV",     "Amazon"),
    "nest":        ("Google Nest",        "Google"),
    "chromecast":  ("Chromecast",         "Google"),
    "xbox":        ("Microsoft Xbox",     "Microsoft"),
    "playstation": ("Sony PlayStation",   "Sony"),
    "nintendo":    ("Nintendo Switch",    "Nintendo"),
    "sonos":       ("Sonos Speaker",      "Sonos"),
    "ring":        ("Ring Camera",        "Ring"),
    "desktop":     ("Windows PC",         "Microsoft"),
    "printer":     ("Network Printer",    "Unknown"),
    "raspberrypi": ("Raspberry Pi",       "Raspberry Pi"),
    "raspberry":   ("Raspberry Pi",       "Raspberry Pi"),
    "nas":         ("NAS Drive",          "Unknown"),
}

DHCP_VENDOR_MAP = {
    "android": ("Android Device", "Android"),
    "MSFT":    ("Windows PC",     "Microsoft"),
    "udhcpc":  ("Linux Device",   "Linux"),
    "dhcpcd":  ("Linux Device",   "Linux"),
    "apple":   ("Apple Device",   "Apple"),
}

_GENERIC = {'Unknown Device', 'Unknown', ''}


def _norm_mac(mac: Optional[str]) -> Optional[str]:
    if not mac:
        return None
    return mac.upper().replace('-', ':').strip()


def _identify_external(ip: str):
    for prefix, name in EXTERNAL_SERVICES.items():
        if ip.startswith(prefix):
            return name
    return None


def _is_locally_administered_mac(mac: str) -> bool:
    if not mac:
        return False
    try:
        return bool(int(mac.split(":")[0], 16) & 0x02)
    except (ValueError, IndexError):
        return False


def _infer_manufacturer(hostname: str, mac: str, services: list, vendor_class: str = "") -> tuple:
    hn = (hostname or "").lower()
    for kw, (label, mfr) in HOSTNAME_DEVICE_MAP.items():
        if kw in hn:
            return label, mfr

    vc = (vendor_class or "").lower()
    for sub, (label, mfr) in DHCP_VENDOR_MAP.items():
        if sub.lower() in vc:
            return label, mfr

    svc = " ".join(services).lower()
    if "apple" in svc and "icloud" in svc: return "Apple Device", "Apple"
    if "apple" in svc:                     return "Apple Device", "Apple"
    if "google" in svc:                    return "Android Device", "Google"

    oui = lookup_oui(mac) if mac else "Unknown"
    if oui != "Unknown":
        return oui + " Device", oui

    return "Unknown Device", "Unknown"


def _port_label(port: int) -> str:
    labels = {
        80: "HTTP", 443: "HTTPS", 53: "DNS", 22: "SSH", 21: "FTP",
        25: "SMTP", 587: "SMTP/TLS", 993: "IMAP", 995: "POP3",
        3389: "RDP", 5900: "VNC", 8080: "HTTP Alt", 8443: "HTTPS Alt",
        123: "NTP", 67: "DHCP", 68: "DHCP", 5353: "mDNS",
        1900: "UPnP", 5223: "Apple Push",
    }
    return labels.get(port, f"Port {port}")


def _extract_hostnames(dissected_packets: list) -> dict:
    """Pull device names from mDNS PTR, DHCP, and NetBIOS inside dissected packets."""
    hostname_map = {}

    for pkt in dissected_packets:
        ip  = pkt.get('ip')
        app = pkt.get('app')
        src_ip = ip.get('src_ip', '') if ip else ''

        if not app or app.get('protocol') != 'DNS':
            continue
        details = app.get('details', {})
        if not details:
            continue

        for ans in details.get('answers', []):
            name = ans.get('name', '')
            if ans.get('type') == 'PTR' and '.local' in name:
                base = name.split('.local')[0]
                if '._' in base:
                    base = base.split('._')[0]
                base = base.strip()
                if src_ip and is_private(src_ip) and not src_ip.startswith('fe80') and base:
                    if len(base) > len(hostname_map.get(src_ip, '')):
                        hostname_map[src_ip] = base

        for q in details.get('queries', []):
            name = q.get('name', '')
            if '.local' in name and src_ip and is_private(src_ip):
                base = name.split('.local')[0]
                if '._' in base:
                    base = base.split('._')[0]
                base = base.strip()
                if base and len(base) > len(hostname_map.get(src_ip, '')):
                    hostname_map[src_ip] = base

    return hostname_map


# ── Main entry point ──────────────────────────────────────────────────────────

def parse_pcap_file(pcap_path: str, scan_devices: list = None) -> dict:
    """
    Parse a pcap/pcapng file and return the full analysis dict.

    Phase 1 — CSV device catalog:
        Build an IP-keyed lookup from the Angry IP Scanner export.
        Each entry carries the authoritative device name, hostname, MAC, and
        vendor as observed by the active scan.

    Phase 2 — PCAP analysis:
        Parse raw packets, dissect protocol layers, extract mDNS/DHCP
        hostnames, and run the traffic analyzer (flows, anomaly detectors).

    Phase 3 — Match by IP and enrich:
        For every IP seen in either source, merge the CSV identity (name,
        hostname, vendor) with the PCAP traffic statistics (bytes, packets,
        services, suspicious ports).  Devices are tagged with data_source:
          'both'         — seen in CSV scan AND in PCAP traffic
          'active_only'  — scan responded, zero PCAP traffic
          'passive_only' — PCAP traffic observed, never answered the scan

    Phase 4 — Vulnerability scoring:
        Build alerts from engine anomalies and per-device flags, then score
        the overall threat level 0–100.
    """

    # ── Phase 1: build CSV device catalog (IP → scan record) ─────────────────
    scan_catalog: dict = {}
    if scan_devices:
        for d in scan_devices:
            ip = d.get('ip')
            if ip:
                scan_catalog[ip] = d

    # ── Phase 2: parse PCAP ───────────────────────────────────────────────────
    capture     = PcapParser.parse(pcap_path)
    raw_packets = capture['packets']
    dissected   = [ProtocolDissector.dissect(p) for p in raw_packets]

    hostname_map   = _extract_hostnames(dissected)
    analyzer       = TrafficAnalyzer()
    engine_results = analyzer.process(dissected)

    # ── Phase 3: build unified device list ───────────────────────────────────
    devices = _build_devices(engine_results, hostname_map, analyzer, scan_catalog)

    # ── Phase 4: alerts and scoring ───────────────────────────────────────────
    alerts = _build_alerts(engine_results['anomalies'], devices)
    threat_score, risk_level = _score(alerts)

    # Protocol breakdown
    proto_counts  = engine_results['protocol_counter']
    total_pkts    = engine_results['total_packets']
    protocols     = sorted(proto_counts.items(), key=lambda x: x[1], reverse=True)[:8]
    protocol_list = [
        {'name': n, 'count': c, 'pct': round(c / total_pkts * 100, 1) if total_pkts else 0}
        for n, c in protocols
    ]

    # Port summary
    port_counter = engine_results['port_counter']
    SUSP = {4444, 1337, 31337, 6667, 6666, 9001, 9050, 8888, 5555}
    port_list = [
        {'port': p, 'count': c, 'suspicious': p in SUSP, 'label': _port_label(p)}
        for p, c in sorted(port_counter.items(), key=lambda x: x[1], reverse=True)[:10]
    ]

    # Top external services
    ext_services: dict = defaultdict(int)
    for hs in engine_results['tls_handshakes']:
        sni = hs.get('sni', '')
        dst = hs.get('dst_ip', '')
        if sni:
            ext_services[sni] += 1
        elif dst and not is_private(dst):
            svc = _identify_external(dst)
            if svc:
                ext_services[svc] += 1
    for req in engine_results['http_requests']:
        host = req.get('host', '')
        dst  = req.get('dst_ip', '')
        if host:
            ext_services[host] += 1
        elif dst and not is_private(dst):
            svc = _identify_external(dst)
            if svc:
                ext_services[svc] += 1

    top_services = sorted(ext_services.items(), key=lambda x: x[1], reverse=True)[:6]

    return {
        'summary': {
            'total_packets':   total_pkts,
            'total_bytes':     engine_results['total_bytes'],
            'duration_secs':   round(engine_results['duration'], 1),
            'unique_hosts':    len(devices),
            'retransmissions': 0,
            'retrans_pct':     0.0,
            'dns_failures':    engine_results['dns_failures'],
            'alert_count':     len(alerts),
            'threat_score':    threat_score,
            'risk_level':      risk_level,
        },
        'devices':      devices,
        'protocols':    protocol_list,
        'ports':        port_list,
        'alerts':       alerts,
        'top_services': [{'name': k, 'count': v} for k, v in top_services],
    }


def _build_devices(engine: dict, hostname_map: dict, analyzer: TrafficAnalyzer,
                   scan_catalog: dict = None) -> list:
    """
    Build the unified device list in three steps:

    Step 1 — Union of IPs:
        Combine PCAP internal IPs, ARP table entries, and CSV catalog IPs into
        one set so no device from either source is missed.

    Step 2 — Per-IP merge:
        For each IP, pull identity (name, hostname, MAC, vendor) from the CSV
        catalog first (active scan data is authoritative for identity).
        Then overlay PCAP traffic statistics (bytes, packets, services).

    Step 3 — Determine data_source and flag anomalies:
        'both' if the IP appears in the CSV catalog AND has PCAP traffic.
        'active_only' if in the catalog but silent in the capture.
        'passive_only' if there is PCAP traffic but the scan never saw it.
    """
    if scan_catalog is None:
        scan_catalog = {}

    arp_table     = engine['arp_table']
    ip_bytes_sent = engine['ip_bytes_sent']
    ip_bytes_recv = engine['ip_bytes_recv']
    ip_pkts_sent  = engine['ip_pkts_sent']
    ip_pkts_recv  = engine['ip_pkts_recv']

    # Per-device external services from TLS SNI + HTTP host
    device_services: dict = defaultdict(set)
    for hs in engine['tls_handshakes']:
        src = hs.get('src_ip', '')
        sni = hs.get('sni', '')
        if src and is_private(src):
            if sni:
                device_services[src].add(sni)
            else:
                svc = _identify_external(hs.get('dst_ip', ''))
                if svc:
                    device_services[src].add(svc)
    for req in engine['http_requests']:
        src  = req.get('src_ip', '')
        host = req.get('host', '')
        if src and is_private(src) and host:
            device_services[src].add(host)

    # Per-device suspicious port hits
    SUSP_PORTS = {
        4444: 'Metasploit default', 1337: 'Common backdoor',
        31337: 'Back Orifice', 6667: 'IRC (C2)', 6666: 'IRC',
        9001: 'Tor relay', 9050: 'Tor proxy', 8888: 'C2 common',
    }
    device_suspicious: dict = defaultdict(list)
    for key in analyzer.flows:
        if len(key) != 5:
            continue
        src_ip, dst_ip = key[0], key[1]
        for port in (key[2], key[3]):
            if port in SUSP_PORTS and is_private(src_ip):
                entry = {'port': port, 'reason': SUSP_PORTS[port], 'dst': dst_ip}
                if entry not in device_suspicious[src_ip]:
                    device_suspicious[src_ip].append(entry)

    # ── Step 1: union of all IPs ──────────────────────────────────────────────
    all_ips: set = set(engine['internal_ips'])
    for ip in arp_table:
        if is_private(ip) and not ip.startswith('fe80') and not ip.startswith('169.254'):
            all_ips.add(ip)
    for ip in scan_catalog:
        if is_private(ip):
            all_ips.add(ip)

    device_list = []

    for ip in all_ips:
        if ip.startswith('fe80') or ip.startswith('169.254'):
            continue
        if ip.startswith('ff'):          # IPv6 multicast (ff02::fb, ff02::1, etc.)
            continue
        # Skip IPv4 broadcast and multicast — these are not real devices
        if ip.endswith('.255') or ip == '255.255.255.255':
            continue
        try:
            _first = int(ip.split('.')[0])
            if 224 <= _first <= 239:
                continue
        except (ValueError, IndexError):
            pass

        # ── Step 2: pull PCAP data for this IP ───────────────────────────────
        pcap_macs    = [m for m in arp_table.get(ip, []) if m and m != '00:00:00:00:00:00']
        mac_pcap     = pcap_macs[0] if pcap_macs else ''
        bytes_sent   = ip_bytes_sent.get(ip, 0)
        bytes_recv   = ip_bytes_recv.get(ip, 0)
        pkts_sent    = ip_pkts_sent.get(ip, 0)
        pkts_recv    = ip_pkts_recv.get(ip, 0)
        total_pkts   = pkts_sent + pkts_recv
        total_bytes  = bytes_sent + bytes_recv
        pcap_hostname = hostname_map.get(ip, '')
        has_pcap_traffic = total_pkts > 0

        # ── Pull CSV (active scan) identity for this IP ───────────────────────
        sd = scan_catalog.get(ip)
        if sd:
            mac_csv       = sd.get('mac') or ''
            scan_hostname = sd.get('hostname') or sd.get('netbios_hostname') or ''
            mac_vendor    = sd.get('mac_vendor') or ''
        else:
            mac_csv = scan_hostname = mac_vendor = ''

        # ── Resolve MAC: CSV (active scan) is more reliable than ARP sniffing ─
        mac = (_norm_mac(mac_csv) or _norm_mac(mac_pcap) or '').upper()

        # ── Resolve hostname: mDNS from PCAP is real-time, CSV is fallback ────
        hostname = pcap_hostname or scan_hostname

        # ── Resolve device name and manufacturer ──────────────────────────────
        services     = list(device_services.get(ip, set()))[:4]
        inferred_name, inferred_mfr = _infer_manufacturer(hostname, mac, services)

        # CSV vendor (from active MAC lookup) wins over PCAP inference
        if mac_vendor and mac_vendor not in _GENERIC:
            manufacturer = mac_vendor
        elif inferred_mfr not in _GENERIC:
            manufacturer = inferred_mfr
        else:
            oui = lookup_oui(mac) if mac else 'Unknown'
            manufacturer = oui if oui != 'Unknown' else 'Unknown'

        # Device name preference order:
        #   PCAP-inferred meaningful name → CSV hostname → PCAP hostname → fallback
        if inferred_name not in _GENERIC:
            device_name = inferred_name
        elif scan_hostname:
            device_name = scan_hostname
        elif pcap_hostname:
            device_name = pcap_hostname
        else:
            device_name = 'Unknown Device'

        # Router override
        if ip.endswith('.1') and total_pkts > 0:
            device_name  = 'Network Router'
            oui = lookup_oui(mac) if mac else ''
            manufacturer = oui if (oui and oui != 'Unknown') else 'Router'

        # ── Step 3: data_source and flagging ─────────────────────────────────
        if sd and has_pcap_traffic:
            data_source = 'both'
        elif sd:
            data_source = 'active_only'
        else:
            data_source = 'passive_only'

        flagged = manufacturer in _GENERIC and not hostname

        device_list.append({
            'ip':           ip,
            'mac':          mac,
            'manufacturer': manufacturer,
            'hostname':     hostname,
            'device_name':  device_name,
            'data_source':  data_source,

            # PCAP traffic fields
            'packets':          total_pkts,
            'bytes':            total_bytes,
            'bytes_sent':       bytes_sent,
            'bytes_recv':       bytes_recv,
            'services':         services,
            'suspicious_ports': device_suspicious.get(ip, []),
            'flagged':          flagged,

            # Active scan fields (None when no CSV was uploaded)
            'scan_ping_ms':          sd.get('ping_ms')          if sd else None,
            'scan_responded':        sd.get('responded', False)  if sd else False,
            'scan_open_ports':       sd.get('open_ports', [])    if sd else [],
            'scan_mac_vendor':       sd.get('mac_vendor')        if sd else None,
            'scan_netbios':          sd.get('netbios_info')      if sd else None,
            'scan_netbios_hostname': sd.get('netbios_hostname')  if sd else None,
            'scan_web_detect':       sd.get('web_detect')        if sd else None,
            'scan_packet_loss':      sd.get('packet_loss_pct')   if sd else None,

            # Internal keys used by mismatch detectors — stripped before JSON response
            '_scan_hostname': scan_hostname,
            '_pcap_hostname': pcap_hostname,
        })

    device_list.sort(key=lambda d: _ip_sort_key(d['ip']))
    return device_list


def _ip_sort_key(ip: str):
    try:
        return tuple(int(x) for x in ip.split('.'))
    except ValueError:
        return (999, 999, 999, 999)


def _build_alerts(anomalies: list, devices: list) -> list:
    """Map engine anomalies + per-device flags to frontend alert objects."""
    CATEGORY_MAP = {
        'port_scan':         ('high',     'port_scan',         'Possible port scan detected'),
        'c2_beacon':         ('critical', 'c2_beacon',         'C2 beaconing pattern detected'),
        'dns_tunnel':        ('critical', 'dns_tunnel',        'DNS tunneling suspected'),
        'arp_spoof':         ('critical', 'arp_spoof',         'ARP spoofing detected'),
        'exfiltration':      ('high',     'data_exfil',        'Potential data exfiltration'),
        'suspicious_port':   ('high',     'suspicious_port',   'Traffic on suspicious port'),
        'cleartext':         ('high',     'cleartext',         'Cleartext protocol detected'),
        'tls':               ('medium',   'tls_issue',         'Deprecated TLS version in use'),
        'smb_lateral':       ('critical', 'smb_lateral',       'SMB Lateral Movement Detected'),
        'dhcp_rogue':        ('critical', 'dhcp_rogue',        'Rogue DHCP Server Detected'),
        'llmnr_poisoning':   ('high',     'llmnr_poisoning',   'LLMNR/NBT-NS Poisoning Suspected'),
        'ntp_amplification': ('medium',   'ntp_amplification', 'NTP Amplification Reflector Detected'),
        'icmp_tunnel':       ('high',     'icmp_tunnel',       'ICMP Tunneling Suspected'),
        'dns_rebind':        ('critical', 'dns_rebind',        'DNS Rebinding Attack Detected'),
        'c2_domain':         ('high',     'c2_domain',         'Known C2 Domain Contacted'),
    }

    ACTIONS = {
        'port_scan':         'Identify which device ran the scan and check for malware or unauthorized software.',
        'c2_beacon':         'Immediately isolate the source device and run a full malware scan.',
        'dns_tunnel':        'Block the flagged domain at the router and scan devices for exfiltration malware.',
        'arp_spoof':         'Disconnect suspected devices immediately — someone may be intercepting traffic.',
        'data_exfil':        'Investigate which device initiated the transfer and review its recent activity.',
        'suspicious_port':   'Investigate the device and block this port at the firewall.',
        'cleartext':         'Disable this service and replace it with its encrypted equivalent.',
        'tls_issue':         'Update device software to enforce TLS 1.2 or 1.3.',
        'unknown_device':    'Change your WiFi password and audit all connected devices.',
        'mac_privacy':       '',
        'smb_lateral':       'Isolate the source device immediately. Run a full ransomware/malware scan on it and all targeted hosts. Check for encrypted files.',
        'dhcp_rogue':        'Identify and disconnect the rogue DHCP server. Rotate all network credentials — the gateway may have been spoofed and traffic intercepted.',
        'llmnr_poisoning':   'Disable LLMNR and NetBIOS Name Service on all Windows hosts via Group Policy. Identify and isolate the poisoner IP.',
        'ntp_amplification': 'Restrict NTP monlist on this device. If it is a router or NAS, update firmware. Report the IP to your ISP if external DDoS is confirmed.',
        'icmp_tunnel':       'Block oversized ICMP at the perimeter firewall. Investigate the source device for tunneling software or malware.',
        'dns_rebind':        'Block the flagged domain at the router DNS level. Rotate credentials for any internal service the attacker may have reached.',
        'c2_domain':         'Isolate the device immediately and run a full malware scan. Block the domain at the router/firewall. Check for outbound data exfiltration.',
    }

    alerts = []

    # Device-level alerts
    for d in devices:
        if d['flagged']:
            if _is_locally_administered_mac(d['mac']):
                alerts.append({
                    'severity': 'info',
                    'type':     'mac_privacy',
                    'title':    'Device using MAC address privacy',
                    'detail':   (f"{d['ip']} ({d['mac']}) — randomized MAC, "
                                 f"likely a phone or laptop with privacy mode on."),
                    'action':   '',
                    'ip':       d['ip'],
                })
            else:
                alerts.append({
                    'severity': 'low',
                    'type':     'unknown_device',
                    'title':    'Unknown device on network',
                    'detail':   f"{d['ip']} ({d['mac']}) — unrecognized device, {d['packets']:,} packets.",
                    'action':   ACTIONS['unknown_device'],
                    'ip':       d['ip'],
                })
        for sp in d['suspicious_ports']:
            alerts.append({
                'severity': 'medium',
                'type':     'suspicious_port',
                'title':    f"Traffic on suspicious port {sp['port']}",
                'detail':   f"{d['ip']} contacted {sp['dst']} on port {sp['port']} ({sp['reason']}).",
                'action':   ACTIONS['suspicious_port'],
                'ip':       d['ip'],
            })

    # Engine anomalies
    for a in anomalies:
        cat = a.get('category', '')
        sev, atype, title = CATEGORY_MAP.get(
            cat, (a.get('severity', 'medium'), cat, cat.replace('_', ' ').title())
        )
        alerts.append({
            'severity': sev,
            'type':     atype,
            'title':    title,
            'detail':   a.get('description', ''),
            'action':   ACTIONS.get(atype, ''),
            'ip':       a.get('source', a.get('ip', '')),
        })

    return alerts


def _score(alerts: list) -> tuple:
    # Weights encode Likelihood × Impact per alert type.
    # Confirmed active threats with network-wide blast radius score highest;
    # theoretical or low-blast-radius findings score lowest.
    _TYPE_WEIGHTS = {
        # Confirmed, active, whole-network impact
        'arp_spoof':             30,
        'dhcp_rogue':            30,
        'smb_lateral':           28,
        'c2_beacon':             28,
        'dns_tunnel':            26,
        'dns_rebind':            26,
        # Confirmed active, device/data impact
        'data_exfil':            22,
        'c2_domain':             20,
        'llmnr_poisoning':       16,
        # Cross-reference confirmed, identity/infrastructure
        'shadow_infrastructure': 16,
        'hostname_spoof':        14,
        'icmp_tunnel':           13,
        # Observed anomalies, require additional conditions to weaponize
        'suspicious_port':       10,
        'ghost_device':          10,
        'port_scan':              9,
        'cleartext':              7,
        'ntp_amplification':      7,
        'tls_issue':              4,
        # Low likelihood or low impact
        'unknown_device':         3,
        'mac_privacy':            0,
    }
    # Each threat TYPE is scored at most once. Finding 10 unknown devices is
    # not 10× more dangerous than finding 1 — it's still the same threat category.
    # Multiple alerts of the same type confirm the finding but don't inflate the score.
    scored_types: set = set()
    score = 0
    for a in alerts:
        atype = a['type']
        if atype not in scored_types:
            scored_types.add(atype)
            score += _TYPE_WEIGHTS.get(atype, {'critical': 20, 'high': 10, 'medium': 5, 'low': 2, 'info': 0}.get(a['severity'], 0))
    score = min(score, 100)
    risk_level = ('CRITICAL' if score >= 55 else 'HIGH' if score >= 30
                  else 'MEDIUM' if score >= 12 else 'LOW' if score > 0 else 'CLEAN')
    return score, risk_level
