from typing import Optional
from app.pcap_engine import is_private


def _norm_mac(mac: Optional[str]) -> Optional[str]:
    if not mac:
        return None
    return mac.upper().replace('-', ':').strip()


def _ip_sort_key(ip: str):
    try:
        return tuple(int(x) for x in ip.split('.'))
    except ValueError:
        return (999, 999, 999, 999)


# ── Merge ────────────────────────────────────────────────────────────────────

def merge_scan_and_pcap(scan_devices: list, pcap_devices: list) -> list:
    """
    Merge Angry IP Scanner rows with PCAP-derived device records.
    Match priority: IP (exact), then MAC fallback.
    Returns a unified list with a `data_source` field on each entry.
    """
    scan_by_ip  = {d['ip']: d for d in scan_devices}
    scan_by_mac = {_norm_mac(d['mac']): d for d in scan_devices if d.get('mac')}
    pcap_by_ip  = {d['ip']: d for d in pcap_devices}
    pcap_by_mac = {_norm_mac(d['mac']): d for d in pcap_devices if d.get('mac')}

    merged: dict = {}

    for sd in scan_devices:
        ip  = sd['ip']
        mac = _norm_mac(sd.get('mac'))
        pd  = pcap_by_ip.get(ip) or (pcap_by_mac.get(mac) if mac else None)
        merged[ip] = _merge_record(sd, pd, 'both' if pd else 'active_only')

    for pd in pcap_devices:
        ip  = pd['ip']
        mac = _norm_mac(pd.get('mac'))
        if ip in merged:
            continue
        if mac and mac in scan_by_mac:
            continue  # already merged via MAC above
        # Exclude noise IPs
        if not is_private(ip) or ip.startswith('fe80') or ip.startswith('169.254'):
            continue
        merged[ip] = _merge_record(None, pd, 'passive_only')

    return sorted(merged.values(), key=lambda d: _ip_sort_key(d['ip']))


def _merge_record(scan: Optional[dict], pcap: Optional[dict], source: str) -> dict:
    s = scan or {}
    p = pcap or {}

    _GENERIC = {'Unknown Device', 'Unknown', ''}

    mac = _norm_mac(p.get('mac')) or _norm_mac(s.get('mac'))

    # Hostname: prefer mDNS/DHCP from PCAP, fall back to active scan hostname
    pcap_hostname = p.get('hostname', '')
    scan_hostname = (s.get('hostname') or s.get('netbios_hostname') or '')
    hostname = pcap_hostname or scan_hostname

    # Only use PCAP-derived name/manufacturer when they are actually meaningful
    pcap_name = p.get('device_name', '')
    pcap_mfr  = p.get('manufacturer', '')
    meaningful_pcap_name = pcap_name if pcap_name not in _GENERIC else ''
    meaningful_pcap_mfr  = pcap_mfr  if pcap_mfr  not in _GENERIC else ''

    device_name  = meaningful_pcap_name or scan_hostname or hostname or 'Unknown Device'
    manufacturer = meaningful_pcap_mfr  or s.get('mac_vendor') or 'Unknown'

    return {
        'ip':               s.get('ip') or p.get('ip'),
        'mac':              mac or '',
        'manufacturer':     manufacturer,
        'hostname':         hostname,
        'device_name':      device_name,
        'data_source':      source,

        # PCAP traffic fields
        'packets':          p.get('packets', 0),
        'bytes':            p.get('bytes', 0),
        'bytes_sent':       p.get('bytes_sent', 0),
        'bytes_recv':       p.get('bytes_recv', 0),
        'services':         p.get('services', []),
        'suspicious_ports': p.get('suspicious_ports', []),
        'flagged':          p.get('flagged', False),

        # Active scan fields
        'scan_ping_ms':         s.get('ping_ms'),
        'scan_responded':       s.get('responded', False),
        'scan_open_ports':      s.get('open_ports', []),
        'scan_mac_vendor':      s.get('mac_vendor'),
        'scan_netbios':         s.get('netbios_info'),
        'scan_netbios_hostname': s.get('netbios_hostname'),
        'scan_web_detect':      s.get('web_detect'),
        'scan_packet_loss':     s.get('packet_loss_pct'),

        # Raw originals kept for mismatch detection (stripped before JSON response)
        '_scan_hostname': s.get('hostname', ''),
        '_pcap_hostname': p.get('hostname', ''),
    }


# ── Mismatch Detectors ────────────────────────────────────────────────────────

_GHOST_ACTION = (
    'Verify this device manually. Check if it has host-based firewall rules '
    'that allow ICMP but block all other traffic. Run a port scan to confirm '
    'it is still reachable and investigate whether it is hardened or hiding.'
)

_SPOOF_ACTION = (
    'Cross-reference both hostnames against your asset inventory. Check ARP '
    'tables on your router for MAC address consistency. If the discrepancy '
    'cannot be explained, isolate the device immediately and investigate.'
)

_SHADOW_ACTION = (
    'Physically trace this device using switch MAC address tables or a Wi-Fi '
    'management console. Do not allow it to continue operating until its '
    'purpose and owner are confirmed. Change Wi-Fi credentials if origin '
    'cannot be determined.'
)


def detect_ghost_devices(devices: list) -> list:
    """
    Ghost Device: responded to active ICMP ping but transmitted 0 bytes
    in the passive PCAP capture window.
    """
    alerts = []
    for d in devices:
        if d['data_source'] != 'both':
            continue
        if not d.get('scan_responded'):
            continue
        if d['bytes'] == 0 and d['packets'] == 0:
            ping = d.get('scan_ping_ms')
            ping_str = f'{ping} ms' if ping is not None else 'alive'
            alerts.append({
                'severity': 'high',
                'type':     'ghost_device',
                'title':    'Ghost Device — Active but Silent in Capture',
                'detail':   (
                    f"{d['ip']} ({d['mac'] or 'no MAC'}) responded to the active ICMP "
                    f"scan ({ping_str}) but transmitted zero bytes during passive monitoring. "
                    f"This suggests a host-based firewall that allows ICMP but blocks all "
                    f"other traffic, or a device that went offline between the scan and capture."
                ),
                'action':   _GHOST_ACTION,
                'ip':       d['ip'],
            })
    return alerts


def detect_hostname_spoofing(devices: list) -> list:
    """
    Hostname Identity Mismatch: the NetBIOS/DNS hostname from the active scan
    clearly contradicts the mDNS/DHCP hostname captured in the PCAP.
    """
    alerts = []
    for d in devices:
        if d['data_source'] != 'both':
            continue

        scan_raw = (d.get('scan_netbios_hostname') or d.get('_scan_hostname') or '').lower().strip()
        pcap_raw = (d.get('_pcap_hostname') or '').lower().strip()

        if not scan_raw or not pcap_raw:
            continue

        # Normalize: strip domain suffixes and possessive forms
        scan_base = scan_raw.split('.')[0].strip()
        pcap_base = pcap_raw.split('.')[0].split("'s ")[-1].strip()

        # Skip if either base is too short to be meaningful
        if len(scan_base) < 3 or len(pcap_base) < 3:
            continue

        # Flag only when they are clearly different (no prefix overlap)
        if (scan_base != pcap_base
                and not pcap_base.startswith(scan_base)
                and not scan_base.startswith(pcap_base)):
            alerts.append({
                'severity': 'critical',
                'type':     'hostname_spoof',
                'title':    'Hostname Identity Mismatch Detected',
                'detail':   (
                    f"{d['ip']} ({d['mac'] or 'no MAC'}) advertised hostname "
                    f"'{d.get('scan_netbios_hostname') or d.get('_scan_hostname')}' "
                    f"during the active NetBIOS/DNS scan, but passive traffic identifies "
                    f"it as '{d.get('_pcap_hostname')}' via mDNS/DHCP. "
                    f"This discrepancy may indicate hostname spoofing, ARP poisoning, "
                    f"or a recently reconfigured device."
                ),
                'action':   _SPOOF_ACTION,
                'ip':       d['ip'],
            })
    return alerts


def detect_shadow_infrastructure(devices: list) -> list:
    """
    Shadow Infrastructure: device actively talking in the PCAP that was
    completely invisible to the active ICMP/NetBIOS scan.
    """
    _SHADOW_MIN_BYTES = 1024  # ignore sub-1 KB link-local noise
    _MULTICAST_PREFIXES = ('224.', '239.', '255.')

    alerts = []
    for d in devices:
        if d['data_source'] != 'passive_only':
            continue
        if d['bytes'] < _SHADOW_MIN_BYTES:
            continue
        ip = d['ip']
        if any(ip.startswith(p) for p in _MULTICAST_PREFIXES) or ip.endswith('.255'):
            continue

        alerts.append({
            'severity': 'high',
            'type':     'shadow_infrastructure',
            'title':    'Shadow Infrastructure — Evading Active Discovery',
            'detail':   (
                f"{ip} ({d['mac'] or 'no MAC'}, {d['manufacturer']}) generated "
                f"{d['bytes']:,} bytes of traffic during passive monitoring but did "
                f"not respond to any active scan probes (ICMP ping, NetBIOS, port scan). "
                f"This device is deliberately or accidentally evading network discovery — "
                f"a potential rogue AP, honeypot, or stealth device."
            ),
            'action':   _SHADOW_ACTION,
            'ip':       ip,
        })
    return alerts
