# ── Mismatch Detectors ────────────────────────────────────────────────────────

_GHOST_ACTION = (
    'Usually benign — most LAN captures are taken from a laptop or the gateway, '
    'not a mirror/SPAN port, so a device\'s unicast traffic is simply not visible. '
    'Only investigate if you specifically expected this device to be generating '
    'traffic during the capture.'
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
                'severity': 'info',
                'type':     'ghost_device',
                'title':    'Device answered scan but was silent in capture',
                'detail':   (
                    f"{d['ip']} ({d['mac'] or 'no MAC'}) responded to the active ICMP "
                    f"scan ({ping_str}) but sent no traffic during the packet capture. "
                    f"On a typical LAN capture this is expected — the capture point can't "
                    f"see this device's unicast traffic. Not a security finding on its own."
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
    _SHADOW_MIN_BYTES = 50_000  # sustained activity, not link-local chatter
    _MULTICAST_PREFIXES = ('224.', '239.', '255.')

    alerts = []
    for d in devices:
        if d['data_source'] != 'passive_only':
            continue
        if d['bytes'] < _SHADOW_MIN_BYTES:
            continue
        # Require real independent activity: the device actually established
        # outbound sessions to external hosts (TLS SNI / HTTP host observed),
        # not just LAN broadcast/multicast (mDNS, SSDP, ARP). A host that only
        # chatters on the broadcast domain but ignored the ICMP scan is almost
        # always a normal device with its firewall dropping ping (Windows does
        # this by default, as do most IoT devices) — not a rogue.
        if not d.get('services'):
            continue
        ip = d['ip']
        if any(ip.startswith(p) for p in _MULTICAST_PREFIXES) or ip.endswith('.255'):
            continue

        alerts.append({
            'severity': 'medium',
            'type':     'shadow_infrastructure',
            'title':    'Active device not seen by the scan',
            'detail':   (
                f"{ip} ({d['mac'] or 'no MAC'}, {d['manufacturer']}) generated "
                f"{d['bytes']:,} bytes and reached external services during the capture, "
                f"but did not respond to the active scan (ICMP/NetBIOS/port). "
                f"Often just a device with ICMP disabled; worth identifying to confirm "
                f"it is a known, sanctioned device."
            ),
            'action':   _SHADOW_ACTION,
            'ip':       ip,
        })
    return alerts
