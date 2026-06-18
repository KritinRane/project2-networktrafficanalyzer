import csv
import io
from typing import Optional

_NA = {'[n/a]', '[n/s]', 'n/a', '[n/a', 'n/s', 'n/s]', ''}


def _clean(val: str) -> Optional[str]:
    v = (val or '').strip()
    return None if v.lower().strip('[]') in ('n/a', 'n/s', '') or v in _NA else v


def _parse_ports(raw: Optional[str]) -> list:
    if not raw:
        return []
    ports = []
    # Angry IP Scanner uses either '.' or ',' as port separators depending on version
    normalized = raw.replace(',', '.').replace(' ', '')
    for tok in normalized.split('.'):
        try:
            p = int(tok)
            if 1 <= p <= 65535:
                ports.append(p)
        except ValueError:
            pass
    return ports


def _parse_ping_ms(raw: Optional[str]) -> Optional[int]:
    if not raw:
        return None
    cleaned = raw.lower().replace('ms', '').replace('timeout', '').strip()
    try:
        return int(float(cleaned))
    except ValueError:
        return None


def _parse_packet_loss(raw: Optional[str]) -> Optional[float]:
    """'2/4 (50%)' -> 50.0"""
    if not raw:
        return None
    try:
        return float(raw.split('(')[1].replace('%)', '').strip())
    except (IndexError, ValueError, AttributeError):
        return None


def _norm_mac(mac: Optional[str]) -> Optional[str]:
    if not mac:
        return None
    return mac.upper().strip()


def _extract_netbios_hostname(netbios: Optional[str]) -> Optional[str]:
    """
    'WORKGROUP [94-E2-3C-50-A0-9B]'  -> None
    'DESKTOP-ABC123 [MAC]'           -> 'DESKTOP-ABC123'
    """
    if not netbios:
        return None
    name = netbios.split('[')[0].strip()
    if name.upper() in ('WORKGROUP', ''):
        return None
    return name if name else None


# ── Flexible column header resolver ──────────────────────────────────────────
# Maps canonical key → list of possible header strings (case-insensitive).
# First match wins.
_HEADER_ALIASES = {
    'ip':          ['ip', 'ip address', 'ipaddress', 'address'],
    'ping':        ['ping', 'ping (ms)', 'latency', 'response time'],
    'ports':       ['ports', 'open ports', 'openports', 'port'],
    'hostname':    ['hostname', 'host name', 'dns name', 'name'],
    'mac':         ['mac address', 'mac addr', 'mac', 'hardware address'],
    'mac_vendor':  ['mac vendor', 'vendor', 'manufacturer', 'oui'],
    'netbios':     ['netbios info', 'netbios', 'netbios name'],
    'web_detect':  ['web detect', 'web detection', 'http'],
    'packet_loss': ['packet loss', 'loss'],
    'ttl':         ['ttl'],
}


def _build_column_map(fieldnames: list) -> dict:
    """
    Given actual CSV fieldnames, return {canonical_key: actual_fieldname}.
    Matches case-insensitively and ignores leading/trailing whitespace.
    """
    normalized = {f.strip().lower(): f for f in (fieldnames or [])}
    col_map = {}
    for key, aliases in _HEADER_ALIASES.items():
        for alias in aliases:
            if alias in normalized:
                col_map[key] = normalized[alias]
                break
    return col_map


def _get(row: dict, col_map: dict, key: str, default: str = '') -> str:
    field = col_map.get(key)
    if field is None:
        return default
    return (row.get(field) or '').strip()


def parse_angry_ip_csv(content: bytes) -> list:
    """
    Parse an Angry IP Scanner tab-delimited or comma-delimited export.

    Handles:
    - BOM (UTF-8 and UTF-16)
    - Comment lines starting with '#'
    - Flexible column header names (case-insensitive, alias matching)
    - Both '.' and ',' as port-list separators
    - Filters dead placeholder rows (no ping response AND no MAC address)
    """
    # Decode — try UTF-8-BOM first, fall back to UTF-8, then latin-1
    for encoding in ('utf-8-sig', 'utf-8', 'latin-1'):
        try:
            text = content.decode(encoding, errors='strict')
            break
        except (UnicodeDecodeError, LookupError):
            continue
    else:
        text = content.decode('utf-8', errors='replace')

    # Strip bare BOM if still present
    text = text.lstrip('﻿').lstrip('￾')

    # Remove comment / metadata lines (start with '#')
    lines = [ln for ln in text.splitlines() if not ln.strip().startswith('#')]
    if not lines:
        return []
    clean_text = '\n'.join(lines)

    # Detect delimiter: try tab first, then comma
    header_line = lines[0]
    delimiter = '\t' if '\t' in header_line else ','

    reader = csv.DictReader(io.StringIO(clean_text), delimiter=delimiter)

    # Build flexible column map from actual headers
    col_map = _build_column_map(reader.fieldnames)

    # If we can't find the IP column at all, parsing will produce nothing useful
    if 'ip' not in col_map:
        return []

    devices = []
    for row in reader:
        ip = _clean(_get(row, col_map, 'ip'))
        if not ip:
            continue

        ping_raw = _clean(_get(row, col_map, 'ping'))
        mac_raw  = _clean(_get(row, col_map, 'mac'))

        responded = ping_raw is not None
        if not responded and not mac_raw:
            continue  # dead placeholder row (all-[n/a] filler)

        ping_ms     = _parse_ping_ms(ping_raw)
        mac         = _norm_mac(mac_raw)
        hostname    = _clean(_get(row, col_map, 'hostname'))
        mac_vendor  = _clean(_get(row, col_map, 'mac_vendor'))
        netbios_raw = _clean(_get(row, col_map, 'netbios'))
        ports_raw   = _clean(_get(row, col_map, 'ports'))
        web_detect  = _clean(_get(row, col_map, 'web_detect'))
        loss_raw    = _clean(_get(row, col_map, 'packet_loss'))

        # Strip .local suffix and trailing dots from hostnames
        if hostname:
            hostname = hostname.rstrip('.')
            if hostname.lower().endswith('.local'):
                hostname = hostname[:-6]

        devices.append({
            'ip':               ip,
            'mac':              mac,
            'mac_vendor':       mac_vendor,
            'hostname':         hostname,
            'netbios_info':     netbios_raw,
            'netbios_hostname': _extract_netbios_hostname(netbios_raw),
            'ping_ms':          ping_ms,
            'responded':        responded,
            'open_ports':       _parse_ports(ports_raw),
            'packet_loss_pct':  _parse_packet_loss(loss_raw),
            'web_detect':       web_detect,
        })

    return devices
