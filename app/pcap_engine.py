"""
Pure-Python PCAP/PCAPNG parser and traffic analyzer.
Adapted from neatlabs packet-capture-analyzer (MIT).
No external dependencies required.
"""

import struct, socket, gzip, math, ipaddress
from collections import defaultdict, Counter
from typing import Dict, List, Any

# ── Magic numbers ────────────────────────────────────────────────────────────
PCAP_MAGIC_LE    = 0xa1b2c3d4
PCAP_MAGIC_BE    = 0xd4c3b2a1
PCAP_MAGIC_NS_LE = 0xa1b23c4d
PCAP_MAGIC_NS_BE = 0x4d3cb2a1
PCAPNG_MAGIC     = 0x0a0d0d0a

# ── Protocol maps ────────────────────────────────────────────────────────────
ETHERTYPES = {0x0800: 'IPv4', 0x0806: 'ARP', 0x86DD: 'IPv6', 0x8100: 'VLAN'}

IP_PROTOCOLS = {
    1: 'ICMP', 6: 'TCP', 17: 'UDP', 41: 'IPv6-encap',
    47: 'GRE', 58: 'ICMPv6', 89: 'OSPF',
}

WELL_KNOWN_PORTS = {
    20: 'FTP-Data', 21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
    53: 'DNS', 67: 'DHCP-S', 68: 'DHCP-C', 80: 'HTTP', 110: 'POP3',
    123: 'NTP', 137: 'NetBIOS-NS', 139: 'NetBIOS-SSN', 143: 'IMAP',
    389: 'LDAP', 443: 'HTTPS', 445: 'SMB', 465: 'SMTPS', 514: 'Syslog',
    587: 'SMTP-Sub', 636: 'LDAPS', 993: 'IMAPS', 995: 'POP3S',
    1433: 'MSSQL', 3306: 'MySQL', 3389: 'RDP', 5060: 'SIP',
    5222: 'XMPP', 5900: 'VNC', 6379: 'Redis', 6667: 'IRC',
    8080: 'HTTP-Alt', 8443: 'HTTPS-Alt', 27017: 'MongoDB',
}

SUSPICIOUS_PORTS = {
    4444: 'Metasploit default', 1337: 'Common backdoor',
    31337: 'Back Orifice', 6666: 'IRC/backdoor', 6667: 'IRC',
    9001: 'Tor', 9050: 'Tor SOCKS', 5555: 'Android ADB',
    12345: 'NetBus', 2323: 'Telnet-alt',
    # 8888 removed — Jupyter, dev servers, and many apps use this legitimately
}

# Legitimate SaaS/CDN domains that use long subdomains (auth tokens, CDN paths).
# DNS tunnel detection is suppressed for these to avoid false positives.
_DNS_TUNNEL_WHITELIST = frozenset({
    'atl-paas.net', 'atlassian.net', 'atlassian.com',      # Atlassian (Jira, Confluence)
    'azure.com', 'azure.net', 'azurewebsites.net',         # Azure (App Insights, APIs)
    'cloudfront.net',                                     # AWS CloudFront
    'akamaihd.net', 'akamai.net', 'akamaiedge.net', 'akadns.net',  # Akamai
    'edgekey.net', 'edgesuite.net',                       # Akamai
    'fastly.net', 'fastlylb.net',                        # Fastly
    'amazonaws.com', 'awsstatic.com',                    # AWS / S3
    'msecnd.net', 'windows.net', 'azureedge.net',        # Microsoft Azure CDN
    'trafficmanager.net', 'microsoftonline.com',
    'office.net', 'sharepoint.com', 'live.com', 'outlook.com',
    'apple-cloudkit.com', 'icloud.com', 'cdn-apple.com', 'mzstatic.com',
    'aaplimg.com', 'itunes-apple.com',                   # Apple CDN / image edge
    'googleapis.com', 'googleusercontent.com', 'gstatic.com', 'googlevideo.com',
    'google.com', 'github.com', 'githubusercontent.com', 'githubassets.com',
    'spotify.com', 'scdn.co',                            # Spotify app + CDN
    'slack.com', 'slack-edge.com',
    'salesforce.com', 'force.com',
    'zoom.us', 'zoomgov.com',
    'cloudflare.com', 'cloudflaressl.com',
    'twilio.com', 'sendgrid.net',
})

# Dynamic DNS providers heavily abused by malware for C2 infrastructure
_C2_DOMAINS = frozenset({
    'duckdns.org', 'no-ip.com', 'no-ip.biz', 'hopto.org', 'zapto.org',
    'sytes.net', 'redirectme.net', 'servebeer.com', 'ddnsking.com',
    'myddns.me', 'publicvm.com', '3utilities.com', 'serveftp.com',
    'servegame.com', 'myftp.biz', 'myq-see.com', 'ddns.net',
    'afraid.org', 'changeip.com', 'dynupdate.no-ip.com',
})
_TOR_MARKERS = ('.onion', 'tor2web', '.onion.to', '.onion.sh', '.onion.cab', '.onion.city')

# Legitimate services that publish a PUBLIC DNS name resolving to a PRIVATE
# LAN IP by design — this is exactly the shape of a DNS-rebinding attack but is
# benign. Common on the small/home networks this tool targets (Plex is the
# canonical example: *.plex.direct → the local media server's 192.168.x IP).
_LAN_MAPPED_DOMAINS = ('plex.direct',)

DNS_TYPES = {
    1: 'A', 2: 'NS', 5: 'CNAME', 6: 'SOA', 12: 'PTR', 15: 'MX',
    16: 'TXT', 28: 'AAAA', 33: 'SRV', 65: 'HTTPS', 255: 'ANY',
}

TLS_VERSIONS = {
    0x0301: 'TLS 1.0', 0x0302: 'TLS 1.1',
    0x0303: 'TLS 1.2', 0x0304: 'TLS 1.3',
    0x0300: 'SSL 3.0', 0x0200: 'SSL 2.0',
}
DEPRECATED_TLS = {0x0300, 0x0301, 0x0302, 0x0200}

HTTP_METHODS = {b'GET', b'POST', b'PUT', b'DELETE', b'HEAD', b'OPTIONS', b'PATCH', b'CONNECT'}

PRIVATE_RANGES = [
    ipaddress.ip_network('10.0.0.0/8'),
    ipaddress.ip_network('172.16.0.0/12'),
    ipaddress.ip_network('192.168.0.0/16'),
    ipaddress.ip_network('127.0.0.0/8'),
    ipaddress.ip_network('169.254.0.0/16'),
    ipaddress.ip_network('224.0.0.0/4'),
]

PRIVATE_RANGES_V6 = [
    ipaddress.ip_network('::1/128'),    # loopback
    ipaddress.ip_network('fc00::/7'),   # unique local (fc00:: and fd00::)
    ipaddress.ip_network('fe80::/10'),  # link-local
    ipaddress.ip_network('ff00::/8'),   # multicast
]


def is_private(ip_str: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip_str)
        if isinstance(addr, ipaddress.IPv6Address):
            return any(addr in net for net in PRIVATE_RANGES_V6)
        return any(addr in net for net in PRIVATE_RANGES)
    except Exception:
        return False


def human_bytes(b: int) -> str:
    for unit in ['B', 'KB', 'MB', 'GB']:
        if b < 1024:
            return f'{b:.1f} {unit}'
        b /= 1024
    return f'{b:.1f} TB'


def _is_local_domain(domain: str) -> bool:
    local_suffixes = ('.local', '.lan', '.internal', '.home', '.corp', '.localdomain', 'localhost')
    return any(domain.lower().endswith(s) for s in local_suffixes)


# ═══════════════════════════════════════════════════════════════════════════════
# PCAP / PCAPNG PARSER
# ═══════════════════════════════════════════════════════════════════════════════

class PcapParser:
    """Pure-Python PCAP and PCAPNG file parser. No external dependencies."""

    @staticmethod
    def parse(filepath: str) -> Dict[str, Any]:
        with open(filepath, 'rb') as f:
            header = f.read(4)
            if len(header) < 4:
                raise ValueError("File too small to be a valid capture file")
            magic = struct.unpack('<I', header[:4])[0]

            if magic in (PCAP_MAGIC_LE, PCAP_MAGIC_BE, PCAP_MAGIC_NS_LE, PCAP_MAGIC_NS_BE):
                f.seek(0)
                return PcapParser._parse_pcap(f, magic)
            elif magic == PCAPNG_MAGIC:
                f.seek(0)
                return PcapParser._parse_pcapng(f)
            else:
                # Try gzip
                f.seek(0)
                sig = f.read(2)
                if sig == b'\x1f\x8b':
                    f.seek(0)
                    gz = gzip.GzipFile(fileobj=f)
                    inner_magic = struct.unpack('<I', gz.read(4))[0]
                    gz.seek(0)
                    if inner_magic in (PCAP_MAGIC_LE, PCAP_MAGIC_BE, PCAP_MAGIC_NS_LE, PCAP_MAGIC_NS_BE):
                        return PcapParser._parse_pcap(gz, inner_magic)
                    elif inner_magic == PCAPNG_MAGIC:
                        return PcapParser._parse_pcapng(gz)
                raise ValueError(f"Unknown capture format (magic: 0x{magic:08x}). Upload a .pcap or .pcapng file.")

    @staticmethod
    def _parse_pcap(f, magic):
        is_be = magic in (PCAP_MAGIC_BE, PCAP_MAGIC_NS_BE)
        is_ns = magic in (PCAP_MAGIC_NS_LE, PCAP_MAGIC_NS_BE)
        endian = '>' if is_be else '<'
        hdr = f.read(24)
        _, ver_maj, ver_min, _, _, snaplen, linktype = struct.unpack(f'{endian}IHHiIII', hdr)
        packets = []
        idx = 0
        while True:
            pkt_hdr = f.read(16)
            if len(pkt_hdr) < 16:
                break
            ts_sec, ts_frac, cap_len, orig_len = struct.unpack(f'{endian}IIII', pkt_hdr)
            timestamp = ts_sec + ts_frac / (1e9 if is_ns else 1e6)
            data = f.read(cap_len)
            if len(data) < cap_len:
                break
            packets.append({'index': idx, 'timestamp': timestamp,
                            'cap_len': cap_len, 'orig_len': orig_len,
                            'data': data, 'linktype': linktype})
            idx += 1
        return {'format': 'pcap', 'linktype': linktype, 'packets': packets}

    @staticmethod
    def _parse_pcapng(f):
        packets = []
        linktype = 1
        idx = 0
        # Default to little-endian until we read the SHB byte-order magic
        endian = '<'
        while True:
            block_hdr = f.read(8)
            if len(block_hdr) < 8:
                break
            block_type, block_len = struct.unpack(f'{endian}II', block_hdr)
            if block_len < 12:
                break
            body = f.read(block_len - 12)
            f.read(4)  # trailing length

            if block_type == 0x0A0D0D0A:  # Section Header Block
                # Bytes 0-3 of body are the byte-order magic
                if len(body) >= 4:
                    bom = struct.unpack('<I', body[:4])[0]
                    if bom == 0x1A2B3C4D:
                        endian = '<'
                    elif bom == 0x4D3C2B1A:
                        endian = '>'
            elif block_type == 0x00000001:  # Interface Description Block
                if len(body) >= 2:
                    linktype = struct.unpack(f'{endian}H', body[:2])[0]
            elif block_type == 0x00000006:  # Enhanced Packet Block
                if len(body) >= 20:
                    _, ts_high, ts_low, cap_len, orig_len = struct.unpack(f'{endian}IIIII', body[:20])
                    timestamp = ((ts_high << 32) | ts_low) / 1e6
                    data = body[20:20 + cap_len]
                    packets.append({'index': idx, 'timestamp': timestamp,
                                    'cap_len': cap_len, 'orig_len': orig_len,
                                    'data': data, 'linktype': linktype})
                    idx += 1
            elif block_type == 0x00000003:  # Simple Packet Block
                if len(body) >= 4:
                    orig_len = struct.unpack(f'{endian}I', body[:4])[0]
                    data = body[4:]
                    packets.append({'index': idx, 'timestamp': 0,
                                    'cap_len': len(data), 'orig_len': orig_len,
                                    'data': data, 'linktype': linktype})
                    idx += 1
        return {'format': 'pcapng', 'linktype': linktype, 'packets': packets}


# ═══════════════════════════════════════════════════════════════════════════════
# PROTOCOL DISSECTOR
# ═══════════════════════════════════════════════════════════════════════════════

class ProtocolDissector:

    @staticmethod
    def dissect(pkt: Dict) -> Dict:
        result = {
            'index': pkt['index'], 'timestamp': pkt['timestamp'],
            'cap_len': pkt['cap_len'], 'orig_len': pkt['orig_len'],
            'ethernet': None, 'ip': None, 'transport': None, 'app': None,
        }
        data = pkt['data']
        linktype = pkt.get('linktype', 1)

        if linktype == 1 and len(data) >= 14:
            eth = ProtocolDissector._parse_ethernet(data)
            result['ethernet'] = eth
            data = data[14:]

            if eth['ethertype'] == 0x8100 and len(data) >= 4:
                eth['ethertype'] = struct.unpack('!H', data[2:4])[0]
                data = data[4:]

            etype = eth['ethertype']
            if etype == 0x0800:
                ProtocolDissector._handle_ipv4(data, result)
            elif etype == 0x0806:
                arp = ProtocolDissector._parse_arp(data)
                if arp:
                    result['ip'] = arp
            elif etype == 0x86DD:
                ProtocolDissector._handle_ipv6(data, result)

        elif linktype == 101 and len(data) >= 20:
            ProtocolDissector._handle_ipv4(data, result)

        return result

    @staticmethod
    def _handle_ipv4(data, result):
        ip = ProtocolDissector._parse_ipv4(data)
        if not ip:
            return
        result['ip'] = ip
        payload = data[ip['ihl'] * 4:]
        if ip['protocol'] == 6:
            tcp = ProtocolDissector._parse_tcp(payload)
            if tcp:
                result['transport'] = tcp
                app_payload = payload[tcp['data_offset'] * 4:]
                result['app'] = ProtocolDissector._identify_app(tcp['src_port'], tcp['dst_port'], app_payload, 'tcp')
        elif ip['protocol'] == 17:
            udp = ProtocolDissector._parse_udp(payload)
            if udp:
                result['transport'] = udp
                result['app'] = ProtocolDissector._identify_app(udp['src_port'], udp['dst_port'], payload[8:], 'udp')
        elif ip['protocol'] == 1:
            result['transport'] = ProtocolDissector._parse_icmp(payload)

    @staticmethod
    def _handle_ipv6(data, result):
        ip = ProtocolDissector._parse_ipv6(data)
        if not ip:
            return
        result['ip'] = ip
        payload = data[40:]
        if ip['next_header'] == 6:
            tcp = ProtocolDissector._parse_tcp(payload)
            if tcp:
                result['transport'] = tcp
                result['app'] = ProtocolDissector._identify_app(tcp['src_port'], tcp['dst_port'], payload[tcp['data_offset'] * 4:], 'tcp')
        elif ip['next_header'] == 17:
            udp = ProtocolDissector._parse_udp(payload)
            if udp:
                result['transport'] = udp
                result['app'] = ProtocolDissector._identify_app(udp['src_port'], udp['dst_port'], payload[8:], 'udp')

    @staticmethod
    def _parse_ethernet(data):
        dst = ':'.join(f'{b:02x}' for b in data[:6])
        src = ':'.join(f'{b:02x}' for b in data[6:12])
        ethertype = struct.unpack('!H', data[12:14])[0]
        return {'dst_mac': dst, 'src_mac': src, 'ethertype': ethertype, 'type': 'ethernet'}

    @staticmethod
    def _parse_ipv4(data):
        if len(data) < 20:
            return None
        ihl = data[0] & 0xF
        if ihl < 5:
            return None
        proto = data[9]
        src_ip = socket.inet_ntoa(data[12:16])
        dst_ip = socket.inet_ntoa(data[16:20])
        ttl = data[8]
        return {
            'type': 'ipv4', 'ihl': ihl, 'protocol': proto,
            'protocol_name': IP_PROTOCOLS.get(proto, f'Proto-{proto}'),
            'src_ip': src_ip, 'dst_ip': dst_ip, 'ttl': ttl,
        }

    @staticmethod
    def _parse_ipv6(data):
        if len(data) < 40:
            return None
        next_header = data[6]
        src_ip = socket.inet_ntop(socket.AF_INET6, data[8:24])
        dst_ip = socket.inet_ntop(socket.AF_INET6, data[24:40])
        return {
            'type': 'ipv6', 'next_header': next_header, 'protocol': next_header,
            'protocol_name': IP_PROTOCOLS.get(next_header, f'Proto-{next_header}'),
            'src_ip': src_ip, 'dst_ip': dst_ip, 'ttl': data[7],
        }

    @staticmethod
    def _parse_tcp(data):
        if len(data) < 20:
            return None
        src_port, dst_port = struct.unpack('!HH', data[:4])
        seq = struct.unpack('!I', data[4:8])[0]
        offset_flags = struct.unpack('!H', data[12:14])[0]
        data_offset = (offset_flags >> 12) & 0xF
        flags = offset_flags & 0x3F
        flag_names = [n for n, bit in [('FIN',1),('SYN',2),('RST',4),('PSH',8),('ACK',16),('URG',32)] if flags & bit]
        return {
            'type': 'tcp', 'src_port': src_port, 'dst_port': dst_port,
            'seq': seq, 'data_offset': data_offset,
            'flags': flags, 'flag_names': flag_names,
            'payload_len': max(0, len(data) - data_offset * 4),
            'src_port_name': WELL_KNOWN_PORTS.get(src_port, ''),
            'dst_port_name': WELL_KNOWN_PORTS.get(dst_port, ''),
        }

    @staticmethod
    def _parse_udp(data):
        if len(data) < 8:
            return None
        src_port, dst_port, length = struct.unpack('!HHH', data[:6])
        return {
            'type': 'udp', 'src_port': src_port, 'dst_port': dst_port,
            'payload_len': max(0, length - 8),
            'src_port_name': WELL_KNOWN_PORTS.get(src_port, ''),
            'dst_port_name': WELL_KNOWN_PORTS.get(dst_port, ''),
        }

    @staticmethod
    def _parse_icmp(data):
        if len(data) < 4:
            return None
        icmp_type, code = data[0], data[1]
        names = {0: 'Echo Reply', 3: 'Dest Unreachable', 8: 'Echo Request', 11: 'Time Exceeded'}
        return {'type': 'icmp', 'icmp_type': icmp_type, 'code': code,
                'type_name': names.get(icmp_type, f'Type-{icmp_type}'),
                'payload_len': max(0, len(data) - 8)}

    @staticmethod
    def _parse_arp(data):
        if len(data) < 28:
            return None
        opcode = struct.unpack('!H', data[6:8])[0]
        sender_mac = ':'.join(f'{b:02x}' for b in data[8:14])
        sender_ip  = socket.inet_ntoa(data[14:18])
        target_ip  = socket.inet_ntoa(data[24:28])
        return {
            'type': 'arp', 'opcode': opcode,
            'opcode_name': {1: 'Request', 2: 'Reply'}.get(opcode, f'Op-{opcode}'),
            'sender_mac': sender_mac, 'sender_ip': sender_ip, 'target_ip': target_ip,
            'src_ip': sender_ip, 'dst_ip': target_ip,
        }

    @staticmethod
    def _identify_app(src_port, dst_port, payload, transport):
        app = {'protocol': 'unknown', 'details': {}}
        if 53 in (src_port, dst_port) and len(payload) >= 12:
            # DNS runs over both UDP and TCP; TCP adds a 2-byte length prefix
            dns_payload = payload[2:] if transport == 'tcp' and len(payload) >= 14 else payload
            dns = ProtocolDissector._parse_dns(dns_payload)
            if dns:
                return dns
        if payload and len(payload) > 4:
            first = payload.split(b' ', 1)[0] if b' ' in payload[:12] else b''
            if first in HTTP_METHODS:
                return ProtocolDissector._parse_http_request(payload)
            if payload[:5] == b'HTTP/':
                return ProtocolDissector._parse_http_response(payload)
        if len(payload) >= 5 and payload[0] == 0x16:
            tls = ProtocolDissector._parse_tls(payload)
            if tls:
                return tls
        ports = {src_port, dst_port}
        if 443 in ports or 8443 in ports: app['protocol'] = 'TLS/HTTPS'
        elif 80 in ports or 8080 in ports: app['protocol'] = 'HTTP'
        elif 22 in ports: app['protocol'] = 'SSH'
        elif 21 in ports: app['protocol'] = 'FTP'
        elif 53 in ports: app['protocol'] = 'DNS'
        elif 3389 in ports: app['protocol'] = 'RDP'
        elif 445 in ports: app['protocol'] = 'SMB'
        return app

    @staticmethod
    def _parse_dns(data):
        if len(data) < 12:
            return None
        try:
            txn_id, flags, qdcount, ancount = struct.unpack('!HHHH', data[:8])
            qr = (flags >> 15) & 1
            rcode = flags & 0xF
            queries, offset = [], 12
            for _ in range(min(qdcount, 10)):
                name, offset = ProtocolDissector._dns_name(data, offset)
                if offset + 4 <= len(data):
                    qtype = struct.unpack('!H', data[offset:offset+2])[0]
                    offset += 4
                    queries.append({'name': name, 'type': DNS_TYPES.get(qtype, f'TYPE-{qtype}'), 'type_num': qtype})
            answers = []
            for _ in range(min(ancount, 20)):
                if offset >= len(data): break
                name, offset = ProtocolDissector._dns_name(data, offset)
                if offset + 10 > len(data): break
                rtype, _, ttl, rdlen = struct.unpack('!HHIH', data[offset:offset+10])
                offset += 10
                rdata = data[offset:offset+rdlen]; offset += rdlen
                ans = {'name': name, 'type': DNS_TYPES.get(rtype, f'TYPE-{rtype}'), 'ttl': ttl, 'data': ''}
                if rtype == 1 and len(rdata) == 4: ans['data'] = socket.inet_ntoa(rdata)
                elif rtype == 28 and len(rdata) == 16: ans['data'] = socket.inet_ntop(socket.AF_INET6, rdata)
                answers.append(ans)
            return {'protocol': 'DNS', 'details': {
                'transaction_id': txn_id, 'is_response': bool(qr),
                'rcode': rcode, 'queries': queries, 'answers': answers,
            }}
        except Exception:
            return None

    @staticmethod
    def _dns_name(data, offset):
        labels, seen = [], set()
        while offset < len(data):
            if offset in seen: break
            seen.add(offset)
            length = data[offset]
            if length == 0: offset += 1; break
            if (length & 0xC0) == 0xC0:
                if offset + 1 >= len(data): break
                ptr = struct.unpack('!H', data[offset:offset+2])[0] & 0x3FFF
                name_part, _ = ProtocolDissector._dns_name(data, ptr)
                labels.append(name_part); offset += 2; break
            offset += 1
            if offset + length > len(data): break
            labels.append(data[offset:offset+length].decode('utf-8', errors='replace'))
            offset += length
        return '.'.join(labels), offset

    @staticmethod
    def _parse_http_request(data):
        try:
            lines = data.split(b'\r\n')
            parts = lines[0].decode('utf-8', errors='replace').split(' ', 2)
            headers = {}
            for line in lines[1:]:
                if not line: break
                decoded = line.decode('utf-8', errors='replace')
                if ':' in decoded:
                    k, _, v = decoded.partition(':')
                    headers[k.strip().lower()] = v.strip()
            return {'protocol': 'HTTP', 'details': {
                'method': parts[0] if parts else '',
                'uri': parts[1] if len(parts) > 1 else '',
                'host': headers.get('host', ''),
                'user_agent': headers.get('user-agent', ''),
                'is_request': True,
            }}
        except Exception:
            return {'protocol': 'HTTP', 'details': {'is_request': True}}

    @staticmethod
    def _parse_http_response(data):
        try:
            lines = data.split(b'\r\n')
            parts = lines[0].decode('utf-8', errors='replace').split(' ', 2)
            headers = {}
            for line in lines[1:]:
                if not line: break
                decoded = line.decode('utf-8', errors='replace')
                if ':' in decoded:
                    k, _, v = decoded.partition(':')
                    headers[k.strip().lower()] = v.strip()
            return {'protocol': 'HTTP', 'details': {
                'status_code': parts[1] if len(parts) > 1 else '',
                'server': headers.get('server', ''),
                'is_request': False,
            }}
        except Exception:
            return {'protocol': 'HTTP', 'details': {'is_request': False}}

    @staticmethod
    def _parse_tls(data):
        try:
            if len(data) < 6 or data[0] != 0x16: return None
            rec_version = struct.unpack('!H', data[1:3])[0]
            hs_type = data[5]
            # The record-layer version is legacy and misleading: RFC 8446 §5.1
            # requires a ClientHello to send 0x0301 (TLS 1.0) for middlebox
            # compatibility, and TLS 1.3 hides the true version in the
            # supported_versions extension. The version we can actually trust
            # is the ServerHello's negotiated version (handshake bytes 9-10).
            hs_version = rec_version
            if hs_type in (1, 2) and len(data) >= 11:
                hs_version = struct.unpack('!H', data[9:11])[0]
            # Only a ServerHello reflects what was negotiated. A deprecated
            # ClientHello legacy version is not a finding — flagging it marks
            # essentially all modern HTTPS as "TLS 1.0".
            deprecated   = (hs_type == 2 and hs_version in DEPRECATED_TLS)
            disp_version = hs_version if hs_type == 2 else rec_version
            result = {'protocol': 'TLS', 'details': {
                'version': TLS_VERSIONS.get(disp_version, f'0x{disp_version:04x}'),
                'version_num': disp_version, 'deprecated': deprecated,
                'sni': '', 'handshake': {1: 'ClientHello', 2: 'ServerHello'}.get(hs_type, f'Type-{hs_type}'),
            }}
            # Extract SNI from ClientHello
            if hs_type == 1 and len(data) > 43:
                off = 43
                if off < len(data): sess_len = data[off]; off += 1 + sess_len
                if off + 2 <= len(data):
                    cs_len = struct.unpack('!H', data[off:off+2])[0]; off += 2 + cs_len
                if off < len(data): comp_len = data[off]; off += 1 + comp_len
                if off + 2 <= len(data):
                    ext_len = struct.unpack('!H', data[off:off+2])[0]; off += 2
                    ext_end = off + ext_len
                    while off + 4 <= ext_end and off + 4 <= len(data):
                        ext_type = struct.unpack('!H', data[off:off+2])[0]
                        ext_data_len = struct.unpack('!H', data[off+2:off+4])[0]; off += 4
                        if ext_type == 0 and ext_data_len > 5:
                            sni_data = data[off:off+ext_data_len]
                            if len(sni_data) > 5:
                                name_len = struct.unpack('!H', sni_data[3:5])[0]
                                if len(sni_data) >= 5 + name_len:
                                    result['details']['sni'] = sni_data[5:5+name_len].decode('utf-8', errors='replace')
                        off += ext_data_len
            return result
        except Exception:
            return None


# ═══════════════════════════════════════════════════════════════════════════════
# TRAFFIC ANALYZER
# ═══════════════════════════════════════════════════════════════════════════════

class TrafficAnalyzer:
    """Analyzes dissected packets for flows, statistics, and anomalies."""

    def __init__(self, known_scanner_ip: str = None):
        # IP of the machine running our OWN diagnostic scan (e.g. Angry IP,
        # launched by the live-capture job on this same host). Its scan
        # traffic is authorized and legitimate, but looks identical on the
        # wire to a port scan or SMB fan-out — so it's excluded from those
        # two detectors specifically, rather than tuning the thresholds
        # (which would just as easily hide a real attacker doing the same
        # thing from a different device).
        self.known_scanner_ip = known_scanner_ip
        self.flows = defaultdict(lambda: {
            'packets': 0, 'bytes': 0, 'payload_bytes': 0,
            'start': float('inf'), 'end': 0,
        })
        self.dns_queries   = []
        self.http_requests = []
        self.tls_handshakes = []
        self.arp_table     = defaultdict(set)   # ip → set of MACs
        self.ip_bytes_sent = defaultdict(int)   # ip → bytes sent
        self.ip_bytes_recv = defaultdict(int)   # ip → bytes received
        self.ip_pkts_sent  = defaultdict(int)
        self.ip_pkts_recv  = defaultdict(int)
        self.port_counter  = Counter()
        self.protocol_counter = Counter()
        self.src_dst_pairs = Counter()
        self.total_bytes   = 0
        self.total_packets = 0
        self.unique_ips    = set()
        self.unique_macs   = set()
        self.internal_ips  = set()
        self.external_ips  = set()
        self.timestamps    = []
        self.user_agents   = Counter()
        self.dns_failures  = 0
        self.anomalies     = []
        self.iocs          = []
        # Extended threat detection trackers
        self.dhcp_server_ips  = set()              # IPs sending DHCP offers (port 67→68)
        self.smb_targets      = defaultdict(set)   # src_ip → set of internal dst_ips on 445
        self.llmnr_responses  = defaultdict(int)   # src_ip → count of LLMNR/NBT-NS responses sent
        self.ntp_resp_bytes   = defaultdict(int)   # src_ip → total bytes of NTP responses
        self.icmp_large       = []                 # {src_ip, dst_ip, payload_len} oversized ICMP
        self.dns_rebind_hits  = []                 # {domain, resolved_ip, ttl, querier}
        self.c2_domain_hits   = []                 # {domain, querier, indicator, type}

    def process(self, dissected_packets: List[Dict]) -> Dict:
        self.ingest(dissected_packets)
        return self.run_detectors()

    def ingest(self, dissected_packets: List[Dict]) -> None:
        """Consume packets and populate flow/state tables. Runs no detectors,
        so `known_scanner_ip` can still be set (e.g. via infer_scan_host) after
        ingestion but before detection."""
        for pkt in dissected_packets:
            self._process_packet(pkt)

    def infer_scan_host(self, scan_catalog: dict) -> str:
        """Best-effort identify the IP that ran our OWN subnet scan (Angry IP).

        The scan host is the one internal device that initiates flows to a
        large majority of the devices the scan itself catalogued — it "sees"
        the whole subnet, which is exactly the port_scan / smb_lateral
        signature. Identifying it lets the upload path exclude that authorized
        scan traffic the same way a live-capture run passes known_scanner_ip.

        Only fires when scan data is present, and returns at most the single
        best-matching host — a real attacker on a different IP still trips the
        detectors. Returns None when no host clearly swept the subnet.
        """
        if not scan_catalog:
            return None
        fanout = defaultdict(set)   # client_ip -> distinct internal hosts contacted
        for key, fl in self.flows.items():
            if len(key) == 5 and 'client_ip' in fl:
                c, s = fl['client_ip'], fl.get('server_ip', '')
                if c and s and is_private(c) and is_private(s) and c != s:
                    fanout[c].add(s)
        if not fanout:
            return None
        top_ip = max(fanout, key=lambda k: len(fanout[k]))
        reach  = len(fanout[top_ip])
        # Require the top talker to have reached a large majority of the
        # scanned subnet (and a meaningful absolute floor) before trusting it
        # as our scanner — a busy NAS or file server touches many hosts but
        # rarely half of everything the scan enumerated.
        if reach >= max(10, 0.5 * len(scan_catalog)):
            return top_ip
        return None

    def run_detectors(self) -> Dict:
        self._detect_port_scan()
        self._detect_beaconing()
        self._detect_dns_tunneling()
        self._detect_arp_spoofing()
        self._detect_data_exfil()
        self._detect_suspicious_ports()
        self._detect_cleartext()
        self._detect_tls_issues()
        self._detect_smb_lateral()
        self._detect_dhcp_rogue()
        self._detect_llmnr_poisoning()
        self._detect_ntp_amplification()
        self._detect_icmp_tunneling()
        self._detect_dns_rebinding()
        self._detect_c2_domains()
        return self._compile_results()

    def _process_packet(self, pkt):
        self.total_packets += 1
        cap_len = pkt.get('cap_len', 0)
        self.total_bytes += cap_len
        ts = pkt.get('timestamp', 0)
        if ts > 0:
            self.timestamps.append(ts)

        ip  = pkt.get('ip')
        tr  = pkt.get('transport')
        app = pkt.get('app')
        eth = pkt.get('ethernet')

        if eth:
            self.unique_macs.add(eth.get('src_mac', ''))
            self.unique_macs.add(eth.get('dst_mac', ''))

        if not ip:
            return

        if ip.get('type') == 'arp':
            self.protocol_counter['ARP'] += 1
            self.arp_table[ip.get('sender_ip', '')].add(ip.get('sender_mac', ''))
            return

        src_ip = ip.get('src_ip', '')
        dst_ip = ip.get('dst_ip', '')

        self.unique_ips.update([src_ip, dst_ip])
        self.src_dst_pairs[(src_ip, dst_ip)] += 1

        for addr in (src_ip, dst_ip):
            if addr:
                (self.internal_ips if is_private(addr) else self.external_ips).add(addr)

        self.ip_pkts_sent[src_ip] += 1
        self.ip_pkts_recv[dst_ip] += 1
        self.ip_bytes_sent[src_ip] += cap_len
        self.ip_bytes_recv[dst_ip] += cap_len

        proto_name = ip.get('protocol_name', 'Other')
        self.protocol_counter[proto_name] += 1

        if tr and tr.get('type') in ('tcp', 'udp'):
            sp = tr.get('src_port', 0)
            dp = tr.get('dst_port', 0)
            self.port_counter[dp] += 1

            key = self._flow_key(ip, tr)
            fl = self.flows[key]
            if 'client_ip' not in fl:
                # Record the true initiator from this (first-seen) packet's real
                # src/dst — the flow key itself is canonicalized (smaller of the
                # two (ip, port) tuples first) purely for bidirectional dedup, so
                # it does NOT reliably indicate who initiated the connection.
                fl['client_ip']   = src_ip
                fl['server_ip']   = dst_ip
                fl['server_port'] = dp
            fl['packets'] += 1
            fl['bytes'] += cap_len
            fl['payload_bytes'] += tr.get('payload_len', 0)
            if ts > 0:
                fl['start'] = min(fl['start'], ts)
                fl['end']   = max(fl['end'], ts)

            # ── Extended threat tracking ──────────────────────────────────────
            # DHCP rogue server: server sends offer from port 67 to 68
            if tr.get('type') == 'udp' and sp == 67 and dp == 68 and src_ip and src_ip != '0.0.0.0':
                self.dhcp_server_ips.add(src_ip)

            # SMB lateral movement: internal → internal on port 445
            if 445 in (sp, dp) and is_private(src_ip) and is_private(dst_ip) and not dst_ip.endswith('.255'):
                self.smb_targets[src_ip].add(dst_ip)

            # LLMNR / NBT-NS poisoning: count responses per source IP.
            # A Responder attack is ONE IP answering many queries; normal hosts
            # send very few. We track response count per IP, not unique senders.
            if tr.get('type') == 'udp' and sp in (5355, 137) and is_private(src_ip):
                self.llmnr_responses[src_ip] += 1

            # NTP amplification: large volume of NTP responses from an internal host
            if tr.get('type') == 'udp' and sp == 123 and is_private(src_ip):
                self.ntp_resp_bytes[src_ip] += cap_len

        # ICMP tunneling: very large payloads sustained across many packets
        if tr and tr.get('type') == 'icmp' and is_private(src_ip):
            if tr.get('payload_len', 0) > 512:
                self.icmp_large.append({'src_ip': src_ip, 'dst_ip': dst_ip,
                                        'payload_len': tr['payload_len']})

        if app:
            proto   = app.get('protocol', '')
            details = app.get('details', {})

            if proto == 'DNS':
                for q in details.get('queries', []):
                    self.dns_queries.append({
                        'name': q['name'], 'type': q.get('type', ''),
                        'timestamp': ts, 'src_ip': src_ip,
                    })
                    # C2 / malicious domain matching
                    name_lower = q.get('name', '').lower().rstrip('.')
                    matched = False
                    for indicator in _C2_DOMAINS:
                        if name_lower == indicator or name_lower.endswith('.' + indicator):
                            self.c2_domain_hits.append({
                                'domain': name_lower, 'querier': src_ip,
                                'indicator': indicator, 'type': 'dyndns_c2',
                            })
                            matched = True
                            break
                    if not matched:
                        for marker in _TOR_MARKERS:
                            if marker in name_lower:
                                self.c2_domain_hits.append({
                                    'domain': name_lower, 'querier': src_ip,
                                    'indicator': marker, 'type': 'tor',
                                })
                                break

                if details.get('is_response') and details.get('rcode', 0) != 0:
                    self.dns_failures += 1

                # DNS rebinding: external domain → private IP with tiny TTL
                if details.get('is_response'):
                    for ans in details.get('answers', []):
                        if ans.get('type') == 'A':
                            resolved_ip = ans.get('data', '')
                            ttl         = ans.get('ttl', 9999)
                            domain      = ans.get('name', '').lower().rstrip('.')
                            if (0 < ttl < 60 and resolved_ip and is_private(resolved_ip)
                                    and domain and not _is_local_domain(domain)
                                    and not any(domain == d or domain.endswith('.' + d)
                                                for d in _LAN_MAPPED_DOMAINS)):
                                self.dns_rebind_hits.append({
                                    'domain': domain, 'resolved_ip': resolved_ip,
                                    'ttl': ttl, 'querier': src_ip,
                                })

            elif proto == 'HTTP' and details.get('is_request'):
                self.http_requests.append({
                    'method': details.get('method', ''),
                    'uri':    details.get('uri', ''),
                    'host':   details.get('host', ''),
                    'user_agent': details.get('user_agent', ''),
                    'src_ip': src_ip, 'dst_ip': dst_ip, 'timestamp': ts,
                })
                if details.get('user_agent'):
                    self.user_agents[details['user_agent']] += 1

            elif proto == 'TLS':
                self.tls_handshakes.append({
                    'sni':        details.get('sni', ''),
                    'version':    details.get('version', ''),
                    'version_num': details.get('version_num', 0),
                    'deprecated': details.get('deprecated', False),
                    'handshake':  details.get('handshake', ''),
                    'src_ip': src_ip, 'dst_ip': dst_ip, 'timestamp': ts,
                })

    def _flow_key(self, ip, tr):
        src = ip.get('src_ip', ''); dst = ip.get('dst_ip', '')
        sp  = tr.get('src_port', 0); dp  = tr.get('dst_port', 0)
        proto = tr.get('type', '')
        if (src, sp) > (dst, dp):
            return (dst, src, dp, sp, proto)
        return (src, dst, sp, dp, proto)

    def _detect_port_scan(self):
        # Bucket by the TRUE initiator of each flow (recorded from the first
        # packet's actual src/dst in _process_packet), not by the canonicalized
        # flow-key tuple — that key only sorts (ip, port) pairs for bidirectional
        # dedup and does not indicate who initiated the connection. Using it here
        # previously misattributed scans to busy servers (e.g. a NAS contacted by
        # many clients on many different ports) instead of the actual client.
        svc_ports = defaultdict(set)
        for key, fl in self.flows.items():
            if len(key) == 5 and 'client_ip' in fl:
                svc_ports[fl['client_ip']].add(fl['server_port'])
        for src, ports in svc_ports.items():
            # Exclude: IPv4 routers (.1), IPv6 loopback/gateway (::1), link-local
            # (fe80::), and our own known diagnostic-scan host (see __init__).
            if (len(ports) > 70
                    and not src.endswith('.1')
                    and not src.endswith('::1')
                    and not src.startswith('fe80')
                    and src != self.known_scanner_ip):
                self.anomalies.append({
                    'severity': 'high', 'category': 'port_scan',
                    'description': f'Possible port scan from {src} — {len(ports)} unique service ports contacted',
                    'source': src,
                })
                self.iocs.append({'type': 'scanner_ip', 'value': src})

    def _detect_beaconing(self):
        for (src, dst), count in self.src_dst_pairs.items():
            if count < 5 or is_private(dst):
                continue
            # Suppress cloud/CDN/push destinations. In small-office and home
            # networks the overwhelming majority of periodic, low-jitter
            # traffic is legitimate: Apple/Google push keepalives, RMM agents
            # (ConnectWise, NinjaOne, Datto, Atera), cloud backup, telemetry,
            # and IoT phone-home — all of which live behind these ranges and
            # beacon far more regularly than real jittered C2. A genuine C2
            # channel to a random VPS is NOT in these ranges and still fires.
            if any(dst.startswith(p) for p in self._CDN_PREFIXES):
                continue
            times = [fl['start'] for key, fl in self.flows.items()
                     if len(key) == 5 and key[0] == src and key[1] == dst
                     and fl['start'] < float('inf')]
            if len(times) < 8:
                continue
            times.sort()
            intervals = [times[i+1] - times[i] for i in range(len(times)-1)]
            mean_int = sum(intervals) / len(intervals)
            if mean_int < 1:
                continue
            variance = sum((x - mean_int)**2 for x in intervals) / len(intervals)
            std_dev = math.sqrt(variance) if variance > 0 else 0
            cv = std_dev / mean_int if mean_int > 0 else float('inf')
            if cv < 0.35 and mean_int > 5:  # 0.35 catches jitter-obfuscated C2 beacons
                self.anomalies.append({
                    'severity': 'high', 'category': 'c2_beacon',
                    'description': (f'Periodic beaconing to non-cloud host: {src} → {dst} '
                                    f'every ~{mean_int:.0f}s (CV={cv:.3f}, {count} flows). '
                                    f'Confirm this is not a legitimate agent before acting.'),
                    'source': src, 'destination': dst,
                })
                self.iocs.append({'type': 'c2_candidate', 'value': f'{src} -> {dst}'})

    @staticmethod
    def _shannon_entropy(s: str) -> float:
        if not s:
            return 0.0
        freq = Counter(s)
        n = len(s)
        return -sum((c / n) * math.log2(c / n) for c in freq.values())

    def _detect_dns_tunneling(self):
        domain_lengths = defaultdict(list)
        domain_entropies = defaultdict(list)
        for q in self.dns_queries:
            parts = q.get('name', '').split('.')
            if len(parts) > 2:
                subdomain = '.'.join(parts[:-2])
                apex = '.'.join(parts[-2:])
                domain_lengths[apex].append(len(subdomain))
                if subdomain:
                    domain_entropies[apex].append(self._shannon_entropy(subdomain))
        for domain, lengths in domain_lengths.items():
            if domain in _DNS_TUNNEL_WHITELIST:
                continue
            if len(lengths) >= 5:
                avg_len = sum(lengths) / len(lengths)
                avg_ent = sum(domain_entropies[domain]) / len(domain_entropies[domain]) if domain_entropies[domain] else 0
                # A DNS tunnel encodes data into subdomain labels, which pushes
                # per-character entropy above ~4.0 bits/char. Human/service
                # names (Spotify's 'spclient', Akamai CNAME chains) top out
                # around 3.5–3.8, so entropy — not length — is the tunnel
                # signal. Length alone is NOT sufficient: CDNs legitimately
                # chain very long hostnames. Require high entropy, and treat
                # length only as a corroborating factor at a higher bar.
                high_entropy    = avg_ent > 4.0 and len(lengths) > 8
                long_and_random = avg_len > 40 and avg_ent > 3.8 and len(lengths) > 10
                if high_entropy or long_and_random:
                    reason = f'avg subdomain {avg_len:.0f} chars, entropy {avg_ent:.2f} bits/char'
                    self.anomalies.append({
                        'severity': 'critical', 'category': 'dns_tunnel',
                        'description': f'DNS tunneling suspected: {domain} — {len(lengths)} queries, {reason}',
                    })
                    self.iocs.append({'type': 'dns_tunnel_domain', 'value': domain})

    def _detect_arp_spoofing(self):
        for ip_addr, macs in self.arp_table.items():
            clean = {m for m in macs if m != '00:00:00:00:00:00'}
            if len(clean) > 1:
                self.anomalies.append({
                    'severity': 'critical', 'category': 'arp_spoof',
                    'description': f'ARP spoofing: {ip_addr} has {len(clean)} MACs ({", ".join(clean)})',
                    'ip': ip_addr,
                })
                self.iocs.append({'type': 'arp_spoof_ip', 'value': ip_addr})

    # CDN/cloud prefixes that regularly carry large legitimate transfers.
    # Rate-based exfil alerts are suppressed for these destinations.
    _CDN_PREFIXES = (
        '13.', '52.', '54.', '3.',     # AWS
        '34.', '35.',                  # Google Cloud
        '104.16.', '104.17.', '104.18.', '104.19.',  # Cloudflare
        '23.', '151.101.',             # Fastly / Akamai
        '17.',                         # Apple / iCloud
        '40.', '20.', '13.107.',       # Microsoft / Azure / OneDrive
        '162.125.',                    # Dropbox
    )

    def _detect_data_exfil(self):
        for key, fl in self.flows.items():
            if len(key) != 5:
                continue
            src, dst = key[0], key[1]
            if is_private(dst):
                continue
            # Suppress both volume- and rate-based alerts for known cloud/CDN
            # destinations. For this audience a large upload is almost always a
            # legitimate cloud backup, photo sync, OneDrive/Dropbox/iCloud, or a
            # game/video upload — not exfiltration. A bulk transfer to a random
            # non-cloud host still fires.
            if any(dst.startswith(p) for p in self._CDN_PREFIXES):
                continue
            if fl['payload_bytes'] > 50 * 1024 * 1024:
                self.anomalies.append({
                    'severity': 'high', 'category': 'exfiltration',
                    'description': f'Large outbound transfer: {src} → {dst} ({human_bytes(fl["payload_bytes"])})',
                })
            duration = fl['end'] - fl['start']
            if duration > 0 and fl['payload_bytes'] / duration > 20 * 1024 * 1024:
                self.anomalies.append({
                    'severity': 'medium', 'category': 'exfiltration',
                    'description': f'High-rate transfer: {src} → {dst} at {human_bytes(int(fl["payload_bytes"]/duration))}/s',
                })

    def _detect_suspicious_ports(self):
        seen = set()
        for key, fl in self.flows.items():
            if len(key) != 5:
                continue
            # Our own diagnostic scan probes odd/high ports across the subnet;
            # a hit on 4444/1337/etc from the scanner is authorized recon, not a
            # backdoor. Skip flows the scan host initiated. A real device
            # touching these ports still fires.
            if self.known_scanner_ip and fl.get('client_ip') == self.known_scanner_ip:
                continue
            for port in (key[2], key[3]):
                if port in SUSPICIOUS_PORTS and port not in seen:
                    seen.add(port)
                    self.anomalies.append({
                        'severity': 'high', 'category': 'suspicious_port',
                        'description': f'Traffic on suspicious port {port} ({SUSPICIOUS_PORTS[port]}): {key[0]} ↔ {key[1]}',
                    })
                    self.iocs.append({'type': 'suspicious_port', 'value': f'{port} ({SUSPICIOUS_PORTS[port]})'})

    def _detect_cleartext(self):
        # Deduplicate by destination host — one alert per host, not per request
        seen_hosts: set = set()
        for req in self.http_requests:
            if req.get('method') == 'POST':
                host = req.get('host') or req.get('dst_ip', '?')
                if host not in seen_hosts:
                    seen_hosts.add(host)
                    self.anomalies.append({
                        'severity': 'medium', 'category': 'cleartext',
                        'description': f'HTTP POST (cleartext) to {host} from {req.get("src_ip","")}',
                    })
        ftp  = sum(1 for k in self.flows if len(k) == 5 and (k[2] in (20, 21) or k[3] in (20, 21)))
        tel  = sum(1 for k in self.flows if len(k) == 5 and (k[2] == 23 or k[3] == 23))
        ldap = sum(1 for k in self.flows if len(k) == 5 and (k[2] == 389 or k[3] == 389))
        imap = sum(1 for k in self.flows if len(k) == 5 and (k[2] == 143 or k[3] == 143))
        pop3 = sum(1 for k in self.flows if len(k) == 5 and (k[2] == 110 or k[3] == 110))
        snmp = sum(1 for k in self.flows if len(k) == 5 and (k[2] == 161 or k[3] == 161))
        if ftp:
            self.anomalies.append({'severity': 'high', 'category': 'cleartext',
                                   'description': f'FTP traffic detected ({ftp} flows) — credentials in cleartext'})
        if tel:
            self.anomalies.append({'severity': 'high', 'category': 'cleartext',
                                   'description': f'Telnet traffic detected ({tel} flows) — all data in cleartext'})
        if ldap:
            self.anomalies.append({'severity': 'high', 'category': 'cleartext',
                                   'description': f'Cleartext LDAP detected ({ldap} flows) — directory queries and credentials unencrypted'})
        if imap:
            self.anomalies.append({'severity': 'medium', 'category': 'cleartext',
                                   'description': f'Cleartext IMAP detected ({imap} flows) — email credentials exposed without STARTTLS'})
        if pop3:
            self.anomalies.append({'severity': 'medium', 'category': 'cleartext',
                                   'description': f'Cleartext POP3 detected ({pop3} flows) — email credentials exposed without STARTTLS'})
        if snmp:
            self.anomalies.append({'severity': 'medium', 'category': 'cleartext',
                                   'description': f'SNMP traffic detected ({snmp} flows) — community strings (passwords) transmitted in cleartext'})

    def _detect_tls_issues(self):
        # hs['deprecated'] is set only for a ServerHello whose *negotiated*
        # version is TLS 1.1 / 1.0 / SSL — i.e. what the two ends actually
        # agreed to use, not the legacy handshake byte.
        seen_versions = set()
        for hs in self.tls_handshakes:
            v = hs.get('version_num', 0)
            if hs.get('deprecated') and v not in seen_versions:
                seen_versions.add(v)
                self.anomalies.append({
                    'severity': 'medium', 'category': 'tls',
                    'description': (f'Deprecated TLS version negotiated: {hs.get("version","?")} '
                                    f'with server {hs.get("dst_ip","")}'),
                })

    def _detect_smb_lateral(self):
        """One internal host contacting many others over SMB = ransomware / worm spreading."""
        # Threshold of 10 (was 5): in a managed small network a backup agent,
        # RMM tool, NAS, or file server legitimately touches many hosts over
        # SMB. A real worm fans out to nearly every reachable host, so 10 still
        # catches aggressive spread while sparing routine 5–8 target fan-out.
        for src, targets in self.smb_targets.items():
            if src == self.known_scanner_ip:
                continue
            internal_targets = {t for t in targets if is_private(t) and t != src}
            if len(internal_targets) >= 10:
                sample = ', '.join(sorted(internal_targets)[:3])
                suffix = '…' if len(internal_targets) > 3 else ''
                self.anomalies.append({
                    'severity': 'high', 'category': 'smb_lateral',
                    'description': (
                        f'SMB fan-out: {src} connected to {len(internal_targets)} '
                        f'internal hosts on port 445 ({sample}{suffix}). '
                        f'This can be ransomware/worm spread — but first confirm it is not '
                        f'your backup, RMM, or file server, which do this legitimately.'
                    ),
                    'source': src,
                })
                self.iocs.append({'type': 'smb_spreader', 'value': src})

    def _detect_dhcp_rogue(self):
        """More than one IP handing out DHCP leases = rogue server / gateway hijack."""
        if len(self.dhcp_server_ips) > 1:
            ips = ', '.join(sorted(self.dhcp_server_ips))
            self.anomalies.append({
                'severity': 'critical', 'category': 'dhcp_rogue',
                'description': (
                    f'Rogue DHCP server detected: {len(self.dhcp_server_ips)} IPs are handing '
                    f'out leases ({ips}). An attacker-controlled DHCP server can redirect all '
                    f'traffic through a malicious gateway and intercept credentials.'
                ),
            })
            self.iocs.append({'type': 'rogue_dhcp', 'value': ips})

    def _detect_llmnr_poisoning(self):
        """Single IP answering many LLMNR/NBT-NS queries = Responder/Inveigh credential harvesting."""
        _THRESHOLD = 20  # a legitimate host rarely sends more than a handful of LLMNR responses
        for src, count in self.llmnr_responses.items():
            if count >= _THRESHOLD:
                self.anomalies.append({
                    'severity': 'high', 'category': 'llmnr_poisoning',
                    'description': (
                        f'LLMNR/NBT-NS poisoning suspected: {src} sent {count} LLMNR/NBT-NS '
                        f'responses — far more than any legitimate host would generate. '
                        f'Consistent with Responder or Inveigh harvesting NetNTLM hashes.'
                    ),
                    'source': src,
                })

    def _detect_ntp_amplification(self):
        """Internal host sending large volumes of NTP responses = DDoS reflector."""
        _THRESHOLD = 5_000_000  # 5 MB — routers legitimately serve NTP to all LAN clients
        for src, total in self.ntp_resp_bytes.items():
            if total > _THRESHOLD:
                self.anomalies.append({
                    'severity': 'medium', 'category': 'ntp_amplification',
                    'description': (
                        f'{src} sent {total:,} bytes of NTP responses — possible NTP monlist '
                        f'amplification reflector. Device may be participating in a DDoS attack '
                        f'against an external target.'
                    ),
                    'source': src,
                })

    def _detect_icmp_tunneling(self):
        """Repeated oversized ICMP payloads = data hidden inside ping packets."""
        by_src: dict = defaultdict(lambda: {'count': 0, 'max_len': 0})
        for entry in self.icmp_large:
            rec = by_src[entry['src_ip']]
            rec['count']   += 1
            rec['max_len']  = max(rec['max_len'], entry['payload_len'])
        for src, stats in by_src.items():
            if stats['count'] >= 10:
                self.anomalies.append({
                    'severity': 'high', 'category': 'icmp_tunnel',
                    'description': (
                        f'ICMP tunneling suspected from {src}: {stats["count"]} packets with '
                        f'oversized payloads (largest: {stats["max_len"]} bytes). '
                        f'Normal ICMP echo payloads are 32–56 bytes. '
                        f'Data may be exfiltrated or C2 traffic hidden inside ICMP.'
                    ),
                    'source': src,
                })
                self.iocs.append({'type': 'icmp_tunnel_src', 'value': src})

    def _detect_dns_rebinding(self):
        """External domain resolves to private IP with tiny TTL = DNS rebinding attack."""
        seen: set = set()
        for hit in self.dns_rebind_hits:
            key = (hit['domain'], hit['resolved_ip'])
            if key not in seen:
                seen.add(key)
                self.anomalies.append({
                    'severity': 'critical', 'category': 'dns_rebind',
                    'description': (
                        f'DNS rebinding: "{hit["domain"]}" resolved to internal IP '
                        f'{hit["resolved_ip"]} with TTL={hit["ttl"]}s. '
                        f'Attacker may be bypassing same-origin policy to reach internal '
                        f'services (routers, cameras, NAS) from a malicious webpage.'
                    ),
                    'source': hit['querier'],
                })
                self.iocs.append({'type': 'dns_rebind_domain', 'value': hit['domain']})

    @staticmethod
    def _is_dga(domain: str) -> bool:
        """Heuristic DGA detector on the registered (second-level) domain label.

        Real DGA domains are a single unpronounceable token that someone
        registered (e.g. 'kq3vzjxwbf.com'). We inspect the second-level label
        — NOT the leftmost subdomain, which for CDNs and SaaS is a long but
        perfectly legitimate service tag (e.g. '0-prod-dynamite-…-signaler-pa'
        under google.com). We also require BOTH high consonant density AND
        high entropy before firing; either one alone flags too many real
        service names. Hyphenated or digit-laced labels are human-composed
        (e.g. 'itunes-apple', 'assets-proxy') and are excluded outright.
        """
        labels = domain.split('.')
        sld = labels[-2] if len(labels) >= 2 else labels[0]
        # Hyphens/underscores mark human-composed names, not DGA output
        if '-' in sld or '_' in sld:
            return False
        # Score letters only; punctuation/digits should not inflate the ratio
        letters = [c for c in sld if c.isalpha()]
        if len(letters) < 12:
            return False
        vowels = sum(1 for c in letters if c in 'aeiou')
        consonant_ratio = 1 - (vowels / len(letters))
        entropy = TrafficAnalyzer._shannon_entropy(sld)
        return consonant_ratio > 0.70 and entropy > 3.6

    def _detect_c2_domains(self):
        """DNS queries to known C2 / dynamic-DNS infrastructure or DGA-generated domains."""
        seen: set = set()
        for hit in self.c2_domain_hits:
            key = (hit['domain'], hit['querier'])
            if key not in seen:
                seen.add(key)
                label = 'Tor network' if hit['type'] == 'tor' else f'dynamic DNS C2 provider ({hit["indicator"]})'
                self.anomalies.append({
                    'severity': 'high', 'category': 'c2_domain',
                    'description': (
                        f'{hit["querier"]} queried "{hit["domain"]}" — matches known {label}. '
                        f'This domain is frequently used by malware for command-and-control. '
                        f'Isolate the device and run a full malware scan.'
                    ),
                    'source': hit['querier'],
                })
                self.iocs.append({'type': 'c2_domain', 'value': hit['domain']})

        # DGA detection: flag high-entropy or consonant-heavy SLDs
        seen_dga: set = set()
        for q in self.dns_queries:
            domain = q.get('name', '').lower().rstrip('.')
            if not domain or domain in seen_dga:
                continue
            apex = '.'.join(domain.split('.')[-2:]) if '.' in domain else domain
            if apex in _DNS_TUNNEL_WHITELIST:
                continue
            if self._is_dga(domain):
                seen_dga.add(domain)
                self.anomalies.append({
                    'severity': 'high', 'category': 'c2_domain',
                    'description': (
                        f'{q.get("src_ip", "?")} queried "{domain}" — domain matches DGA '
                        f'(Domain Generation Algorithm) patterns: high consonant density or '
                        f'entropy typical of Emotet, Mirai, or similar malware families.'
                    ),
                    'source': q.get('src_ip', ''),
                })
                self.iocs.append({'type': 'dga_domain', 'value': domain})

    def _compile_results(self) -> Dict:
        ts = self.timestamps
        duration = (max(ts) - min(ts)) if len(ts) > 1 else 0

        # deduplicate anomalies
        seen, unique = set(), []
        for a in self.anomalies:
            d = a.get('description', '')
            if d not in seen:
                seen.add(d); unique.append(a)

        # NOTE: scoring lives in parser._score (type-weighted, dedup-by-type).
        # The engine only surfaces raw anomalies; it does not score them.

        return {
            'total_packets':   self.total_packets,
            'total_bytes':     self.total_bytes,
            'duration':        duration,
            'unique_ips':      list(self.unique_ips),
            'internal_ips':    list(self.internal_ips),
            'external_ips':    list(self.external_ips),
            'arp_table':       {k: list(v) for k, v in self.arp_table.items()},
            'ip_bytes_sent':   dict(self.ip_bytes_sent),
            'ip_bytes_recv':   dict(self.ip_bytes_recv),
            'ip_pkts_sent':    dict(self.ip_pkts_sent),
            'ip_pkts_recv':    dict(self.ip_pkts_recv),
            'port_counter':    dict(self.port_counter.most_common(20)),
            'protocol_counter': dict(self.protocol_counter),
            'dns_queries':     self.dns_queries,
            'dns_failures':    self.dns_failures,
            'http_requests':   self.http_requests,
            'tls_handshakes':  self.tls_handshakes,
            'user_agents':     dict(self.user_agents.most_common(10)),
            'anomalies':       unique,
            'iocs':            self.iocs,
        }
