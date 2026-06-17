import subprocess
import json
import tempfile
import os
from pathlib import Path


TSHARK_FIELDS = [
    "-e", "frame.number",
    "-e", "frame.time_epoch",
    "-e", "frame.len",
    "-e", "ip.src",
    "-e", "ip.dst",
    "-e", "ip.proto",
    "-e", "tcp.srcport",
    "-e", "tcp.dstport",
    "-e", "udp.srcport",
    "-e", "udp.dstport",
    "-e", "dns.qry.name",
    "-e", "dns.flags.rcode",
    "-e", "tcp.analysis.retransmission",
    "-e", "eth.src",
    "-e", "eth.dst",
    "-e", "_ws.col.Protocol",
]

def run_tshark_json(pcap_path: str) -> list[dict]:
    cmd = [
        "tshark",
        "-r", pcap_path,
        "-T", "json",
        "--no-duplicate-keys",
        "-N", "m",  # resolve mDNS hostnames
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    if result.returncode != 0:
        raise RuntimeError(f"tshark error: {result.stderr.strip()}")
    return json.loads(result.stdout)

def run_tshark_json(pcap_path: str) -> list[dict]:
    """Run tshark on a pcap file and return parsed packet list."""
    cmd = [
        "tshark",
        "-r", pcap_path,
        "-T", "json",
        "--no-duplicate-keys",
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    if result.returncode != 0:
        raise RuntimeError(f"tshark error: {result.stderr.strip()}")
    return json.loads(result.stdout)


def run_tshark_fields(pcap_path: str) -> list[dict]:
    """
    Run tshark with specific fields for faster, leaner extraction.
    Falls back to full JSON parse if field mode fails.
    """
    cmd = [
        "tshark",
        "-r", pcap_path,
        "-T", "fields",
        "-E", "header=y",
        "-E", "separator=,",
        "-E", "quote=d",
        "-E", "occurrence=f",
    ] + TSHARK_FIELDS

    result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    if result.returncode != 0:
        raise RuntimeError(f"tshark error: {result.stderr.strip()}")

    lines = result.stdout.strip().splitlines()
    if not lines:
        return []

    headers = lines[0].split(",")
    # strip quotes from headers
    headers = [h.strip('"') for h in headers]

    packets = []
    for line in lines[1:]:
        # simple CSV split -- handles quoted fields
        import csv
        row = next(csv.reader([line]))
        pkt = dict(zip(headers, row))
        packets.append(pkt)

    return packets
