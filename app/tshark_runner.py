import subprocess
import json


def run_tshark_json(pcap_path: str) -> list[dict]:
    """Run tshark on a pcap/pcapng file and return the full parsed packet list."""
    cmd = [
        "tshark",
        "-r", pcap_path,
        "-T", "json",
        "--no-duplicate-keys",
        "-N", "mnd",  # m=MAC  n=network(IP)  d=DHCP/mDNS hostnames from packets
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    if result.returncode != 0:
        raise RuntimeError(f"tshark error: {result.stderr.strip()}")
    return json.loads(result.stdout)
