"""Live packet capture via Wireshark's ``dumpcap`` (macOS + Windows).

We shell out to the installed ``dumpcap`` binary rather than embedding
Wireshark: dumpcap is battle-tested, supports duration and size limits
natively, and — with Wireshark's ChmodBPF / ``access_bpf`` group — captures
WITHOUT sudo. The resulting ``.pcap`` feeds the existing ``parse_pcap_file``.

On Windows, capture needs Npcap installed (bundled with the Wireshark
installer) and the backend usually has to run as Administrator. Point the
``DUMPCAP`` env var at ``dumpcap.exe`` if Wireshark isn't on the PATH.

Nothing here parses packets; it only acquires the capture file.
"""
import os
import re
import shutil
import subprocess
import sys
from typing import Optional, List, Dict


def _dumpcap_candidates() -> List[str]:
    """dumpcap lookup order: explicit DUMPCAP override, PATH, then the usual
    per-OS install locations."""
    cands: List[str] = []
    env = os.environ.get("DUMPCAP", "").strip()
    if env:
        cands.append(env)
    cands.append("dumpcap")  # resolved via PATH
    if sys.platform == "win32":
        cands += [
            r"C:\Program Files\Wireshark\dumpcap.exe",
            r"C:\Program Files (x86)\Wireshark\dumpcap.exe",
        ]
    else:
        cands += [
            "/opt/homebrew/bin/dumpcap",
            "/usr/local/bin/dumpcap",
            "/Applications/Wireshark.app/Contents/MacOS/dumpcap",
        ]
    return cands


class CaptureError(RuntimeError):
    pass


def find_dumpcap() -> Optional[str]:
    """Return an executable dumpcap path, or None if not installed."""
    for c in _dumpcap_candidates():
        looks_like_path = ("/" in c) or ("\\" in c)
        if looks_like_path:
            if os.path.isfile(c) and os.access(c, os.X_OK):
                return c
        else:
            p = shutil.which(c)
            if p:
                return p
    return None


def _dumpcap() -> str:
    p = find_dumpcap()
    if not p:
        raise CaptureError("dumpcap not found — install Wireshark.")
    return p


def list_interfaces() -> List[Dict[str, str]]:
    """Parse ``dumpcap -D`` into [{'id','name','description'}]."""
    out = subprocess.run([_dumpcap(), "-D"], capture_output=True, text=True, timeout=15)
    ifaces = []
    for line in out.stdout.splitlines():
        # e.g. "1. en0 (Wi-Fi)"  or  "3. utun0"
        m = re.match(r"\s*(\d+)\.\s+(\S+)(?:\s+\((.*)\))?", line)
        if m:
            ifaces.append({"id": m.group(1), "name": m.group(2),
                           "description": (m.group(3) or "").strip()})
    return ifaces


# Interface descriptions (from ``dumpcap -D``) that are virtual/loopback and
# should never be the auto-picked default. Matched case-insensitively.
_SKIP_IFACE_DESC = (
    "loopback", "virtual", "vmware", "virtualbox", "hyper-v", "vpn",
    "bluetooth", "wan miniport", "tunneling", "npcap loopback",
)


def default_interface() -> Optional[str]:
    """The interface carrying the default route — what we want to capture."""
    # macOS/BSD: ask the routing table directly (most reliable).
    if sys.platform == "darwin":
        try:
            out = subprocess.run(["route", "-n", "get", "default"],
                                 capture_output=True, text=True, timeout=5).stdout
            m = re.search(r"interface:\s*(\S+)", out)
            if m:
                return m.group(1)
        except Exception:
            pass
    # Cross-platform fallback (and Windows default): first "real" interface
    # dumpcap reports, skipping loopback/virtual adapters. On Windows names look
    # like ``\Device\NPF_{GUID}`` with a human description in parentheses.
    for i in list_interfaces():
        name = i["name"]
        desc = (i.get("description") or "").lower()
        if name.startswith(("lo", "utun", "awdl", "llw")):
            continue
        if any(x in desc for x in _SKIP_IFACE_DESC):
            continue
        return name
    return None


def start_capture(out_path: str, iface: Optional[str] = None,
                  duration: int = 300, max_size_kb: int = 200_000,
                  cfilter: str = "") -> subprocess.Popen:
    """Start a NON-blocking dumpcap capture; return the Popen handle.

    duration     stop after N seconds (``-a duration:N``).
    max_size_kb  also stop at this many KB, whichever comes first
                 (``-a filesize:N``). A 5-minute capture on a busy LAN can be
                 hundreds of MB, so this bounds disk/RAM to keep the parser
                 sane. Single output file (no ring buffer) so it feeds
                 parse_pcap_file directly.
    cfilter      optional BPF capture filter (e.g. exclude your own mgmt IP).
    """
    iface = iface or default_interface()
    if not iface:
        raise CaptureError("No capture interface found.")
    cmd = [_dumpcap(), "-i", iface, "-a", f"duration:{duration}",
           "-a", f"filesize:{max_size_kb}", "-w", out_path]
    if cfilter:
        cmd += ["-f", cfilter]
    return subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)


def run_capture(out_path: str, iface: Optional[str] = None,
                duration: int = 300, **kw) -> str:
    """Blocking convenience wrapper: capture, wait, return out_path."""
    proc = start_capture(out_path, iface=iface, duration=duration, **kw)
    _, err = proc.communicate(timeout=duration + 30)
    if proc.returncode not in (0, None) and not os.path.exists(out_path):
        raise CaptureError(f"dumpcap failed: {(err or b'').decode(errors='replace')[:300]}")
    return out_path


def probe() -> Dict:
    """Preflight for the UI / job layer: is capture usable, and on what iface?"""
    path = find_dumpcap()
    info: Dict = {"dumpcap": path, "available": bool(path)}
    if path:
        try:
            info["default_interface"] = default_interface()
            info["interfaces"] = list_interfaces()
        except Exception as e:  # pragma: no cover - environment dependent
            info["error"] = str(e)
    return info
