"""Live packet capture via Wireshark's ``dumpcap`` (macOS-first).

We shell out to the installed ``dumpcap`` binary rather than embedding
Wireshark: dumpcap is battle-tested, supports duration and size limits
natively, and — with Wireshark's ChmodBPF / ``access_bpf`` group — captures
WITHOUT sudo. The resulting ``.pcap`` feeds the existing ``parse_pcap_file``.

Nothing here parses packets; it only acquires the capture file.
"""
import os
import re
import shutil
import subprocess
from typing import Optional, List, Dict

# dumpcap lookup order: PATH first, then the usual macOS install locations.
_DUMPCAP_CANDIDATES = (
    "dumpcap",
    "/opt/homebrew/bin/dumpcap",
    "/usr/local/bin/dumpcap",
    "/Applications/Wireshark.app/Contents/MacOS/dumpcap",
)


class CaptureError(RuntimeError):
    pass


def find_dumpcap() -> Optional[str]:
    """Return an executable dumpcap path, or None if not installed."""
    for c in _DUMPCAP_CANDIDATES:
        if "/" in c:
            if os.access(c, os.X_OK):
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


def default_interface() -> Optional[str]:
    """The interface carrying the default route — what we want to capture."""
    try:
        out = subprocess.run(["route", "-n", "get", "default"],
                             capture_output=True, text=True, timeout=5).stdout
        m = re.search(r"interface:\s*(\S+)", out)
        if m:
            return m.group(1)
    except Exception:
        pass
    # Fallback: first non-loopback interface dumpcap reports.
    for i in list_interfaces():
        if not i["name"].startswith(("lo", "utun", "awdl", "llw")):
            return i["name"]
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
