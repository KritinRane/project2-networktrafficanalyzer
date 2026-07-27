"""Active network discovery via Angry IP Scanner (macOS + Windows).

Angry IP 3.x on **macOS** is SWT/GUI-bound and cannot run truly headless — even
its command-line mode instantiates the GUI on the Cocoa main thread. We
therefore launch it in GUI mode with ``-XstartOnFirstThread`` plus its
scan+export flags (``-f:range … -s -o file -q``). A window briefly appears
and closes on its own. The launcher script inside the .app does NOT forward CLI
args, so we invoke the bundled Java directly.

On **Windows** we run ``ipscan.exe`` directly with the same scan/export flags
(no ``-XstartOnFirstThread`` — that switch is macOS-only). Angry IP still opens
its window briefly, so the backend must run inside an interactive desktop
session. MAC-address/vendor columns additionally need Npcap/WinPcap installed.

IMPORTANT: on either OS the backend must run inside the logged-in user's GUI
session. Launched as a service / over SSH there is no display and the scan will
fail. That is a property of Angry IP, not of this wrapper.

Output is Angry IP's CSV export, fed straight to ``parse_angry_ip_csv``.
"""
import os
import re
import glob
import socket
import subprocess
import sys
import tempfile
import ipaddress
from typing import List, Optional, Tuple

from app.csv_parser import parse_angry_ip_csv

_IS_WINDOWS = sys.platform == "win32"

# macOS: locate the .app bundle. Override with the IPSCAN_APP env var.
_MAC_APP_CANDIDATES = (
    os.environ.get("IPSCAN_APP", ""),
    "/Applications/Angry IP Scanner.app",
    os.path.expanduser("~/Applications/Angry IP Scanner.app"),
    os.path.expanduser("~/Downloads/Angry IP Scanner.app"),
)

# Windows: locate ipscan.exe. Override with IPSCAN_APP (point it at the .exe).
_WIN_EXE_CANDIDATES = (
    os.environ.get("IPSCAN_APP", ""),
    r"C:\Program Files\Angry IP Scanner\ipscan.exe",
    r"C:\Program Files (x86)\Angry IP Scanner\ipscan.exe",
)


class ScanError(RuntimeError):
    pass


# ── Locating the scanner ────────────────────────────────────────────────────

def _find_app() -> str:
    """macOS: return the Angry IP Scanner.app bundle path."""
    for c in _MAC_APP_CANDIDATES:
        if c and os.path.isdir(c):
            return c
    raise ScanError("Angry IP Scanner.app not found — set the IPSCAN_APP env var.")


def _find_windows_exe() -> str:
    """Windows: return the ipscan.exe path."""
    for c in _WIN_EXE_CANDIDATES:
        if c and os.path.isfile(c):
            return c
    from shutil import which
    p = which("ipscan")
    if p:
        return p
    raise ScanError(
        "Angry IP Scanner (ipscan.exe) not found — install it, or set the "
        "IPSCAN_APP env var to the full path of ipscan.exe."
    )


def _java_and_jar() -> Tuple[str, str]:
    """macOS: the bundled JRE and ipscan jar inside the .app."""
    app = _find_app()
    java = os.path.join(app, "Contents/MacOS/jre/bin/java")
    if not os.access(java, os.X_OK):
        java = "java"  # fall back to a system JRE
    jars = glob.glob(os.path.join(app, "Contents/MacOS/ipscan*.jar"))
    if not jars:
        raise ScanError("ipscan jar not found inside the app bundle.")
    return java, jars[0]


# ── Local IP / subnet detection ─────────────────────────────────────────────

def _primary_ipv4() -> Optional[str]:
    """This machine's primary outbound IPv4, cross-platform.

    Opens a UDP socket toward a public address — no packets are actually sent
    for UDP ``connect`` — and reads back the local address the OS would use.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except Exception:
        return None
    finally:
        s.close()


def _iface_ipv4(iface: str) -> Optional[Tuple[str, int]]:
    """macOS/BSD: return (ip, netmask_int) for an interface via ifconfig."""
    out = subprocess.run(["ifconfig", iface], capture_output=True, text=True, timeout=5).stdout
    m = re.search(r"inet (\d+\.\d+\.\d+\.\d+) netmask (0x[0-9a-fA-F]+)", out)
    if not m:
        return None
    return m.group(1), int(m.group(2), 16)


def local_ip(iface: str) -> Optional[str]:
    """Return this machine's own IPv4 address, for scanner-IP exclusion."""
    if not _IS_WINDOWS:
        info = _iface_ipv4(iface)
        if info:
            return info[0]
    return _primary_ipv4()


def local_range(iface: str) -> Tuple[str, str]:
    """Compute the (first_host, last_host) IPv4 range to scan.

    macOS/BSD derives the exact subnet from the interface netmask. On Windows
    (and as a universal fallback) we take the machine's primary IPv4 and assume
    a /24 — by far the most common layout on the small/home networks this tool
    targets. Override the range explicitly if a site uses something wider.
    """
    if not _IS_WINDOWS:
        info = _iface_ipv4(iface)
        if info:
            ip, mask_int = info
            prefix = bin(mask_int).count("1")
            net = ipaddress.ip_network(f"{ip}/{prefix}", strict=False)
            hosts = list(net.hosts())
            return (str(hosts[0]), str(hosts[-1])) if hosts else (ip, ip)

    ip = _primary_ipv4()
    if not ip:
        raise ScanError("Could not determine this machine's local IP to scan.")
    net = ipaddress.ip_network(f"{ip}/24", strict=False)
    hosts = list(net.hosts())
    return (str(hosts[0]), str(hosts[-1])) if hosts else (ip, ip)


# ── Running the scan ────────────────────────────────────────────────────────

def _scan_command(start: str, end: str, out_csv: str) -> list:
    """Build the platform-specific Angry IP command line."""
    common = ["-f:range", start, end, "-s", "-o", out_csv, "-q"]
    if _IS_WINDOWS:
        return [_find_windows_exe()] + common
    java, jar = _java_and_jar()
    # -XstartOnFirstThread is REQUIRED on macOS (Cocoa main thread) and must
    # NOT appear on any other platform.
    return [java, "--add-opens", "java.base/java.net=ALL-UNNAMED",
            "-XstartOnFirstThread", "-jar", jar] + common


def run_scan(iface: str = "en0", timeout: int = 180,
             range_override: Optional[Tuple[str, str]] = None) -> List[dict]:
    """Scan the local subnet with Angry IP; return scan_devices.

    range_override lets callers scan a specific (start, end) range instead of
    the whole subnet — handy for testing and for targeted rescans.
    """
    start, end = range_override or local_range(iface)

    fd, out_csv = tempfile.mkstemp(suffix=".csv", prefix="ipscan_")
    os.close(fd)
    os.unlink(out_csv)  # let ipscan create the file itself
    cmd = _scan_command(start, end, out_csv)

    try:
        subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        raise ScanError(f"Angry IP scan exceeded {timeout}s.")

    if not os.path.exists(out_csv):
        raise ScanError(
            "Angry IP produced no output — is the backend running in an "
            "interactive desktop session? (No display => the scanner window "
            "cannot start.)"
        )
    try:
        with open(out_csv, "rb") as f:
            return parse_angry_ip_csv(f.read())
    finally:
        if os.path.exists(out_csv):
            os.unlink(out_csv)


def probe() -> dict:
    """Preflight for the UI / job layer: is Angry IP locatable and runnable?"""
    try:
        if _IS_WINDOWS:
            exe = _find_windows_exe()
            return {"available": True, "exe": exe}
        app = _find_app()
        java, jar = _java_and_jar()
        return {"available": True, "app": app, "java": java, "jar": os.path.basename(jar)}
    except ScanError as e:
        return {"available": False, "error": str(e)}
