"""Active network discovery via Angry IP Scanner (macOS).

Angry IP 3.x on macOS is SWT/GUI-bound and cannot run truly headless — even
its command-line mode instantiates the GUI on the Cocoa main thread. We
therefore launch it in GUI mode with ``-XstartOnFirstThread`` plus its
scan+export flags (``-f:range … -s -o file -q``). A window briefly appears
and closes on its own.

IMPORTANT: this REQUIRES the backend to run inside the logged-in user's GUI
session. Launched as a launchd daemon or over SSH there is no display and the
scan will fail (SWT "Invalid thread access"). That is a property of Angry IP
on macOS, not of this wrapper.

The launcher script inside the .app does NOT forward CLI args, so we invoke
the bundled Java directly. Output is Angry IP's CSV export, fed straight to
the existing ``parse_angry_ip_csv``.
"""
import os
import re
import glob
import ipaddress
import subprocess
import tempfile
from typing import List, Optional, Tuple

from app.csv_parser import parse_angry_ip_csv

# Locate the app bundle; override with the IPSCAN_APP env var. (It currently
# lives in ~/Downloads on this machine, hence the non-standard candidate.)
_APP_CANDIDATES = (
    os.environ.get("IPSCAN_APP", ""),
    "/Applications/Angry IP Scanner.app",
    os.path.expanduser("~/Applications/Angry IP Scanner.app"),
    os.path.expanduser("~/Downloads/Angry IP Scanner.app"),
)


class ScanError(RuntimeError):
    pass


def _find_app() -> str:
    for c in _APP_CANDIDATES:
        if c and os.path.isdir(c):
            return c
    raise ScanError("Angry IP Scanner.app not found — set the IPSCAN_APP env var.")


def _java_and_jar() -> Tuple[str, str]:
    app = _find_app()
    java = os.path.join(app, "Contents/MacOS/jre/bin/java")
    if not os.access(java, os.X_OK):
        java = "java"  # fall back to a system JRE
    jars = glob.glob(os.path.join(app, "Contents/MacOS/ipscan*.jar"))
    if not jars:
        raise ScanError("ipscan jar not found inside the app bundle.")
    return java, jars[0]


def _iface_ipv4(iface: str) -> Optional[Tuple[str, int]]:
    """Return (ip, netmask_int) for an interface via ifconfig, or None."""
    out = subprocess.run(["ifconfig", iface], capture_output=True, text=True, timeout=5).stdout
    m = re.search(r"inet (\d+\.\d+\.\d+\.\d+) netmask (0x[0-9a-fA-F]+)", out)
    if not m:
        return None
    return m.group(1), int(m.group(2), 16)


def local_range(iface: str) -> Tuple[str, str]:
    """Compute the (first_host, last_host) IPv4 range for an interface's subnet."""
    info = _iface_ipv4(iface)
    if not info:
        raise ScanError(f"No IPv4 address on interface {iface}.")
    ip, mask_int = info
    prefix = bin(mask_int).count("1")
    net = ipaddress.ip_network(f"{ip}/{prefix}", strict=False)
    hosts = list(net.hosts())
    return (str(hosts[0]), str(hosts[-1])) if hosts else (ip, ip)


def run_scan(iface: str = "en0", timeout: int = 180,
             range_override: Optional[Tuple[str, str]] = None) -> List[dict]:
    """Scan the interface's local subnet with Angry IP; return scan_devices.

    range_override lets callers scan a specific (start, end) range instead of
    the whole subnet — handy for testing and for targeted rescans.
    """
    java, jar = _java_and_jar()
    start, end = range_override or local_range(iface)

    fd, out_csv = tempfile.mkstemp(suffix=".csv", prefix="ipscan_")
    os.close(fd)
    os.unlink(out_csv)  # let ipscan create the file itself

    cmd = [java, "--add-opens", "java.base/java.net=ALL-UNNAMED",
           "-XstartOnFirstThread", "-jar", jar,
           "-f:range", start, end, "-s", "-o", out_csv, "-q"]
    try:
        subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        raise ScanError(f"Angry IP scan exceeded {timeout}s.")

    if not os.path.exists(out_csv):
        raise ScanError(
            "Angry IP produced no output — is the backend running in a GUI "
            "session? (No display => SWT cannot start.)"
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
        app = _find_app()
        java, jar = _java_and_jar()
        return {"available": True, "app": app, "java": java, "jar": os.path.basename(jar)}
    except ScanError as e:
        return {"available": False, "error": str(e)}
