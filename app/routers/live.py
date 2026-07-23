"""Automated live capture + scan, run as a background job.

Flow after login:
  POST /api/live/start          -> kicks off a job, returns {job_id}
      * starts a 5-min dumpcap capture (non-blocking subprocess)
      * runs an Angry IP subnet scan concurrently (~seconds)
  GET  /api/live/{job_id}/status -> poll; scan result appears in ~seconds,
                                    full analysis when the capture finishes.

Capture and scan feed the SAME analysis pipeline the upload path uses
(parse_pcap_file + merger + _score), so results are identical in shape.

Jobs are held in memory — fine for the single-user local/appliance model
this is designed for. They do not survive a backend restart.
"""
import asyncio
import os
import tempfile
import time
import uuid

from fastapi import APIRouter, HTTPException

from app import capture, scanner
from app.parser import parse_pcap_file, _score
from app.merger import (
    detect_ghost_devices,
    detect_hostname_spoofing,
    detect_shadow_infrastructure,
)
from app.summarizer import generate_customer_summary

router = APIRouter()

# The subnet scan runs concurrently with the capture and gets its own budget —
# it is independent of how long the capture runs (a 5-min capture and a short
# capture both allow the scan the same time to finish).
_SCAN_TIMEOUT = 180

# job_id -> dict(status, iface, scan, analysis, ...)
JOBS: dict = {}


def _finalize(pcap_path: str, scan_devices: list, known_scanner_ip: str = None) -> dict:
    """Run the shared analysis pipeline (mirrors /api/analyze)."""
    has_scan = bool(scan_devices)
    analysis = parse_pcap_file(pcap_path, scan_devices if has_scan else None,
                                known_scanner_ip=known_scanner_ip)

    if has_scan:
        mismatch = (
            detect_ghost_devices(analysis['devices'])
            + detect_hostname_spoofing(analysis['devices'])
            + detect_shadow_infrastructure(analysis['devices'])
        )
        for d in analysis['devices']:
            d.pop('_scan_hostname', None)
            d.pop('_pcap_hostname', None)
        analysis['alerts'] = mismatch + analysis.get('alerts', [])
        analysis['scan_device_count'] = len(scan_devices)
        analysis['scan_active_count'] = sum(1 for d in scan_devices if d.get('responded'))
        ts, rl = _score(analysis['alerts'])
        analysis['summary']['threat_score'] = ts
        analysis['summary']['risk_level'] = rl
        analysis['summary']['alert_count'] = len(analysis['alerts'])
    else:
        for d in analysis['devices']:
            d.pop('_scan_hostname', None)
            d.pop('_pcap_hostname', None)
        analysis['scan_device_count'] = 0
        analysis['scan_active_count'] = 0

    analysis['has_scan_data'] = has_scan
    analysis['customer_summary'] = generate_customer_summary(analysis)
    return analysis


async def _run_live(job_id: str, iface: str, duration: int):
    job = JOBS[job_id]
    pcap = os.path.join(tempfile.gettempdir(), f"live_{job_id}.pcap")

    try:
        proc = capture.start_capture(pcap, iface=iface, duration=duration)
    except Exception as e:
        job.update(status='error', error=f'capture failed to start: {e}')
        return
    job.update(status='capturing', capture_ends_at=time.time() + duration)

    # Scan runs concurrently. It's blocking (spawns Angry IP), so off-thread.
    try:
        scan_devices = await asyncio.to_thread(scanner.run_scan, iface, _SCAN_TIMEOUT)
        job['scan'] = scan_devices
        job['scan_device_count'] = len(scan_devices)
        if job['status'] == 'capturing':
            job['status'] = 'scan_ready'
    except Exception as e:
        job['scan_error'] = str(e)
        scan_devices = []

    # Await the capture without blocking the event loop.
    while proc.poll() is None:
        await asyncio.sleep(1)

    if not os.path.exists(pcap) or os.path.getsize(pcap) == 0:
        job.update(status='error', error='capture produced no data')
        return

    job['status'] = 'analyzing'
    try:
        # We ran the Angry IP scan from THIS machine — its own scan traffic
        # (SMB/NetBIOS probes, wide port checks) would otherwise look like
        # an attacker to smb_lateral/port_scan. Exclude it by IP.
        known_scanner_ip = await asyncio.to_thread(scanner.local_ip, iface)
        job['analysis'] = await asyncio.to_thread(_finalize, pcap, scan_devices, known_scanner_ip)
        job['status'] = 'done'
    except Exception as e:
        job.update(status='error', error=f'analysis failed: {e}')
    finally:
        if os.path.exists(pcap):
            os.unlink(pcap)


@router.get("/live/preflight")
def live_preflight():
    """Report whether capture + scan are usable, and on what interface."""
    return {"capture": capture.probe(), "scan": scanner.probe()}


@router.post("/live/start")
async def live_start(duration: int = 300, iface: str = ""):
    if not capture.find_dumpcap():
        raise HTTPException(status_code=400, detail="dumpcap not found — install Wireshark.")
    iface = iface or capture.default_interface()
    if not iface:
        raise HTTPException(status_code=400, detail="No capture interface available.")
    if duration < 1 or duration > 3600:
        raise HTTPException(status_code=400, detail="duration must be 1–3600 seconds.")

    job_id = uuid.uuid4().hex
    JOBS[job_id] = {"status": "starting", "iface": iface, "duration": duration,
                    "scan": None, "analysis": None}
    asyncio.create_task(_run_live(job_id, iface, duration))
    return {"job_id": job_id, "iface": iface, "duration": duration}


@router.get("/live/{job_id}/status")
def live_status(job_id: str):
    job = JOBS.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Unknown job id.")
    remaining = None
    if job.get("capture_ends_at"):
        remaining = max(0, int(job["capture_ends_at"] - time.time()))
    return {
        "status":            job["status"],
        "iface":             job.get("iface"),
        "seconds_remaining": remaining,
        "scan":              job.get("scan"),
        "scan_device_count": job.get("scan_device_count"),
        "scan_error":        job.get("scan_error"),
        "analysis":          job.get("analysis"),
        "error":             job.get("error"),
    }
