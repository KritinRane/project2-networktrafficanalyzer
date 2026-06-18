import os
import tempfile
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, UploadFile, File, HTTPException
from fastapi.responses import JSONResponse

from app.parser import parse_pcap_file, _score
from app.csv_parser import parse_angry_ip_csv
from app.merger import (
    detect_ghost_devices,
    detect_hostname_spoofing,
    detect_shadow_infrastructure,
)
from app.summarizer import generate_customer_summary

router = APIRouter()

_ALLOWED_PCAP = {".pcap", ".pcapng", ".cap"}
_ALLOWED_CSV  = {".csv", ".txt", ".tsv"}
_MAX_MB       = 100


@router.post("/analyze")
async def analyze_capture(
    file:     UploadFile = File(...),
    csv_file: Optional[UploadFile] = File(default=None),
):
    """
    POST /api/analyze

    Accepts:
      file      — .pcap / .pcapng / .cap   (required)
      csv_file  — Angry IP Scanner TSV/CSV  (optional)
    """
    ext = Path(file.filename).suffix.lower()
    if ext not in _ALLOWED_PCAP:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid capture file type '{ext}'. Allowed: {', '.join(_ALLOWED_PCAP)}"
        )

    tmp_path = None
    try:
        # ── Save PCAP to temp file ────────────────────────────────────────────
        with tempfile.NamedTemporaryFile(suffix=ext, delete=False) as tmp:
            tmp_path = tmp.name
            content  = await file.read()
            size_mb  = len(content) / 1_048_576
            if size_mb > _MAX_MB:
                raise HTTPException(
                    status_code=413,
                    detail=f"File too large ({size_mb:.1f} MB). Max: {_MAX_MB} MB."
                )
            tmp.write(content)

        # ── Phase 1: parse CSV scan data ──────────────────────────────────────
        scan_devices = []
        has_scan = False
        if csv_file and csv_file.filename:
            csv_ext = Path(csv_file.filename).suffix.lower()
            if csv_ext not in _ALLOWED_CSV:
                raise HTTPException(
                    status_code=400,
                    detail=f"Invalid CSV file type '{csv_ext}'. Allowed: {', '.join(_ALLOWED_CSV)}"
                )
            csv_bytes    = await csv_file.read()
            scan_devices = parse_angry_ip_csv(csv_bytes)
            has_scan     = bool(scan_devices)

        # ── Phase 2+3: analyze PCAP, matching devices by IP to CSV catalog ────
        analysis = parse_pcap_file(tmp_path, scan_devices if has_scan else None)

        if not analysis.get("devices") and analysis.get("summary", {}).get("total_packets", 0) == 0:
            raise HTTPException(status_code=422, detail="No packets found in capture file.")

        # ── Phase 4: cross-reference mismatch detection ───────────────────────
        if has_scan:
            mismatch_alerts = (
                detect_ghost_devices(analysis['devices']) +
                detect_hostname_spoofing(analysis['devices']) +
                detect_shadow_infrastructure(analysis['devices'])
            )

            # Strip internal keys before serialisation
            for d in analysis['devices']:
                d.pop('_scan_hostname', None)
                d.pop('_pcap_hostname', None)

            analysis['alerts']            = mismatch_alerts + analysis.get('alerts', [])
            analysis['scan_device_count'] = len(scan_devices)
            analysis['scan_active_count'] = sum(1 for d in scan_devices if d.get('responded'))

            threat_score, risk_level = _score(analysis['alerts'])
            analysis['summary']['threat_score'] = threat_score
            analysis['summary']['risk_level']   = risk_level
            analysis['summary']['alert_count']  = len(analysis['alerts'])
        else:
            for d in analysis['devices']:
                d.pop('_scan_hostname', None)
                d.pop('_pcap_hostname', None)
            analysis['scan_device_count'] = 0
            analysis['scan_active_count'] = 0

        analysis['has_scan_data'] = has_scan

        analysis["customer_summary"] = generate_customer_summary(analysis)

        return JSONResponse(content={
            "filename":     file.filename,
            "csv_filename": csv_file.filename if (csv_file and csv_file.filename) else None,
            "status":       "ok",
            "analysis":     analysis,
        })

    except HTTPException:
        raise
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")
    finally:
        if tmp_path and os.path.exists(tmp_path):
            os.unlink(tmp_path)


@router.get("/analyze/health")
def analyze_health():
    return {
        "engine":          "pcap_engine (native Python)",
        "tshark_required": False,
        "groq_configured": bool(os.environ.get("GROQ_API_KEY")),
    }


_TEST_DATA = Path(__file__).parent.parent.parent / "test_data"


@router.post("/analyze/test")
def analyze_test():
    """
    Run analysis on whatever .pcap and .csv sit in test_data/.
    No upload required — for dev/testing only.
    """
    pcap_files = sorted(_TEST_DATA.glob("*.pcap")) + sorted(_TEST_DATA.glob("*.pcapng")) + sorted(_TEST_DATA.glob("*.cap"))
    csv_files  = sorted(_TEST_DATA.glob("*.csv")) + sorted(_TEST_DATA.glob("*.txt")) + sorted(_TEST_DATA.glob("*.tsv"))

    if not pcap_files:
        raise HTTPException(status_code=404, detail="No .pcap file found in test_data/. Drop one in and try again.")

    pcap_path = str(pcap_files[0])
    scan_devices = []
    csv_name = None
    if csv_files:
        csv_bytes    = csv_files[0].read_bytes()
        csv_name     = csv_files[0].name
        scan_devices = parse_angry_ip_csv(csv_bytes)

    has_scan = bool(scan_devices)
    analysis = parse_pcap_file(pcap_path, scan_devices if has_scan else None)

    if has_scan:
        mismatch_alerts = (
            detect_ghost_devices(analysis['devices']) +
            detect_hostname_spoofing(analysis['devices']) +
            detect_shadow_infrastructure(analysis['devices'])
        )
        for d in analysis['devices']:
            d.pop('_scan_hostname', None)
            d.pop('_pcap_hostname', None)

        analysis['alerts']            = mismatch_alerts + analysis.get('alerts', [])
        analysis['scan_device_count'] = len(scan_devices)
        analysis['scan_active_count'] = sum(1 for d in scan_devices if d.get('responded'))

        threat_score, risk_level = _score(analysis['alerts'])
        analysis['summary']['threat_score'] = threat_score
        analysis['summary']['risk_level']   = risk_level
        analysis['summary']['alert_count']  = len(analysis['alerts'])
    else:
        for d in analysis['devices']:
            d.pop('_scan_hostname', None)
            d.pop('_pcap_hostname', None)
        analysis['scan_device_count'] = 0
        analysis['scan_active_count'] = 0

    analysis['has_scan_data'] = has_scan
    analysis['customer_summary'] = generate_customer_summary(analysis)

    return JSONResponse(content={
        "filename":     pcap_files[0].name,
        "csv_filename": csv_name,
        "status":       "ok",
        "analysis":     analysis,
    })
