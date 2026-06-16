import os
import tempfile
import shutil
from pathlib import Path

from fastapi import APIRouter, UploadFile, File, HTTPException
from fastapi.responses import JSONResponse

from app.tshark_runner import run_tshark_json
from app.parser import parse_packets
from app.summarizer import generate_customer_summary

router = APIRouter()

ALLOWED_EXTENSIONS = {".pcap", ".pcapng", ".cap"}
MAX_FILE_SIZE_MB = 100


@router.post("/analyze")
async def analyze_capture(file: UploadFile = File(...)):
    """
    Accepts a .pcap / .pcapng / .cap upload.
    Returns structured analysis + customer summary.
    """
    ext = Path(file.filename).suffix.lower()
    if ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid file type '{ext}'. Allowed: {', '.join(ALLOWED_EXTENSIONS)}"
        )

    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile(suffix=ext, delete=False) as tmp:
            tmp_path = tmp.name
            content = await file.read()

            size_mb = len(content) / (1024 * 1024)
            if size_mb > MAX_FILE_SIZE_MB:
                raise HTTPException(
                    status_code=413,
                    detail=f"File too large ({size_mb:.1f} MB). Max allowed: {MAX_FILE_SIZE_MB} MB."
                )

            tmp.write(content)

        raw_packets = run_tshark_json(tmp_path)

        if not raw_packets:
            raise HTTPException(status_code=422, detail="No packets found in capture file.")

        analysis = parse_packets(raw_packets)
        customer_summary = generate_customer_summary(analysis)
        analysis["customer_summary"] = customer_summary

        return JSONResponse(content={
            "filename": file.filename,
            "status": "ok",
            "analysis": analysis,
        })

    except HTTPException:
        raise
    except RuntimeError as e:
        raise HTTPException(status_code=500, detail=f"TShark error: {str(e)}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")
    finally:
        if tmp_path and os.path.exists(tmp_path):
            os.unlink(tmp_path)


@router.get("/analyze/health")
def analyze_health():
    """Check if tshark is available on the system."""
    import subprocess
    result = subprocess.run(["which", "tshark"], capture_output=True, text=True)
    tshark_available = result.returncode == 0
    return {
        "tshark_available": tshark_available,
        "tshark_path": result.stdout.strip() if tshark_available else None,
        "groq_configured": bool(os.environ.get("GROQ_API_KEY")),
    }
