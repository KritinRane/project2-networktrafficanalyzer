import asyncio, json, os, shutil
from fastapi import Request
from fastapi.responses import Response, JSONResponse
from fastapi.routing import APIRouter

router = APIRouter()

# ── HTTP endpoints (used by browser-based methodology — accurate only when
#    the backend is hosted on an internet server, not localhost) ───────────────
_MAX_CHUNK = 32 * 1024 * 1024
_POOL      = os.urandom(_MAX_CHUNK)


@router.get("/speedtest/ping")
async def speedtest_ping():
    return JSONResponse({"pong": True})


@router.get("/speedtest/chunk")
async def speedtest_chunk(bytes: int = 1048576):
    size = min(max(int(bytes), 1024), _MAX_CHUNK)
    return Response(
        content=_POOL[:size],
        media_type="application/octet-stream",
        headers={"Cache-Control": "no-store", "Content-Length": str(size)},
    )


@router.post("/speedtest/upload-chunk")
async def speedtest_upload_chunk(request: Request):
    body = await request.body()
    return JSONResponse({"bytes": len(body)})


# ── Official Ookla binary (brew install speedtest) ───────────────────────────
# Uses speedtest.net servers over real TCP — accurate regardless of where the
# backend runs, because the binary reaches out to the internet itself.
_OOKLA_CANDIDATES = [
    "speedtest",
    "/opt/homebrew/bin/speedtest",   # Apple Silicon Mac
    "/usr/local/bin/speedtest",      # Intel Mac
    "/usr/bin/speedtest",
]


def _find_ookla() -> str | None:
    for c in _OOKLA_CANDIDATES:
        if shutil.which(c):
            return c
    return None


@router.get("/speedtest/run")
async def speedtest_run():
    exe = _find_ookla()
    if not exe:
        return JSONResponse(
            {"error": "Official Ookla CLI not found.\n"
                       "Install: brew install speedtest\n"
                       "Then run once to accept license: speedtest --accept-license --accept-gdpr"},
            status_code=500,
        )

    try:
        proc = await asyncio.create_subprocess_exec(
            exe,
            "--format=json",
            "--accept-license",
            "--accept-gdpr",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=120)
    except asyncio.TimeoutError:
        return JSONResponse({"error": "Speed test timed out (>2 min)"}, status_code=504)
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)

    raw = stdout.decode().strip()
    if proc.returncode != 0:
        err = stderr.decode().strip() or raw or "speedtest exited with an error"
        return JSONResponse({"error": err}, status_code=500)

    # Find the result object — Ookla CLI may emit one JSON per line
    result = None
    for line in reversed(raw.splitlines()):
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
            if "download" in obj and "upload" in obj:
                result = obj
                break
        except json.JSONDecodeError:
            continue

    if result is None:
        return JSONResponse({"error": f"Could not parse output: {raw[:300]}"}, status_code=500)

    try:
        dl   = result["download"]["bandwidth"] * 8 / 1e6   # bytes/s → Mbps
        ul   = result["upload"]["bandwidth"]   * 8 / 1e6
        ping = result.get("ping", {}).get("latency", 0)
        srv  = result.get("server", {})
        name = f"{srv.get('name', '')} ({srv.get('location', '')})".strip(" ()")
        return JSONResponse({
            "download_mbps": round(dl, 2),
            "upload_mbps":   round(ul, 2),
            "ping_ms":       round(ping, 1),
            "server":        name,
        })
    except (KeyError, TypeError) as e:
        return JSONResponse({"error": f"Unexpected format: {e} — raw: {raw[:200]}"}, status_code=500)
