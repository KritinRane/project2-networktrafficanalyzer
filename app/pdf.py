"""Render a network assessment report to a branded PDF via WeasyPrint.

WeasyPrint is imported lazily inside ``render_report_pdf`` so that a missing
native lib (Pango/Cairo — see nixpacks.toml) degrades to "no PDF" rather than
crashing app startup or the whole /api/reports/send request. Callers treat a
None return as "PDF unavailable" and still persist/deliver the report.
"""
import html
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List

# NerdsToGo brand palette.
_ORANGE = "#F58220"
_INK = "#1f2733"
_MUTE = "#6b7885"

# Risk level -> (background, text) for the hero badge.
_RISK_COLORS = {
    "low":      ("#e6f4ea", "#1e7d34"),
    "medium":   ("#fff4e0", "#b3690b"),
    "high":     ("#fdecec", "#c0392b"),
    "critical": ("#3a0d0d", "#ffffff"),
}
_SEV_COLORS = {
    "critical": ("#fdecec", "#c0392b"),
    "high":     ("#fdecec", "#c0392b"),
    "medium":   ("#fff4e0", "#b3690b"),
    "low":      ("#eef2f7", "#42566b"),
    "info":     ("#eef2f7", "#42566b"),
}
# Order for sorting findings most-severe first.
_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _esc(v: Any) -> str:
    return html.escape(str(v if v is not None else ""))


def _risk_key(level: str) -> str:
    return (level or "").strip().lower()


def _fmt_bytes(n: Any) -> str:
    """Human-readable byte count (e.g. 3.4 MB)."""
    try:
        n = float(n)
    except (TypeError, ValueError):
        return "—"
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def _fmt_duration(secs: Any) -> str:
    """Seconds -> compact h/m/s string (e.g. 4m 12s)."""
    try:
        secs = int(float(secs))
    except (TypeError, ValueError):
        return "—"
    if secs <= 0:
        return "—"
    h, rem = divmod(secs, 3600)
    m, s = divmod(rem, 60)
    if h:
        return f"{h}h {m}m"
    if m:
        return f"{m}m {s}s"
    return f"{s}s"


def _stat(label: str, value: Any) -> str:
    return (
        f'<td class="stat"><div class="stat-val">{_esc(value)}</div>'
        f'<div class="stat-label">{_esc(label)}</div></td>'
    )


def _sorted_alerts(alerts: List[dict]) -> List[dict]:
    """Most-severe first; stable within a severity so source order is kept."""
    return sorted(alerts, key=lambda a: _SEV_ORDER.get((a.get("severity") or "info").lower(), 9))


def _alerts_rows(alerts: List[dict]) -> str:
    if not alerts:
        return (
            '<tr><td colspan="2" class="empty">No issues detected — '
            'the network looks healthy.</td></tr>'
        )
    rows = []
    for a in _sorted_alerts(alerts):
        sev = (a.get("severity") or "info").lower()
        bg, fg = _SEV_COLORS.get(sev, _SEV_COLORS["info"])
        action = (a.get("action") or "").strip()
        action_html = (
            f'<div class="alert-action"><b>Recommended:</b> {_esc(action)}</div>'
            if action else ""
        )
        rows.append(
            f'<tr>'
            f'<td class="sev-cell"><span class="sev" style="background:{bg};color:{fg}">'
            f'{_esc(sev.upper())}</span></td>'
            f'<td><div class="alert-title">{_esc(a.get("title"))}</div>'
            f'<div class="alert-detail">{_esc(a.get("detail"))}</div>'
            f'{action_html}</td>'
            f'</tr>'
        )
    return "".join(rows)


def _device_rows(devices: List[dict], limit: int = 30) -> str:
    if not devices:
        return '<tr><td colspan="4" class="empty">No devices recorded.</td></tr>'
    # Flagged devices first, then the rest — most interesting at the top.
    ordered = sorted(devices, key=lambda d: (not d.get("flagged"),))
    rows = []
    for d in ordered[:limit]:
        flag = ('<span class="dot-flag">●</span> Flagged' if d.get("flagged")
                else '<span class="dot-ok">●</span> Known')
        rows.append(
            f'<tr>'
            f'<td class="mono">{_esc(d.get("ip"))}</td>'
            f'<td>{_esc(d.get("hostname") or d.get("mac") or "—")}</td>'
            f'<td>{_esc(d.get("vendor") or "—")}</td>'
            f'<td>{flag}</td>'
            f'</tr>'
        )
    extra = len(devices) - limit
    if extra > 0:
        rows.append(f'<tr><td colspan="4" class="more">+ {extra} more device(s)</td></tr>')
    return "".join(rows)


def _protocol_bars(protocols: List[dict]) -> str:
    """Horizontal bars for the protocol mix, scaled to the largest slice."""
    if not protocols:
        return ""
    top = max((p.get("pct") or 0) for p in protocols) or 1
    rows = []
    for p in protocols[:8]:
        pct = p.get("pct") or 0
        width = max(2, round(pct / top * 100))
        rows.append(
            f'<tr>'
            f'<td class="bar-name">{_esc(p.get("name"))}</td>'
            f'<td class="bar-track"><div class="bar-fill" style="width:{width}%"></div></td>'
            f'<td class="bar-val">{_esc(pct)}%</td>'
            f'</tr>'
        )
    return (
        '<div class="section keep">'
        '<div class="section-title">Protocol Breakdown</div>'
        f'<table class="bars">{"".join(rows)}</table>'
        '</div>'
    )


def _services_block(services: List[dict]) -> str:
    """Top external services/destinations as tidy chips."""
    if not services:
        return ""
    chips = "".join(
        f'<span class="chip">{_esc(s.get("name"))}'
        f'<span class="chip-n">{_esc(s.get("count"))}</span></span>'
        for s in services[:8]
    )
    return (
        '<div class="section keep">'
        '<div class="section-title">Top External Services</div>'
        f'<div class="chips">{chips}</div>'
        '</div>'
    )


def _build_html(analysis: Dict[str, Any], meta: Dict[str, Any]) -> str:
    summary = analysis.get("summary", {}) or {}
    alerts = analysis.get("alerts", []) or []
    devices = analysis.get("devices", []) or []
    protocols = analysis.get("protocols", []) or []
    top_services = analysis.get("top_services", []) or []

    risk_level = summary.get("risk_level") or "—"
    rk = _risk_key(risk_level)
    rbg, rfg = _RISK_COLORS.get(rk, ("#eef2f7", _INK))
    threat = summary.get("threat_score")
    threat_disp = "—" if threat is None else str(threat)

    cust_line_parts = [meta.get("customer_name"), meta.get("customer_company")]
    cust_line = " · ".join(p for p in cust_line_parts if p)
    gen_dt = meta.get("generated_at") or datetime.now(timezone.utc)
    gen_str = gen_dt.strftime("%B %d, %Y at %H:%M UTC")

    summary_text = analysis.get("customer_summary") or "No summary available."

    # Severity tally for the findings sub-header.
    sev_counts: Dict[str, int] = {}
    for a in alerts:
        s = (a.get("severity") or "info").lower()
        sev_counts[s] = sev_counts.get(s, 0) + 1
    tally_parts = [
        f'{sev_counts[s]} {s}' for s in ("critical", "high", "medium", "low", "info")
        if sev_counts.get(s)
    ]
    tally = " · ".join(tally_parts)

    # Scan cross-reference note (dual-source assessments only).
    scan_note = ""
    if analysis.get("has_scan_data"):
        sc = analysis.get("scan_device_count", 0)
        sa = analysis.get("scan_active_count", 0)
        scan_note = (
            f'<span class="pill">Cross-referenced with active scan · '
            f'{_esc(sa)}/{_esc(sc)} devices responded</span>'
        )

    # Key stats — only render cells that exist.
    stats = []
    stats.append(_stat("Devices", summary.get("unique_hosts", len(devices))))
    if summary.get("total_packets") is not None:
        stats.append(_stat("Packets", f'{summary.get("total_packets"):,}'))
    if summary.get("total_bytes") is not None:
        stats.append(_stat("Data", _fmt_bytes(summary.get("total_bytes"))))
    if summary.get("duration_secs") is not None:
        stats.append(_stat("Capture", _fmt_duration(summary.get("duration_secs"))))
    stats.append(_stat("Alerts", summary.get("alert_count", len(alerts))))
    if summary.get("dns_failures"):
        stats.append(_stat("DNS failures", summary.get("dns_failures")))

    return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><style>
  @page {{
    size: letter;
    margin: 1.6cm 1.6cm 2.2cm 1.6cm;
    @bottom-center {{
      content: "NerdsToGo Network Assessment — Confidential";
      font-size: 8pt; color: #9aa7b4;
    }}
    @bottom-right {{ content: "Page " counter(page) " of " counter(pages);
      font-size: 8pt; color: #9aa7b4; }}
  }}
  * {{ box-sizing: border-box; }}
  body {{ font-family: "Liberation Sans", "Helvetica Neue", Arial, sans-serif;
    color: {_INK}; font-size: 10.5pt; line-height: 1.45; margin: 0; }}
  .mono {{ font-family: "Liberation Mono", "DejaVu Sans Mono", monospace; font-size: 9pt; }}
  .brandbar {{ display: flex; align-items: center; justify-content: space-between;
    border-bottom: 3px solid {_ORANGE}; padding-bottom: 10px; margin-bottom: 18px; }}
  .brand {{ font-size: 20pt; font-weight: 800; letter-spacing: -.5px; }}
  .brand .go {{ color: {_ORANGE}; }}
  .doc-type {{ text-align: right; font-size: 9pt; color: {_MUTE}; text-transform: uppercase;
    letter-spacing: 1px; }}
  h1 {{ font-size: 17pt; margin: 0 0 2px 0; }}
  .meta {{ color: {_MUTE}; font-size: 9.5pt; margin-bottom: 12px; }}
  .meta b {{ color: {_INK}; }}
  .pill {{ display: inline-block; background: #eef2f7; color: #42566b; border-radius: 10px;
    padding: 3px 10px; font-size: 8.5pt; margin-bottom: 16px; }}

  .hero {{ display: flex; gap: 16px; margin-bottom: 6px; }}
  .hero-score {{ flex: 0 0 150px; background: {_INK}; color: #fff; border-radius: 10px;
    padding: 16px; text-align: center; }}
  .hero-score .num {{ font-size: 40pt; font-weight: 800; line-height: 1; }}
  .hero-score .cap {{ font-size: 8.5pt; text-transform: uppercase; letter-spacing: 1px;
    color: #b9c4cf; margin-top: 4px; }}
  .hero-risk {{ flex: 1; background: {rbg}; border-radius: 10px; padding: 16px 18px;
    display: flex; flex-direction: column; justify-content: center; }}
  .hero-risk .rl {{ font-size: 22pt; font-weight: 800; color: {rfg}; }}
  .hero-risk .rc {{ font-size: 9pt; text-transform: uppercase; letter-spacing: 1px;
    color: {rfg}; opacity: .8; }}

  .section {{ margin-top: 4px; }}
  .keep {{ break-inside: avoid; page-break-inside: avoid; }}
  .section-title {{ font-size: 12pt; font-weight: 700; margin: 22px 0 8px 0;
    padding-bottom: 4px; border-bottom: 1px solid #e3e9ef;
    break-after: avoid; page-break-after: avoid; }}
  .section-title .sub {{ float: right; font-size: 8.5pt; font-weight: 600; color: {_MUTE};
    text-transform: uppercase; letter-spacing: .5px; padding-top: 4px; }}
  .summary {{ background: #f7f9fb; border-left: 3px solid {_ORANGE}; padding: 12px 14px;
    border-radius: 4px; }}

  table.stats {{ width: 100%; border-collapse: separate; border-spacing: 8px 0; margin: 4px 0 2px; }}
  td.stat {{ background: #f7f9fb; border-radius: 8px; padding: 12px 8px; text-align: center; }}
  .stat-val {{ font-size: 15pt; font-weight: 800; }}
  .stat-label {{ font-size: 8pt; text-transform: uppercase; letter-spacing: .5px; color: {_MUTE}; }}

  table.grid {{ width: 100%; border-collapse: collapse; margin-top: 6px; }}
  table.grid th {{ background: {_INK}; color: #fff; text-align: left; font-size: 8.5pt;
    text-transform: uppercase; letter-spacing: .5px; padding: 7px 10px; }}
  table.grid td {{ padding: 8px 10px; border-bottom: 1px solid #edf1f5; vertical-align: top;
    font-size: 9.5pt; }}
  table.grid tr {{ break-inside: avoid; page-break-inside: avoid; }}
  .sev-cell {{ width: 66px; }}
  .sev {{ display: inline-block; padding: 2px 7px; border-radius: 10px; font-size: 8pt;
    font-weight: 700; }}
  .alert-title {{ font-weight: 700; }}
  .alert-detail {{ color: #5a6672; font-size: 9pt; margin-top: 1px; }}
  .alert-action {{ color: #8a5a12; background: #fff8ef; border-radius: 4px;
    padding: 4px 8px; font-size: 8.5pt; margin-top: 5px; }}
  .alert-action b {{ color: {_ORANGE}; }}
  .empty {{ color: {_MUTE}; font-style: italic; padding: 14px 10px; }}
  .more {{ color: {_MUTE}; font-style: italic; text-align: center; }}
  .dot-flag {{ color: #c0392b; }} .dot-ok {{ color: #1e7d34; }}

  table.bars {{ width: 100%; border-collapse: collapse; }}
  table.bars td {{ padding: 3px 0; vertical-align: middle; }}
  .bar-name {{ width: 90px; font-size: 9pt; font-weight: 600; padding-right: 10px; }}
  .bar-track {{ background: #eef2f7; border-radius: 4px; height: 13px; }}
  .bar-fill {{ background: {_ORANGE}; height: 13px; border-radius: 4px; }}
  .bar-val {{ width: 52px; text-align: right; font-size: 8.5pt; color: {_MUTE};
    padding-left: 10px; }}

  .chips {{ line-height: 2.1; }}
  .chip {{ display: inline-block; background: #f7f9fb; border: 1px solid #e3e9ef;
    border-radius: 14px; padding: 4px 6px 4px 12px; font-size: 9pt; margin: 0 6px 4px 0; }}
  .chip-n {{ display: inline-block; background: {_INK}; color: #fff; border-radius: 10px;
    padding: 1px 7px; font-size: 8pt; margin-left: 7px; }}
</style></head>
<body>
  <div class="brandbar">
    <div class="brand">Nerds<span class="go">To</span>Go</div>
    <div class="doc-type">Network Assessment<br>Report</div>
  </div>

  <h1>Network Assessment Report</h1>
  <div class="meta">
    {('<b>' + _esc(cust_line) + '</b> &nbsp;·&nbsp; ') if cust_line else ''}
    Generated {_esc(gen_str)}
    {(' &nbsp;·&nbsp; Capture: ' + _esc(meta.get('filename'))) if meta.get('filename') else ''}
  </div>
  {scan_note}

  <div class="hero">
    <div class="hero-score">
      <div class="num">{_esc(threat_disp)}</div>
      <div class="cap">Threat Score</div>
    </div>
    <div class="hero-risk">
      <div class="rc">Overall Risk Level</div>
      <div class="rl">{_esc(risk_level)}</div>
    </div>
  </div>

  <div class="section-title">Executive Summary</div>
  <div class="summary">{_esc(summary_text)}</div>

  <div class="section-title">At a Glance</div>
  <table class="stats"><tr>{''.join(stats)}</tr></table>

  <div class="section-title">Findings &amp; Alerts{f'<span class="sub">{_esc(tally)}</span>' if tally else ''}</div>
  <table class="grid">
    <thead><tr><th>Severity</th><th>Finding</th></tr></thead>
    <tbody>{_alerts_rows(alerts)}</tbody>
  </table>

  {_protocol_bars(protocols)}
  {_services_block(top_services)}

  <div class="section-title">Devices Discovered</div>
  <table class="grid">
    <thead><tr><th>IP Address</th><th>Host / MAC</th><th>Vendor</th><th>Status</th></tr></thead>
    <tbody>{_device_rows(devices)}</tbody>
  </table>
</body></html>"""


def render_report_pdf(analysis: Dict[str, Any], meta: Optional[Dict[str, Any]] = None) -> Optional[bytes]:
    """Render the analysis to PDF bytes, or None if WeasyPrint/its native libs
    are unavailable. Never raises — the caller decides how to handle None."""
    meta = meta or {}
    try:
        from weasyprint import HTML  # lazy: native libs may be absent
    except Exception:
        return None
    try:
        return HTML(string=_build_html(analysis, meta)).write_pdf()
    except Exception:
        return None
