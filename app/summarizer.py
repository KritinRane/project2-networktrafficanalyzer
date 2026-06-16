import os
import json

SYSTEM_PROMPT = """
You are a friendly network technician explaining findings to a non-technical customer.
You will be given a JSON summary of a network scan.

Your job is to write 2-3 short paragraphs in plain English that:
1. Summarize what was found on the network overall
2. Highlight any issues clearly, without jargon
3. Suggest what actions the customer should consider

Rules:
- Never use technical terms without immediately explaining them in parentheses
- Use friendly, reassuring language — not alarmist
- If there are no issues, say so clearly and positively
- Keep it under 150 words total
- Return ONLY the plain-English summary text, no JSON, no headers
""".strip()


def generate_customer_summary(analysis: dict) -> str:
    summary = analysis.get("summary", {})
    alerts = analysis.get("alerts", [])
    devices = analysis.get("devices", [])
    flagged = [d for d in devices if d.get("flagged")]
    known = [d for d in devices if not d.get("flagged")]

    api_key = os.environ.get("GROQ_API_KEY")
    if not api_key:
        return _fallback_summary(summary, alerts, flagged)

    payload = {
        "total_packets": summary.get("total_packets"),
        "unique_devices": summary.get("unique_hosts"),
        "known_devices": len(known),
        "flagged_devices": len(flagged),
        "retransmission_pct": summary.get("retrans_pct"),
        "dns_failures": summary.get("dns_failures"),
        "alerts": [
            {"severity": a["severity"], "title": a["title"], "detail": a["detail"]}
            for a in alerts
        ],
    }

    try:
        from groq import Groq
        client = Groq(api_key=api_key)
        response = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": json.dumps(payload, indent=2)},
            ],
            temperature=0.4,
            max_tokens=300,
        )
        return response.choices[0].message.content.strip()
    except Exception:
        return _fallback_summary(summary, alerts, flagged)


def _fallback_summary(summary: dict, alerts: list, flagged: list) -> str:
    device_count = summary.get("unique_hosts", 0)
    alert_count = len(alerts)

    if alert_count == 0:
        return (
            f"We scanned your network and found {device_count} devices connected. "
            "Everything looks healthy — all devices were recognized and no unusual activity was detected."
        )

    high = [a for a in alerts if a["severity"] == "high"]
    med = [a for a in alerts if a["severity"] == "medium"]

    parts = [
        f"We analyzed your network and found {device_count} connected devices. "
        f"There {'is' if alert_count == 1 else 'are'} {alert_count} issue{'s' if alert_count != 1 else ''} that need attention."
    ]
    if high:
        parts.append(f"The most urgent issue: {high[0]['title'].lower()}. {high[0]['detail']}")
    if med:
        parts.append(f"We also noticed: {med[0]['title'].lower()}. {med[0]['detail']}")
    parts.append("Our technician can walk you through the recommended next steps.")
    return " ".join(parts)