"""Send a customer their report by email (Gmail SMTP), PDF attached.

Configuration (env):
    SMTP_HOST      default smtp.gmail.com
    SMTP_PORT      default 587 (STARTTLS)
    SMTP_USER      the Gmail address that sends
    SMTP_PASS      a Gmail *App Password* (not the account password — Gmail
                   requires an app password with 2FA enabled)
    SMTP_FROM      optional From header; defaults to SMTP_USER
    SMTP_FROM_NAME optional display name; defaults to "NerdsToGo"

If SMTP_USER/SMTP_PASS are unset, sending is skipped and ``send_report_email``
returns (False, "reason") so the report is still persisted and downloadable —
the app stays usable before email is configured.
"""
import os
import smtplib
from email.message import EmailMessage
from typing import Optional, Tuple


def is_configured() -> bool:
    return bool(os.getenv("SMTP_USER") and os.getenv("SMTP_PASS"))


def _body_text(name: str, invite_url: Optional[str], has_pdf: bool) -> str:
    greeting = f"Hi {name}," if name else "Hi,"
    lines = [
        greeting,
        "",
        "Your network assessment report from NerdsToGo is ready.",
    ]
    if has_pdf:
        lines.append("A PDF copy is attached to this email.")
    if invite_url:
        lines += [
            "",
            "You can also view this and any future reports securely in your "
            "customer portal. Set up your account here:",
            invite_url,
            "",
            "(This link expires in 7 days. If it expires, ask us to resend it.)",
        ]
    lines += ["", "Thanks,", "The NerdsToGo Team"]
    return "\n".join(lines)


def send_report_email(
    to_email: str,
    name: str = "",
    pdf_bytes: Optional[bytes] = None,
    invite_url: Optional[str] = None,
    subject: Optional[str] = None,
) -> Tuple[bool, str]:
    """Return (sent, detail). Never raises — SMTP errors become (False, msg)."""
    if not is_configured():
        return False, "SMTP not configured (set SMTP_USER and SMTP_PASS)."

    host = os.getenv("SMTP_HOST", "smtp.gmail.com")
    port = int(os.getenv("SMTP_PORT", "587"))
    user = os.getenv("SMTP_USER", "")
    password = os.getenv("SMTP_PASS", "")
    from_addr = os.getenv("SMTP_FROM", user)
    from_name = os.getenv("SMTP_FROM_NAME", "NerdsToGo")

    msg = EmailMessage()
    msg["Subject"] = subject or "Your NerdsToGo Network Assessment Report"
    msg["From"] = f"{from_name} <{from_addr}>"
    msg["To"] = to_email
    msg.set_content(_body_text(name, invite_url, pdf_bytes is not None))

    if pdf_bytes:
        msg.add_attachment(
            pdf_bytes, maintype="application", subtype="pdf",
            filename="network-assessment-report.pdf",
        )

    try:
        with smtplib.SMTP(host, port, timeout=30) as server:
            server.starttls()
            server.login(user, password)
            server.send_message(msg)
        return True, "sent"
    except Exception as e:  # auth failure, network, etc.
        return False, f"email send failed: {e}"
