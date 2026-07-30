# NerdsToGo Network Analyzer

A self-contained network assessment tool. Upload a packet capture (and,
optionally, an Angry IP Scanner export), and it produces a scored security
assessment, a plain-English customer summary, and an emailable PDF report.

The backend is **FastAPI**. The frontend is a **single `index.html` file** the
server hands out at `/` — there is no separate frontend to build or deploy.

> **No Wireshark/TShark required to analyze captures.** The PCAP/PCAPNG parser
> (`app/pcap_engine.py`) is pure Python with no external dependencies. Wireshark
> is only needed if you use the optional **live capture** feature (see below).

---

## What it does

- **Analyze a capture** — upload a `.pcap` / `.pcapng` / `.cap` file; the engine
  dissects every packet and runs ~20 threat detectors (ARP spoofing, rogue DHCP,
  DNS tunneling, C2 beaconing, data exfiltration, and more). See the scoring and
  detection methodology document for the full breakdown.
- **Cross-check with an active scan** *(optional)* — also upload an **Angry IP
  Scanner** CSV/TSV export and the tool correlates the two, flagging mismatches
  like ghost devices and hostname spoofing.
- **AI customer summary** — a Groq-hosted LLM turns the technical findings into a
  summary a non-technical client can read.
- **Email a PDF report** — save the assessment, render it to PDF, and email it to
  the client with a portal invite so they can view their own reports.
- **Live capture** *(optional, macOS-first)* — run a capture and scan directly
  from the machine instead of uploading files.

---

## Requirements

- **Python 3.11+**
- **A Groq API key** — free tier is fine (https://console.groq.com). Needed for
  the AI summary.
- **System libraries for PDF generation** — WeasyPrint (used for report PDFs)
  needs Pango, cairo, and GDK-PixBuf:
  - **macOS:** `brew install pango gdk-pixbuf libffi`
  - **Ubuntu / Debian:** `sudo apt install libpango-1.0-0 libpangocairo-1.0-0 libgdk-pixbuf2.0-0 libffi-dev`
  - **Windows:** follow the WeasyPrint install guide — https://doc.courtbouillon.org/weasyprint/stable/first_steps.html

You do **not** need TShark, Wireshark, or Npcap for the core upload-and-analyze
workflow.

---

## Setup

```bash
# 1. Get the code
# Option 1: download the ZIP from GitHub, unzip it, then cd into the
#           extracted folder (the folder name may include a branch suffix,
#           e.g. project2-networktrafficanalyzer-main)
cd project2-networktrafficanalyzer

# Option 2: clone with git
git clone https://github.com/KritinRane/project2-networktrafficanalyzer.git
cd project2-networktrafficanalyzer

# 2. Create and activate a virtual environment
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate

# 3. Install Python dependencies
pip install -r requirements.txt

# 4. Create your .env from the template and fill it in
cp .env.example .env
# then open .env and set at least GROQ_API_KEY (see "Configuration" below)

# 5. Run the server
uvicorn app.main:app --reload --port 8000
```

Then open **http://localhost:8000** in your browser — the server serves the full
UI. Log in with the admin credentials from your `.env` (defaults: `admin` /
`nerds2go` — **change these**).

---

## Configuration

All settings are read from a `.env` file in the project root (loaded
automatically at startup). Copy `.env.example` to `.env` and fill it in.

### Required

| Variable | What it's for |
|---|---|
| `GROQ_API_KEY` | Powers the AI customer summary. Get one free at console.groq.com. |

### Admin login & security

| Variable | Default | What it's for |
|---|---|---|
| `APP_USERNAME` | `admin` | Username for the technician (admin) login. |
| `APP_PASSWORD` | `nerds2go` | Password for the admin login. **Change this.** |
| `JWT_SECRET` | dev fallback | Signs login sessions. **Set a long random value in production.** |
| `TOKEN_EXPIRE_HOURS` | `12` | How long a login session stays valid. |
| `DB_PATH` | `data/app.db` | Location of the SQLite database file. |

### Email delivery (needed only to email client reports)

| Variable | Default | What it's for |
|---|---|---|
| `SMTP_USER` | — | Sending email account. |
| `SMTP_PASS` | — | Password. For **Gmail, use a 16-character App Password**, not your normal password. |
| `SMTP_HOST` | `smtp.gmail.com` | SMTP server (change for non-Gmail providers). |
| `SMTP_PORT` | `587` | SMTP port. |
| `SMTP_FROM` | falls back to `SMTP_USER` | The "from" address on the email. |
| `SMTP_FROM_NAME` | `NerdsToGo` | Display name on the email. |
| `PUBLIC_BASE_URL` | `http://localhost:8000` | The public URL clients use to open their portal. **Must be your real domain in production**, or portal invite links will point at localhost. |

Email is only attempted when `SMTP_USER` and `SMTP_PASS` are set. Everything
else in the app works without them.

### Live capture (optional, macOS-first)

Only needed if you want to capture/scan from the machine instead of uploading
files.

| Variable | What it's for |
|---|---|
| `DUMPCAP` | Path to Wireshark's `dumpcap` binary (if not on `PATH`). Requires Wireshark installed. |
| `IPSCAN_APP` | Path to `Angry IP Scanner.app` (if not in a standard Applications folder). |

---

## Using it

1. Open http://localhost:8000 and log in as the admin.
2. Upload a `.pcap` / `.pcapng` capture. Optionally also attach an Angry IP
   Scanner export to cross-check.
3. Review the risk score, findings, and device inventory.
4. Open **Reports → Email Client Report**, enter the client's email (and
   optionally name/company) to save the assessment, generate a PDF, and send it
   with a customer-portal invite.

Clients who accept the invite can log in at the same site and view only their
own reports.

---

## API reference

The UI uses these endpoints; you can also call them directly. Every route under
`/api/` except the login/invite routes requires a `Bearer <token>` from a login.

**Analysis**
- `POST /api/analyze` — upload a capture. Form fields: `file` (required PCAP),
  `csv_file` (optional Angry IP export).
- `GET  /api/analyze/health` — check that Groq is configured.

**Auth**
- `POST /api/auth/login` — admin login → returns a JWT.
- `POST /api/auth/customer/login` — client portal login.
- `GET  /api/auth/invite/{token}` — look up a portal invite.
- `POST /api/auth/accept-invite` — client sets a password from an invite.

**Reports**
- `POST /api/reports/send` — save an assessment, render a PDF, email the client.
- `GET  /api/my/reports` — client: list my reports.
- `GET  /api/my/reports/{id}` / `.../pdf` — client: view a report or its PDF.

**Other**
- `GET  /api/live/preflight`, `POST /api/live/start`, `GET /api/live/{job_id}/status` — live capture.
- `GET  /api/speedtest/*` — bandwidth test used by the UI.
- `GET  /health` — unauthenticated server health check.

Example:
```bash
# Log in, then analyze a capture
TOKEN=$(curl -s -X POST http://localhost:8000/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"nerds2go"}' | python3 -c 'import sys,json;print(json.load(sys.stdin)["token"])')

curl -X POST http://localhost:8000/api/analyze \
  -H "Authorization: Bearer $TOKEN" \
  -F "file=@your_capture.pcap" \
  -F "csv_file=@angryip_export.csv"      # optional
```

---

## Project structure

```
nerdstogoanalyzer/
├── index.html              # Single-file web UI (served at /)
├── app/
│   ├── main.py             # FastAPI app, CORS, JWT auth middleware, routing
│   ├── db.py               # SQLite storage (users, reports, invites)
│   ├── pcap_engine.py      # Pure-Python PCAP/PCAPNG parser + traffic analyzer
│   ├── parser.py           # Turns engine output into devices, alerts, and the risk score
│   ├── csv_parser.py       # Parses Angry IP Scanner CSV/TSV exports
│   ├── merger.py           # Correlates capture vs. active scan (mismatch detection)
│   ├── scanner.py          # Runs an active Angry IP scan (live mode)
│   ├── capture.py          # Runs a live packet capture via dumpcap (live mode)
│   ├── oui.py              # MAC address → manufacturer lookup
│   ├── summarizer.py       # Groq LLM customer summary
│   ├── pdf.py              # Renders the PDF report (WeasyPrint)
│   ├── email_sender.py     # Sends the report email via SMTP
│   └── routers/
│       ├── analyze.py      # POST /api/analyze
│       ├── auth.py         # Login, invites, portal auth
│       ├── reports.py      # Save/send reports, client portal report views
│       ├── live.py         # Live capture + scan jobs
│       └── speedtest.py    # Bandwidth test endpoints
├── requirements.txt
├── .env.example            # Copy to .env and fill in
└── README.md
```

---

## Troubleshooting

- **`cannot import name 'HTML' from 'weasyprint'` / library load errors** — the
  WeasyPrint system libraries aren't installed. See the Requirements section.
- **AI summary is empty or errors** — `GROQ_API_KEY` isn't set or is invalid.
- **Report emails don't send** — `SMTP_USER` / `SMTP_PASS` aren't set; for Gmail
  make sure you're using an App Password.
- **Portal invite links point at `localhost`** — set `PUBLIC_BASE_URL` to your
  real public domain.
- **Live capture fails** — the machine needs Wireshark (`dumpcap`) and, for
  scanning, Angry IP Scanner; on macOS the app must run in a GUI session.
