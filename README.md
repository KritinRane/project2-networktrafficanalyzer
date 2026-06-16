# NerdsToGo Network Analyzer - Backend

FastAPI backend that accepts .pcap file uploads, runs TShark dissection,
parses the output, and returns a structured analysis + Groq-generated
customer summary.

## Requirements

- Python 3.11+
- TShark installed on the system
- A Groq API key (free tier works fine)

## Install TShark

**Ubuntu / Debian:**
```bash
sudo apt install tshark
# When prompted, allow non-root users to capture: Yes
```

**macOS:**
```bash
brew install wireshark
# tshark is included
```

**Windows:**
Download Wireshark installer from https://www.wireshark.org/download.html
TShark ships with it. Add the install directory to your PATH.

## Setup

```bash
# 1. Clone / copy this folder to your machine

# 2. Create a virtual environment
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Set your Groq API key
export GROQ_API_KEY=your_key_here
# Windows: set GROQ_API_KEY=your_key_here

# 5. Run the server
uvicorn app.main:app --reload --port 8000
```

Server will be live at http://localhost:8000

## API Endpoints

### POST /api/analyze
Upload a capture file for analysis.

```bash
curl -X POST http://localhost:8000/api/analyze \
  -F "file=@your_capture.pcap"
```

Response shape:
```json
{
  "filename": "capture.pcap",
  "status": "ok",
  "analysis": {
    "summary": {
      "total_packets": 14382,
      "total_bytes": 12181754,
      "duration_secs": 252.1,
      "unique_hosts": 11,
      "retransmissions": 312,
      "retrans_pct": 2.2,
      "dns_failures": 47,
      "alert_count": 3
    },
    "devices": [...],
    "protocols": [...],
    "ports": [...],
    "alerts": [...],
    "customer_summary": "Plain English summary here..."
  }
}
```

### GET /api/analyze/health
Check if TShark and Groq are configured correctly.

### GET /health
Basic server health check.

## Connecting the React Frontend

In your React upload component, point the fetch to:
```
POST http://localhost:8000/api/analyze
```

Use FormData:
```js
const form = new FormData();
form.append('file', selectedFile);
const res = await fetch('http://localhost:8000/api/analyze', {
  method: 'POST',
  body: form,
});
const data = await res.json();
```

## Project Structure

```
nerdstogoanalyzer/
├── app/
│   ├── main.py           # FastAPI app + CORS
│   ├── tshark_runner.py  # Shells out to tshark
│   ├── parser.py         # Parses raw packets into structured data
│   ├── oui.py            # MAC -> manufacturer lookup
│   ├── summarizer.py     # Groq LLM customer summary
│   └── routers/
│       └── analyze.py    # POST /api/analyze endpoint
├── requirements.txt
└── README.md
```
# project2-networktrafficanalyzer
# project2-networktrafficanalyzer
