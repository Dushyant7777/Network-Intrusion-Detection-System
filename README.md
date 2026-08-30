# 🛡️ NIDS Console — Network Intrusion Detection System

A full-stack, web-based **Network Intrusion Detection System (NIDS)** that captures and analyzes live network traffic, detects common attack patterns in real time, and presents everything through a secure, interactive security dashboard.

Built with **Python, Flask, Scapy, SQLite, Bootstrap, and Chart.js.**

---

## 📌 Problem Statement

Modern networks are constantly exposed to threats such as **port scanning, denial-of-service floods (SYN/ICMP), and abnormal traffic spikes** — attacks that often go unnoticed until real damage is done. Enterprise-grade intrusion detection systems exist, but they're typically expensive, complex to deploy, and opaque to anyone trying to *learn* how network monitoring and threat detection actually work under the hood.

There's a need for a system that is:
- **Lightweight** — runs on a single machine, no specialized hardware
- **Transparent** — rule-based logic that's easy to read, tune, and explain
- **Accessible** — a real-time web dashboard instead of raw logs or a CLI
- **Cost-effective** — built entirely on free and open-source tools

## 💡 Solution

**NIDS Console** captures network packets (via **Scapy**), extracts key metadata (source/destination IP, protocol, ports, size, timestamp), and runs it through a detection engine that flags:

- **Port scanning** — one source probing many ports in a short window
- **SYN floods** — a burst of half-open TCP connections (classic DoS pattern)
- **ICMP floods** — a burst of ping requests aimed at exhausting resources
- **Traffic anomalies** — statistical spikes in overall packet rate vs. a rolling baseline (a lightweight, explainable stand-in for a full ML anomaly model)

Every detection becomes an **alert** with a severity level (**Critical / High / Medium / Low**), persisted to a SQLite database for investigation and historical reporting. All of it is served through an authenticated, real-time web dashboard — no command line required to actually *use* the tool day-to-day.

A built-in **Simulation Mode** generates realistic synthetic traffic (including simulated attack bursts) so the entire system — detection, database, dashboard, charts — can be explored and demoed without root/Administrator privileges or a live network. It never sends a single real packet; it only feeds the same data pipeline that live capture uses.

---

## 🚀 Key Features

- ✅ Real-time network packet monitoring
- ✅ Packet capture and analysis using **Scapy**
- ✅ Detection of suspicious network activities
- ✅ Port scan and flood attack detection (SYN / ICMP)
- ✅ Statistical, ML-adjacent anomaly detection (rolling z-score)
- ✅ Alert generation with severity levels
- ✅ Web-based, real-time monitoring dashboard
- ✅ Database storage of packets and security alerts (SQLite)
- ✅ User authentication and secure login (hashed passwords, sessions, brute-force lockout)
- ✅ Self-service account creation with role separation (self-registered users vs. the admin account) and per-IP rate limiting, toggleable off entirely for public deployments
- ✅ Network traffic visualization (live charts, protocol mix, top talkers)
- ✅ Security reports, historical analysis, and CSV export
- ✅ Safe, no-privileges-required Simulation Mode for demos/testing

---

## 🛠️ Technology Used

| Layer | Technology |
|---|---|
| Backend | Python 3, Flask |
| Packet Capture | Scapy |
| Database | SQLite |
| Auth / Security | Werkzeug (PBKDF2 password hashing), Flask signed sessions |
| Frontend | HTML5, CSS3, JavaScript (vanilla) |
| UI Framework | Bootstrap 5 |
| Data Visualization | Chart.js |
| Fonts | Google Fonts (Chakra Petch, Inter, JetBrains Mono) |

---

## 🏗️ System Architecture

```
 ┌──────────────┐      ┌──────────────┐
 │  capture.py  │      │ simulator.py │
 │ (Scapy live  │      │ (synthetic   │
 │  sniffing)   │      │  demo data)  │
 └──────┬───────┘      └──────┬───────┘
        │   packet metadata dict    │
        └────────────┬─────────────┘
                      ▼
              handle_packet()  (app.py)
                      │
        ┌─────────────┼──────────────┐
        ▼             ▼              ▼
  metrics.py     detection.py    database.py
 (live stats)   (4 detection     (SQLite: packets,
                  rules)           alerts, users)
        │             │              │
        └─────────────┼──────────────┘
                      ▼
              Flask REST API (/api/*)
                      │
                      ▼
     templates/index.html + dashboard.js
        (Bootstrap + Chart.js dashboard,
         polls the API every 2–3 seconds)
```

Both `capture.py` and `simulator.py` speak the exact same "packet dict" format and feed the exact same callback — the detection engine, database, and dashboard have no idea (and don't need to know) whether traffic is real or simulated.

---

## 📂 Project Structure

```
nids-dashboard/
├── app.py                    # Flask app: routes, REST API, app wiring
├── auth.py                   # Sessions, password hashing, brute-force lockout
├── database.py               # SQLite schema + all queries
├── detection.py               # Detection engine (4 rules)
├── capture.py                  # Real packet capture via Scapy
├── simulator.py                 # Synthetic traffic generator (Simulation Mode)
├── metrics.py                    # In-memory rolling stats for the dashboard
├── selftest.py                    # Standalone automated tests (no server needed)
├── requirements.txt
├── .gitignore
├── LICENSE
├── README.md
├── templates/
│   ├── login.html
│   └── index.html              # Dashboard (Overview + Reports tabs)
└── static/
    ├── css/style.css            # Dashboard design system
    └── js/dashboard.js           # Polling, charts, controls, modals
```

---

## ⚙️ Installation & Setup

```bash
# 1. Clone the repository
git clone https://github.com/<your-username>/nids-dashboard.git
cd nids-dashboard

# 2. Create and activate a virtual environment
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Run the app
python app.py
```

You'll see:
```
First run: created default login  admin / admin123
NIDS dashboard starting at http://127.0.0.1:5000
```

Open **http://127.0.0.1:5000**, sign in, and change the default password immediately (there's a banner that stays until you do).

## ▶️ Usage

1. Log in.
2. Pick **Simulation Mode** (default) and click **Start Monitoring** — traffic, charts, and alerts populate within seconds, no privileges needed.
3. Explore the **Overview** tab for live stats, traffic/protocol charts, and a live alert feed.
4. Explore the **Reports** tab for historical trends, top offending sources, and full alert history — export it as CSV.
5. For **real** traffic instead of simulated data, switch to **Live Capture**. This requires elevated privileges:
   - Linux/macOS: `sudo venv/bin/python app.py`
   - Windows: install [Npcap](https://npcap.com/#download), run as Administrator
   - Only monitor networks you own or are authorized to observe.

Run `python selftest.py` any time to re-verify the database, auth, and detection logic (23 automated checks).

---

## 🔍 Detection Logic

| Rule | Trigger Condition |
|---|---|
| **Port Scan** | One source IP touches ≥15 distinct destination ports within 10 seconds |
| **SYN Flood** | ≥50 SYN (no-ACK) packets from one source within 5 seconds |
| **ICMP Flood** | ≥50 ICMP echo requests from one source within 5 seconds |
| **Traffic Anomaly** | Packet-rate z-score ≥3 against its own rolling baseline |

Severity (Critical/High/Medium/Low) scales with how far past the threshold the activity is. Thresholds live as constants at the top of `detection.py` and are easy to retune. Repeated detections from the same source are rate-limited with a cooldown so one sustained attack doesn't spam duplicate alerts.

---

## 🔐 Security Notes

This project implements **real, working security fundamentals**: passwords are hashed with PBKDF2 (never stored in plaintext), sessions are signed cookies, and login attempts are rate-limited per username. It is intentionally scoped for **learning and local/LAN use**, not hardened for open-internet production — it does not include CSRF tokens, HTTPS enforcement, or multi-factor auth. See the code comments in `auth.py` for specifics on what a production deployment should add.

**Signup and roles:** `/signup` is open by default, but every self-registered account is a normal (non-admin) user — only the original seeded account can perform destructive actions (currently: wiping all stored data), enforced both in the UI and at the API level, not just hidden client-side. Signup attempts are rate-limited per IP (6/hour) to blunt scripted mass account creation. If you'd rather not accept public signups at all — recommended if you're hosting this somewhere reachable by strangers — set:
```bash
NIDS_ALLOW_SIGNUP=false python app.py
```
which removes the "Create account" link and closes the `/signup` route entirely (both GET and POST), while leaving the seeded admin account and everything else untouched.

**Configuration (environment variables):**

| Variable | Default | Purpose |
|---|---|---|
| `NIDS_ALLOW_SIGNUP` | `true` | Set to `false` to disable self-service signup entirely |
| `NIDS_HOST` | `127.0.0.1` | Set to `0.0.0.0` to accept connections from other devices, not just this machine |
| `NIDS_PORT` | `5000` | Change the port the dashboard listens on |
| `NIDS_SECRET_KEY` | auto-generated | Pin the session-signing key explicitly instead of the auto-generated `.secret_key` file (useful if you're running multiple instances, or redeploying and want existing sessions to survive) |

---

## 🔮 Future Enhancements

- Replace the statistical anomaly rule with a trained ML model (Isolation Forest / autoencoder)
- Finer-grained roles/permissions beyond the current two-tier admin/user split
- Email/webhook notifications on Critical alerts
- Session history table for tracking monitoring sessions over time
- Deploy behind Gunicorn/Nginx with HTTPS for always-on monitoring

---

## 📄 License

This project is licensed under the MIT License — see [LICENSE](LICENSE) for details.

## 🙌 Acknowledgements

Built as an educational cybersecurity project demonstrating real-time network monitoring, rule-based intrusion detection, and full-stack web development.
