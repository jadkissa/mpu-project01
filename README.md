# Snort IDS — AI-Powered Network Intrusion Detection System

Graduation Project — Security Engineering · DevOps

![Ubuntu](https://img.shields.io/badge/Ubuntu-24.04_LTS-E95420?style=flat&logo=ubuntu&logoColor=white)
![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?style=flat&logo=docker&logoColor=white)
![Python](https://img.shields.io/badge/Python-3.11-3776AB?style=flat&logo=python&logoColor=white)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-15-336791?style=flat&logo=postgresql&logoColor=white)
![Snort](https://img.shields.io/badge/Snort-3.x-FF0000?style=flat)
![React](https://img.shields.io/badge/React-18-61DAFB?style=flat&logo=react&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-0.110-009688?style=flat&logo=fastapi&logoColor=white)
![n8n](https://img.shields.io/badge/n8n-2.16-EA4B71?style=flat&logo=n8n&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green?style=flat)

---

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Why This Design](#why-this-design)
- [Project Structure](#project-structure)
- [Components](#components)
- [Prerequisites](#prerequisites)
- [Quick Start](#quick-start)
- [Database Schema](#database-schema)
- [Environment Variables](#environment-variables)
- [API Endpoints](#api-endpoints)
- [ML Engine](#ml-engine)
- [Alerting with n8n](#alerting-with-n8n)
- [Security Notes](#security-notes)
- [Roadmap](#roadmap)
- [Authors](#authors)

---

## Overview

A full-stack Network Intrusion Detection System developed as a two-semester graduation project. The system combines **signature-based detection** (Snort 3) with **unsupervised machine learning** (Isolation Forest) for two-layer threat detection, real-time monitoring, and automated Telegram alerting via n8n.

**Snort 3** handles known attacks via rules. The **ML engine** monitors raw network traffic, learns normal behavior, and flags anomalies that Snort's rules miss — such as DDoS floods, slow scans, and unknown attack patterns. **n8n** listens to PostgreSQL triggers and sends instant Telegram notifications when either layer detects a threat.

**WebGoat** runs as a deliberately vulnerable target application. Attacks are simulated from **Kali Linux** in VirtualBox (Bridged network mode) on the host machine.

### Key Targets

| Metric              | Target |
| ------------------- | ------ |
| Detection Rate      | 94%+   |
| Response Time       | < 50ms |
| False Positive Rate | < 5%   |
| Uptime              | 99%+   |

---

## Architecture

```
Host Machine (Ubuntu 24.04 LTS)
          |
          | Raw network traffic (host NIC: wlp4s0)
          |
          +------------------+------------------+
          |                                     |
          v                                     v
+----------------------+           +------------------------+
|   Snort 3            |           |   ML Engine (Python)   |
|   network_mode: host |           |   network_mode: host   |
|   Signature-based    |           |   Isolation Forest     |
|   detection          |           |   Anomaly detection    |
|   --> alert_json.txt |           |   Checks event table   |
+----------+-----------+           |   before alerting      |
           |                       +----------+-------------+
           | shared volume                    |
           v                                  |
+----------------------------------------------------------+
|   Docker Compose Network (mpu-network bridge)            |
|                                                          |
|   +--------------------------------------------------+   |
|   |   alerts_watcher (Python)                        |   |
|   |   Tails alert_json.txt --> writes to PostgreSQL  |   |
|   +--------------------------------------------------+   |
|                                                          |
|   +------------------+    +-------------------------+    |
|   |   PostgreSQL 15  |<---+   ML Engine inserts     |    |
|   |   event table    |    |   into ml_alerts        |    |
|   |   ml_alerts table|    +-------------------------+    |
|   +--------+---------+                                   |
|            |  LISTEN/NOTIFY triggers                     |
|            v                                             |
|   +------------------+    +-------------------------+    |
|   |   n8n            |    |   FastAPI Backend       |    |
|   |   Workflow engine|    |   :8000                 |    |
|   |   Telegram alerts|    +----------+--------------+    |
|   +------------------+               |                   |
|                                      v                   |
|                           +----------+--------------+    |
|                           |   React Frontend        |    |
|                           |   :3000                 |    |
|                           +-------------------------+    |
|                                                          |
|   +--------------------------------------------------+   |
|   |   WebGoat — Vulnerable target app                |   |
|   |   :8080 / :9090                                  |   |
|   +--------------------------------------------------+   |
+----------------------------------------------------------+

Attack Simulation:
  Kali Linux (VirtualBox, Bridged) --> attacks --> Host / WebGoat
  Snort detects known attacks      --> event table --> Dashboard + Telegram
  ML detects unknown anomalies     --> ml_alerts table --> Dashboard + Telegram
```

---

## Two-Layer Detection Logic

The system uses a deliberate separation between the two detection layers:

```
New network traffic
        |
        v
Snort checks rules
        |
   Detected? ----YES----> event table --> Telegram (Snort alert)
        |
        NO
        |
        v
ML Engine analyzes flow
        |
   Anomaly? ----YES----> Check event table (was it already caught by Snort?)
                              |
                         Already there? --> SKIP (avoid duplicate alerts)
                              |
                              NO
                              |
                              v
                         ml_alerts table --> Telegram (ML alert)
```

This ensures Snort handles known threats efficiently, while the ML layer focuses exclusively on what Snort missed.

---

## Why This Design

### Why Snort with `network_mode: host`?

Snort needs direct access to the physical network interface to capture packets before any Docker NAT or bridge processing happens. `network_mode: host` gives the container full visibility over the host NIC while keeping every other service isolated inside the bridge network.

### Why a custom `alerts_watcher` instead of a database plugin?

Snort 3 writes alerts as newline-delimited JSON to `alert_json.txt`. The `alerts_watcher` service tails that file from the last known position, parses each JSON line, and writes structured rows to PostgreSQL. This keeps Snort fully decoupled from the database — Snort never waits on a DB write, and the watcher can be restarted independently without losing alerts.

### Why Isolation Forest for anomaly detection?

Isolation Forest is an unsupervised algorithm — it requires no labeled attack data. It learns what "normal" traffic looks like during a training phase, then flags anything that deviates significantly. This is ideal for detecting unknown or novel attacks that signature-based systems like Snort miss.

### Why n8n for alerting instead of custom code?

n8n uses PostgreSQL's native `LISTEN/NOTIFY` mechanism via Postgres Trigger nodes. This means alerts fire instantly the moment a row is inserted — no polling delay. The visual workflow editor also makes it easy to extend alerting to Slack, email, or webhooks without touching application code.

### Why PostgreSQL?

PostgreSQL's native `INET` type stores IP addresses cleanly. The `LISTEN/NOTIFY` feature enables real-time triggers for n8n. It also gives the ML layer a solid foundation for querying traffic patterns and flow aggregation.

---

## Project Structure

```
mpu-project01/
├── docker-compose.yml
├── .env                          # NOT in git
├── .env.example
├── .gitignore
├── README.md
├── Dockerfile.watcher            # alerts_watcher container image
├── alerts_watcher.py             # Tails alert_json.txt and writes to PostgreSQL
│
├── ml_engine/
│   ├── Dockerfile
│   ├── requirements.txt
│   ├── ml_watcher.py             # Captures traffic, trains model, detects anomalies
│   └── models/
│       └── model.pkl             # Saved Isolation Forest model (generated at runtime)
│
├── database/
│   └── init.sql                  # Schema — runs automatically on first PostgreSQL start
│
├── snort/
│   ├── snort.lua                 # Snort 3 configuration
│   └── rules/
│       └── local.rules
│
├── snort_logs/                   # Shared volume: Snort writes, alerts_watcher reads
│   └── alert_json.txt
│
└── dashboard/
    ├── backend/
    │   ├── Dockerfile
    │   ├── requirements.txt
    │   ├── main.py
    │   ├── database.py
    │   └── routes/
    │       ├── alerts.py         # /api/alerts/snort  /api/alerts/ml
    │       └── stats.py          # /api/stats/*
    └── frontend/
        ├── Dockerfile
        └── src/
            ├── App.js
            ├── api/
            │   └── index.js
            └── components/
                ├── StatsCards.js
                ├── SnortAlerts.js
                ├── MLDetections.js
                └── ProtocolChart.js
```

---

## Components

### Snort 3 (`ciscotalos/snort3` — `network_mode: host`)

- Signature-based detection engine using rules from `snort/rules/local.rules`
- Runs with `network_mode: host` and `privileged: true`
- On rule match: appends a JSON object to `snort_logs/alert_json.txt`
- Has no database dependency — writes only to the shared volume

### alerts_watcher (Python — `mpu-network`)

- Tails `alert_json.txt` using a file position cursor (survives restarts)
- Writes one row to `signature` and one row to `event` per alert
- Polls every 1 second with `restart: unless-stopped`

### ML Engine (Python — `network_mode: host`)

- Captures live traffic from `wlp4s0` using Scapy
- **Training mode:** collects normal traffic flows for 15 minutes, trains Isolation Forest, saves `model.pkl`
- **Detection mode:** aggregates flows every 10 seconds, scores them against the model
- Before inserting an alert, checks `event` table — skips if Snort already detected the same flow
- Inserts anomalies into `ml_alerts` with verdict (`HIGH_THREAT` / `MEDIUM_THREAT`) and confidence score

### PostgreSQL 15 (`mpu-network`)

- Persistent storage for all alerts
- `LISTEN/NOTIFY` triggers on `event` and `ml_alerts` tables for real-time n8n integration
- Schema initialized automatically from `database/init.sql`

### n8n (`mpu-network`)

- Two workflows running in parallel:
  - **Workflow 1:** Postgres Trigger on `event` → Code node → Telegram (Snort alerts)
  - **Workflow 2:** Postgres Trigger on `ml_alerts` → Code node → Telegram (ML alerts)
- Fires instantly on INSERT via PostgreSQL `LISTEN/NOTIFY` — no polling
- Accessible at `http://localhost:5678`

### FastAPI Backend (`mpu-network`)

- REST API reading from PostgreSQL
- Port 8000 — exposed for browser access
- Auto-generated docs at `/docs`

### React Frontend (`mpu-network`)

- Real-time dashboard polling FastAPI every 500ms
- Displays: stats cards, Snort alerts table, ML detections table, protocol distribution chart
- Port 3000

### WebGoat (`mpu-network`)

- Deliberately vulnerable Java web application — attack simulation target
- Ports 8080 and 9090

---

## Prerequisites

| Requirement    | Version          | Check Command            |
| -------------- | ---------------- | ------------------------ |
| Ubuntu Server  | 24.04 LTS        | `lsb_release -a`         |
| Docker CE      | 24.x+            | `docker --version`       |
| Docker Compose | v2.x+            | `docker compose version` |
| RAM            | 8 GB recommended | `free -h`                |
| Storage        | 40 GB minimum    | `df -h`                  |

**Attack simulation requires:**
- VirtualBox with Kali Linux VM
- Kali VM network adapter set to **Bridged** mode on `wlp4s0`

---

## Quick Start

```bash
# 1. Clone the repository
git clone https://github.com/your-username/mpu-project01.git
cd mpu-project01

# 2. Create the environment file
cp .env.example .env

# 3. Create required directories
mkdir -p snort_logs ml_engine/models

# 4. Start all services
docker compose up -d

# 5. Verify everything is running
docker compose ps

# 6. Watch ML engine training progress
docker compose logs -f ml_engine
# Wait 15 minutes — keep the network attack-free during training

# 7. After training completes, start attacking from Kali
nmap -sS <host-ip>
hping3 -2 -p 9090 --flood <host-ip>   # DDoS test — ML only, no Snort rule

# 8. Open the dashboard
# http://localhost:3000

# 9. Open n8n workflows
# http://localhost:5678

# 10. Open the API docs
# http://localhost:8000/docs
```

---

## Database Schema

```sql
CREATE SEQUENCE IF NOT EXISTS event_cid_seq START 1;

CREATE TABLE IF NOT EXISTS event (
    sid           INT NOT NULL,
    cid           INT NOT NULL DEFAULT nextval('event_cid_seq'),
    signature     TEXT,
    signature_gen INT,
    signature_id  INT,
    signature_rev INT,
    timestamp     TIMESTAMP NOT NULL,
    ip_src        INET,
    ip_dst        INET,
    layer4_sport  INT,
    layer4_dport  INT,
    ip_proto      INT,
    priority      INT,
    class_id      INT,
    notified      BOOLEAN DEFAULT FALSE,
    PRIMARY KEY (sid, cid)
);

CREATE TABLE IF NOT EXISTS signature (
    sig_id       SERIAL PRIMARY KEY,
    sig_name     TEXT,
    sig_class_id INT,
    sig_priority INT,
    sig_rev      INT,
    sig_sid      INT UNIQUE
);

CREATE TABLE IF NOT EXISTS ml_alerts (
    id            SERIAL PRIMARY KEY,
    timestamp     TIMESTAMP NOT NULL,
    src_ip        INET NOT NULL,
    dst_ip        INET NOT NULL,
    protocol      TEXT,
    anomaly_score FLOAT,
    confidence    FLOAT,
    verdict       TEXT,
    created_at    TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS statistics (
    id                 SERIAL PRIMARY KEY,
    total_snort_alerts INT DEFAULT 0,
    total_ml_alerts    INT DEFAULT 0,
    high_threats       INT DEFAULT 0,
    medium_threats     INT DEFAULT 0,
    updated_at         TIMESTAMP DEFAULT NOW()
);

-- PostgreSQL NOTIFY triggers for n8n real-time alerting
CREATE OR REPLACE FUNCTION notify_new_event()
RETURNS TRIGGER AS $$
BEGIN
  PERFORM pg_notify('event_insert', row_to_json(NEW)::text);
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE TRIGGER event_insert_trigger
AFTER INSERT ON event
FOR EACH ROW EXECUTE FUNCTION notify_new_event();

CREATE OR REPLACE FUNCTION notify_new_ml_alert()
RETURNS TRIGGER AS $$
BEGIN
  PERFORM pg_notify('ml_alert_insert', row_to_json(NEW)::text);
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE TRIGGER ml_alert_insert_trigger
AFTER INSERT ON ml_alerts
FOR EACH ROW EXECUTE FUNCTION notify_new_ml_alert();
```

---

## Environment Variables

| Variable           | Description              | Default  |
| ------------------ | ------------------------ | -------- |
| `DB_NAME`          | PostgreSQL database name | `mpu_db` |
| `DB_USER`          | PostgreSQL username       | `mpu`    |
| `DB_PASSWORD`      | PostgreSQL user password  | `123`    |
| `DB_ROOT_PASSWORD` | PostgreSQL root password  | `root`   |

> **Note:** Credentials are intentionally simple as per university project requirements.

---

## API Endpoints

| Method | Endpoint                 | Description                           |
| ------ | ------------------------ | ------------------------------------- |
| GET    | `/api/alerts/snort`      | Latest Snort alerts (default: 50)     |
| GET    | `/api/alerts/ml`         | Latest ML detections                  |
| GET    | `/api/alerts/ml/threats` | ML detections where verdict != NORMAL |
| GET    | `/api/stats/summary`     | Total alerts, high/medium counts      |
| GET    | `/api/stats/by-protocol` | Alert count grouped by protocol       |
| GET    | `/api/stats/by-priority` | Alert count grouped by priority       |
| GET    | `/api/stats/timeline`    | Alert count per hour (last 24h)       |
| GET    | `/docs`                  | Auto-generated API documentation      |

---

## ML Engine

### Training Phase

On first run, the ML engine enters training mode automatically:

```
[ML ENGINE] No model found — entering training mode
[TRAINING] Collecting normal traffic for 900 seconds...
[TRAINING] Make sure NO attacks are happening now!
[TRAINING] 10/900s — 2 flows collected
...
[TRAINING] Training Isolation Forest on 171 flows...
[TRAINING] Model saved to /app/models/model.pkl
```

The model is saved to `./ml_engine/models/model.pkl` via a Docker volume. On subsequent restarts it loads the saved model directly and skips training.

### Detection Phase

```
[DETECTION] Monitoring wlp4s0 for anomalies...
[SKIP] Already detected by Snort: 192.168.0.247 → 192.168.0.147
[ML ALERT SAVED] HIGH_THREAT | 172.20.10.2 → 172.20.10.3
```

### Flow Features

The model scores each flow using 8 features:

| Feature           | Description                          |
| ----------------- | ------------------------------------ |
| `packet_count`    | Total packets in the flow            |
| `total_bytes`     | Total bytes transferred              |
| `avg_packet_size` | Average packet size                  |
| `duration`        | Flow duration in seconds             |
| `packets_per_sec` | Packet rate                          |
| `syn_count`       | Number of SYN flags (TCP)            |
| `unique_dst_ips`  | Number of distinct destination IPs   |
| `unique_dst_ports`| Number of distinct destination ports |

### Verdict Thresholds

| Anomaly Score | Verdict        |
| ------------- | -------------- |
| < -0.3        | `HIGH_THREAT`  |
| -0.3 to 0     | `MEDIUM_THREAT`|
| > 0           | `NORMAL`       |

---

## Alerting with n8n

Two independent workflows run in parallel:

### Workflow 1 — Snort Alerts

```
Postgres Trigger (channel: event_insert)
        → Code node (formats Snort alert message)
        → Telegram node
```

Sample message:
```
🚨 NIDS Alert
Source: 🛡️ Snort
Type: Nmap SYN Scan Detected
Severity: Low
Src IP: 192.168.0.247
Dst IP: 192.168.0.147
Ports: 54321 → 8080
Time: 2026-04-21T11:05:30
```

### Workflow 2 — ML Alerts

```
Postgres Trigger (channel: ml_alert_insert)
        → Code node (formats ML detection message)
        → Telegram node
```

Sample message:
```
🤖 ML Detection
Verdict: 🔴 HIGH
Src IP: 172.20.10.2
Dst IP: 172.20.10.3
Protocol: UDP
Confidence: 75.1%
Score: -0.715
Time: 2026-04-21T11:05:38
```

Both workflows fire instantly via PostgreSQL `LISTEN/NOTIFY` — no polling interval.

---

## Security Notes

- Snort and ML engine run with `privileged: true` and `network_mode: host` — required for packet capture
- PostgreSQL port 5432 is never exposed outside the Docker network
- `.env` is excluded from git via `.gitignore`
- WebGoat is intentionally vulnerable — do not expose it to public networks
- Run this system on an isolated lab network or VM environment only

---

## Roadmap

**Semester 1 — Completed**
- [x] Snort 3 containerized with host network access
- [x] alerts_watcher Python service writing to PostgreSQL
- [x] FastAPI backend with alert and stats endpoints
- [x] React dashboard with live data refresh
- [x] WebGoat as attack simulation target
- [x] ML Engine — Isolation Forest anomaly detection
- [x] Two-layer detection (Snort + ML with deduplication)
- [x] Real-time Telegram alerting via n8n
- [x] PostgreSQL LISTEN/NOTIFY triggers for instant notifications

**Semester 2 — Planned**
- [ ] Cloud deployment on Azure AKS or AWS EKS
- [ ] Infrastructure as Code with Terraform
- [ ] CI/CD pipeline with GitHub Actions
- [ ] Monitoring with Prometheus and Grafana

---

## Authors

| Name               | Role       |
| ------------------ | ---------- |
| Jad Issa           | CS Student |
| Abdulkader Motraji | CS Student |

---

## License

This project is licensed under the MIT License.
