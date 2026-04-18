# Snort IDS — AI-Powered Network Intrusion Detection System

Graduation Project — Security Engineering · DevOps

![Ubuntu](https://img.shields.io/badge/Ubuntu-24.04_LTS-E95420?style=flat&logo=ubuntu&logoColor=white)
![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?style=flat&logo=docker&logoColor=white)
![Python](https://img.shields.io/badge/Python-3.11-3776AB?style=flat&logo=python&logoColor=white)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-15-336791?style=flat&logo=postgresql&logoColor=white)
![Snort](https://img.shields.io/badge/Snort-3.x-FF0000?style=flat)
![React](https://img.shields.io/badge/React-18-61DAFB?style=flat&logo=react&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-0.110-009688?style=flat&logo=fastapi&logoColor=white)
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
- [Security Notes](#security-notes)
- [Roadmap](#roadmap)
- [Authors](#authors)

---

## Overview

A full-stack Network Intrusion Detection System developed as a two-semester graduation project. Semester 1 delivers a working detection and monitoring stack. Semester 2 will add a machine learning layer for anomaly detection.

The system uses **Snort 3** (`ciscotalos/snort3`) as the signature-based detection engine running with host network access. A custom **alerts_watcher** Python service tails Snort's JSON alert output and writes structured events into **PostgreSQL**. A **FastAPI** backend exposes that data to a **React** dashboard for real-time monitoring.

**WebGoat** runs as a deliberately vulnerable target application. Attacks are simulated from **Kali Linux** in VirtualBox on the host machine.

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
          | Raw network traffic (host NIC)
          v
+----------------------------------------------------------+
|   Snort 3  (network_mode: host, privileged)              |
|   Image: ciscotalos/snort3                               |
|   Reads packets directly from host interface             |
|   Writes: alert_json.txt --> /var/log/snort              |
+---------------------------+------------------------------+
                            | shared volume (snort_logs)
                            v
+----------------------------------------------------------+
|   Docker Compose Network (mpu-network bridge)            |
|                                                          |
|   +--------------------------------------------------+   |
|   |   alerts_watcher (Python)                         |   |
|   |   Tails alert_json.txt from shared volume         |   |
|   |   Parses JSON alerts --> writes to PostgreSQL     |   |
|   +--------------------------------------------------+   |
|                                                          |
|   +------------------+    +-------------------------+    |
|   |   PostgreSQL     |    |   WebGoat               |    |
|   |   :5432 internal |    |   :8080 / :9090         |    |
|   +--------+---------+    +-------------------------+    |
|            |                                             |
|   +--------v---------+    +-------------------------+    |
|   |   FastAPI        |    |   React Frontend        |    |
|   |   :8000          +<-->+   :3000                 |    |
|   +------------------+    +-------------------------+    |
+----------------------------------------------------------+

Attack Simulation:
  Kali Linux (VirtualBox) --> attacks --> WebGoat
                          --> Snort detects --> alert_json.txt
                          --> alerts_watcher --> PostgreSQL --> Dashboard
```

---

## Why This Design

### Why Snort with `network_mode: host`?

Snort needs direct access to the physical network interface to capture packets before any Docker NAT or bridge processing happens. Running it inside `mpu-network` would hide host-level traffic from it. `network_mode: host` gives the container full visibility over the host NIC while keeping every other service isolated inside the bridge network.

### Why a custom `alerts_watcher` instead of a database plugin?

Snort 3 writes alerts as newline-delimited JSON to `alert_json.txt`. The `alerts_watcher` service tails that file from the last known position, parses each JSON line, and writes structured rows to PostgreSQL. This keeps Snort fully decoupled from the database — Snort never waits on a DB write, and the watcher can be restarted independently without losing alerts (it resumes from where it left off using a file position cursor).

### Why PostgreSQL?

PostgreSQL's native `INET` type stores IP addresses cleanly without casting hacks. The schema uses sequences, conflict handling, and timestamp casting that map naturally onto PostgreSQL features. It also gives the ML layer (Semester 2) a solid foundation for querying traffic patterns.

### Why WebGoat as the attack target?

WebGoat is a purpose-built vulnerable application with documented attack surfaces (SQL injection, XSS, CSRF, and more). It generates realistic, repeatable traffic that produces meaningful Snort alerts without any legal or ethical complexity.

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
├── database/
│   └── init.sql                  # Schema — runs automatically on first PostgreSQL start
│
├── snort/
│   ├── snort.lua                 # Snort 3 configuration
│   └── rules/
│       └── local.rules
│
├── snort_logs/                   # Shared volume: Snort writes here, alerts_watcher reads here
│   └── alert_json.txt
│
└── dashboard/
    ├── backend/
    │   ├── Dockerfile
    │   ├── requirements.txt
    │   ├── main.py               # FastAPI app entrypoint
    │   ├── database.py           # PostgreSQL connection and query helper
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

- Runs with `network_mode: host` and `privileged: true` to access the host NIC directly
- Signature-based detection engine using rules from `snort/rules/local.rules`
- Config: `snort/snort.lua`
- On rule match: appends a JSON object to `snort_logs/alert_json.txt`
- Has no database dependency — writes only to the shared volume

### alerts_watcher (Python — `mpu-network`)

- Tails `alert_json.txt` using a file position cursor (survives restarts)
- Parses each JSON line and extracts: `sid`, `gid`, `rev`, `msg`, `priority`, `proto`, `src_addr`, `dst_addr`, `src_port`, `dst_port`, `timestamp`
- Writes one row to `signature` and one row to `event` per alert
- Updates the `statistics` table counters (`total_snort_alerts`, `high_threats`, `medium_threats`) on every insert
- Polls every 1 second with `restart: unless-stopped`

### PostgreSQL 15 (`mpu-network`)

- Persistent storage for Snort alerts and (future) ML detections
- Port 5432 — internal only, never exposed outside the Docker network
- Schema initialized automatically from `database/init.sql` on first start
- Volume: `db_data:/var/lib/postgresql/data`

### FastAPI Backend (`mpu-network`)

- REST API that reads from PostgreSQL and serves the React frontend
- Port 8000 — exposed for browser access
- Auto-generated API documentation at `/docs`

### React Frontend (`mpu-network`)

- Real-time dashboard polling FastAPI every 30 seconds
- Port 3000 — accessible from browser
- Displays: stats cards, Snort alerts table, ML detections table (Semester 2), protocol distribution chart

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

---

## Quick Start

```bash
# 1. Clone the repository
git clone https://github.com/your-username/mpu-project01.git
cd mpu-project01

# 2. Create the environment file
cp .env.example .env

# 3. Create the shared log directory
mkdir -p snort_logs

# 4. Start all services
docker compose up -d

# 5. Verify everything is running
docker compose ps

# 6. Tail Snort alerts in real time
docker compose logs -f snort

# 7. Watch alerts_watcher insert events
docker compose logs -f alerts_watcher

# 8. Open the dashboard
# http://localhost:3000

# 9. Open the API docs
# http://localhost:8000/docs
```

---

## Database Schema

Initialized automatically from `database/init.sql` on first PostgreSQL start.

```sql
-- Auto-incrementing counter for event IDs
CREATE SEQUENCE IF NOT EXISTS event_cid_seq START 1;

-- One row per detected event
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
    PRIMARY KEY (sid, cid)
);

-- One row per unique Snort rule that has fired
CREATE TABLE IF NOT EXISTS signature (
    sig_id       SERIAL PRIMARY KEY,
    sig_name     TEXT,
    sig_class_id INT,
    sig_priority INT,
    sig_rev      INT,
    sig_sid      INT UNIQUE
);

-- Reserved for ML anomaly detections (Semester 2)
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

-- Aggregated counters for the dashboard stats cards
CREATE TABLE IF NOT EXISTS statistics (
    id                 SERIAL PRIMARY KEY,
    total_snort_alerts INT DEFAULT 0,
    total_ml_alerts    INT DEFAULT 0,
    high_threats       INT DEFAULT 0,
    medium_threats     INT DEFAULT 0,
    updated_at         TIMESTAMP DEFAULT NOW()
);
```

---

## Environment Variables

| Variable           | Description              | Default  |
| ------------------ | ------------------------ | -------- |
| `DB_NAME`          | PostgreSQL database name | `mpu_db` |
| `DB_USER`          | PostgreSQL username      | `mpu`    |
| `DB_PASSWORD`      | PostgreSQL user password | `123`    |
| `DB_ROOT_PASSWORD` | PostgreSQL root password | `root`   |

Copy `.env.example` to `.env`. Never commit `.env` to git.

> **Note:** Credentials are intentionally simple as per university project requirements.

---

## API Endpoints

| Method | Endpoint                 | Description                           |
| ------ | ------------------------ | ------------------------------------- |
| GET    | `/api/alerts/snort`      | Latest Snort alerts (default: 50)     |
| GET    | `/api/alerts/ml`         | Latest ML detections (Semester 2)     |
| GET    | `/api/alerts/ml/threats` | ML detections where verdict != normal |
| GET    | `/api/stats/summary`     | Total alerts, high/medium counts      |
| GET    | `/api/stats/by-protocol` | Alert count grouped by protocol       |
| GET    | `/api/stats/by-priority` | Alert count grouped by priority       |
| GET    | `/api/stats/timeline`    | Alert count per hour (last 24h)       |
| GET    | `/docs`                  | Auto-generated API documentation      |

---

## Security Notes

- Snort runs with `privileged: true` and `network_mode: host` — required for packet capture
- PostgreSQL port 5432 is never exposed outside the Docker network
- `.env` is excluded from git via `.gitignore`
- WebGoat is intentionally vulnerable — do not expose it to public networks
- Run this system on an isolated lab network or VM environment only

---

## Roadmap

**Semester 1 — Current**
- [x] Snort 3 containerized with host network access
- [x] alerts_watcher Python service writing to PostgreSQL
- [x] FastAPI backend with alert and stats endpoints
- [x] React dashboard with live data refresh
- [x] WebGoat as attack simulation target
- [ ] End-to-end integration test with Kali Linux attack scenarios

**Semester 2 — Planned**
- [ ] ML anomaly detection layer (Isolation Forest + Random Forest on UNSW-NB15)
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