# NIDS — Network Intrusion Detection System

Graduation Project — Security Engineering · DevOps

![Ubuntu](https://img.shields.io/badge/Ubuntu-24.04_LTS-E95420?style=flat&logo=ubuntu&logoColor=white)
![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?style=flat&logo=docker&logoColor=white)
![Python](https://img.shields.io/badge/Python-3.11-3776AB?style=flat&logo=python&logoColor=white)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-15-336791?style=flat&logo=postgresql&logoColor=white)
![Snort](https://img.shields.io/badge/Snort-3.x-FF0000?style=flat)
![React](https://img.shields.io/badge/React-18-61DAFB?style=flat&logo=react&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-0.110-009688?style=flat&logo=fastapi&logoColor=white)
![Nginx](https://img.shields.io/badge/Nginx-Reverse_Proxy-009639?style=flat&logo=nginx&logoColor=white)
![n8n](https://img.shields.io/badge/n8n-latest-EA4B71?style=flat&logo=n8n&logoColor=white)
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
- [Nginx Configuration](#nginx-configuration)
- [Database Schema](#database-schema)
- [Environment Variables](#environment-variables)
- [API Endpoints](#api-endpoints)
- [Telegram Alerting with n8n](#telegram-alerting-with-n8n)
- [Security Notes](#security-notes)
- [Roadmap](#roadmap)
- [Authors](#authors)

---

## Overview

A full-stack Network Intrusion Detection System developed as a graduation project. The system uses **Snort 3** for signature-based detection, a custom **alerts_watcher** service to persist alerts into **PostgreSQL**, a **FastAPI** backend, a **React** dashboard for real-time monitoring, **Nginx** as a reverse proxy in front of the frontend, backend, and n8n, and **n8n** for automated Telegram alerting.

**WebGoat** runs as a deliberately vulnerable target application. Attacks are simulated from **Kali Linux** running in VirtualBox with a Bridged network adapter.

---

## Architecture

```
Host Machine (Ubuntu 24.04 LTS)
          |
          | Raw network traffic (host NIC)
          |
          v
+----------------------+
|   Snort 3            |
|   network_mode: host |
|   Signature-based    |
|   detection          |
|   --> alert_json.txt |
+----------+-----------+
           |
           | shared volume (snort_logs/)
           v
+------------------------------------------------------------+
|   Docker Compose Network (mpu-network 172.28.0.0/16)       |
|                                                              |
|   +--------------------------------------------------+       |
|   |   alerts_watcher        172.28.0.101             |       |
|   |   Tails alert_json.txt  -->  PostgreSQL           |       |
|   +--------------------------------------------------+       |
|                                                              |
|   +------------------+                                       |
|   |   PostgreSQL 15  |  172.28.0.105                         |
|   |   event table    |                                       |
|   |   NOTIFY trigger |                                       |
|   +--------+---------+                                       |
|            |                                                 |
|            | LISTEN/NOTIFY (channel: new_event)              |
|            v                                                 |
|   +------------------+                                       |
|   |   n8n            |  172.28.0.100  :5678                  |
|   |   Telegram alerts|                                       |
|   +--------+---------+                                       |
|            ^                                                 |
|            |                                                 |
|   +--------+------------------+                              |
|   |   FastAPI Backend         |  172.28.0.103  :8000         |
|   +--------+------------------+                              |
|            ^                                                 |
|            |                                                 |
|   +--------+------------------+                              |
|   |   React Frontend          |  172.28.0.102  :80           |
|   +--------+------------------+                              |
|            ^                                                 |
|            |  reverse proxy routes: / , /api/ , /n8n/        |
|   +--------+------------------+                              |
|   |   Nginx (reverse proxy)   |  172.28.0.106  :80           |
|   |   /       --> frontend:80                                |
|   |   /api/   --> backend:8000/api/                          |
|   |   /n8n/   --> n8n:5678/ (WebSocket upgrade)               |
|   +----------------------------+                              |
|                                                              |
|   +--------------------------------------------------+       |
|   |   WebGoat               172.28.0.104  :8080/:9090 |       |
|   +--------------------------------------------------+       |
+------------------------------------------------------------+

Attack Simulation:
  Kali Linux (VirtualBox, Bridged) --> attacks --> Host / WebGoat
  Snort detects attacks --> event table --> Dashboard + Telegram

Client access (single entry point):
  Browser --> Nginx (:80) --> React Frontend / FastAPI Backend / n8n
```

---

## Why This Design

### Why Snort with `network_mode: host`?

Snort needs direct access to the physical network interface to capture packets before any Docker NAT or bridge processing occurs. `network_mode: host` gives the container full visibility over the host NIC while every other service remains isolated inside the bridge network.

### Why a custom `alerts_watcher` instead of a database output plugin?

Snort 3 writes alerts as newline-delimited JSON to `alert_json.txt`. The `alerts_watcher` service tails that file from the last known position, parses each JSON line, and writes structured rows to PostgreSQL. This keeps Snort fully decoupled from the database — Snort never waits on a database write, and the watcher can be restarted independently without dropping alerts.

### Why n8n for alerting instead of custom code?

n8n listens to PostgreSQL's native `LISTEN/NOTIFY` channel, which means notifications fire the moment a row is inserted — no polling delay. The visual workflow editor also makes it straightforward to extend alerting to other channels (Slack, email, webhooks) without modifying application code.

### Why PostgreSQL?

PostgreSQL's native `INET` type stores IP addresses cleanly and efficiently. The `LISTEN/NOTIFY` mechanism enables real-time push notifications to n8n without any polling overhead. The fixed subnet (`172.28.0.0/16`) with static IPs for each service ensures predictable inter-container communication.

### Why Nginx as a reverse proxy?

Nginx exposes a single public entry point on port 80 and routes requests by path: `/` to the React frontend, `/api/` to the FastAPI backend, and `/n8n/` to the n8n editor — with WebSocket upgrade headers enabled so n8n's real-time UI keeps working behind the proxy. Every other internal service (PostgreSQL, alerts_watcher) stays unreachable from outside the Docker network, centralizing routing, simplifying future TLS termination, and minimizing the attack surface of the dashboard layer.

---

## Project Structure

```
mpu-project01/
├── docker-compose.yml
├── init.sql                      # Schema — runs automatically on first PostgreSQL start
├── .env                          # NOT in git
├── .gitignore
├── README.md
├── Dockerfile.watcher            # alerts_watcher container image
├── alerts_watcher.py             # Tails alert_json.txt and writes to PostgreSQL
│
├── snort/
│   ├── snort.lua                 # Snort 3 configuration
│   ├── entrypoint.sh             # Snort startup script
│   └── rules/
│       └── local.rules
│
├── snort_logs/                   # Shared volume: Snort writes, alerts_watcher reads
│   └── alert_json.txt
│
├── n8n_data/                     # n8n persistent workflow storage
│
├── nginx/
│   ├── nginx.conf                # Reverse proxy configuration (/, /api/, /n8n/)
│   └── Dockerfile
│
└── dashboard/
    ├── backend/
    │   ├── Dockerfile
    │   ├── requirements.txt
    │   ├── main.py
    │   ├── database.py
    │   └── routes/
    │       ├── alerts.py         # /api/alerts/snort
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
                └── ProtocolChart.js
```

---

## Components

### Snort 3 (`ciscotalos/snort3` — `network_mode: host`)

- Signature-based detection engine using rules from `snort/rules/local.rules`
- Runs with `network_mode: host` and `privileged: true` for direct NIC access
- On rule match: appends a JSON object to `snort_logs/alert_json.txt`
- Has no database dependency — writes only to the shared volume

### alerts_watcher (Python — `172.28.0.101`)

- Tails `alert_json.txt` using a persistent file position cursor (survives restarts)
- Writes one row to `signature` and one row to `event` per alert
- Polls every 1 second with `restart: unless-stopped`

### PostgreSQL 15 (`172.28.0.105`)

- Persistent storage for all alerts via the `event` and `signature` tables
- `LISTEN/NOTIFY` trigger on the `event` table fires instantly on every INSERT
- Schema initialized automatically from `init.sql` on first start
- Port 5432 exposed on the host for local development access

### n8n (`172.28.0.100` — internal port `5678`)

- Workflow automation engine connected to PostgreSQL via `LISTEN/NOTIFY`
- Listens on the `new_event` notification channel
- On each new alert: formats a structured message and delivers it to a Telegram bot
- Reachable through Nginx at `/n8n/`, with WebSocket upgrade support for the live editor UI
- Workflow state persisted in `./n8n_data`

### FastAPI Backend (`172.28.0.103` — internal port `8000`)

- REST API reading from PostgreSQL
- Reachable through Nginx at `/api/`
- Auto-generated interactive docs at `/api/docs`

### React Frontend (`172.28.0.102` — internal port `80`)

- Real-time dashboard polling FastAPI every 500ms
- Displays: stats cards, Snort alerts table, protocol distribution chart
- Served internally on port 80, reachable through Nginx at `/`

### Nginx (`172.28.0.106` — port `80`)

- Reverse proxy and single public entry point for the whole dashboard stack
- `location /` → `proxy_pass http://frontend:80`
- `location /api/` → `proxy_pass http://backend:8000/api/`
- `location /n8n/` → `proxy_pass http://n8n:5678/`, with `Upgrade`/`Connection` headers and `proxy_buffering off` for n8n's WebSocket-based editor
- Forwards `Host`, `X-Real-IP`, and `X-Forwarded-For` headers to preserve client info upstream

### WebGoat (`172.28.0.104`)

- Deliberately vulnerable Java web application used as the attack target
- Ports 8080 and 9090

---

## Prerequisites

| Requirement    | Version   | Check Command            |
| -------------- | --------- | ------------------------ |
| Ubuntu         | 24.04 LTS | `lsb_release -a`         |
| Docker CE      | 24.x+     | `docker --version`       |
| Docker Compose | v2.x+     | `docker compose version` |
| RAM            | 8 GB+     | `free -h`                |
| Storage        | 20 GB+    | `df -h`                  |

Attack simulation requires a VirtualBox Kali Linux VM with the network adapter set to **Bridged** mode on the host NIC.

---

## Quick Start

```bash
# 1. Clone the repository
git clone https://github.com/your-username/mpu-project01.git
cd mpu-project01

# 2. Create the environment file
cp .env.example .env

# 3. Create required directories
mkdir -p snort_logs n8n_data

# 4. Start all services
docker compose up -d

# 5. Verify all containers are running
docker compose ps

# 6. Simulate attacks from Kali Linux
nmap -sS <host-ip>
nikto -h http://<host-ip>:8080

# 7. Open the dashboard (through Nginx)
# http://localhost

# 8. Open n8n (through Nginx)
# http://localhost/n8n/

# 9. Open API docs (through Nginx)
# http://localhost/api/docs
```

---

## Nginx Configuration

`nginx/nginx.conf`:

```nginx
server {
    listen 80;
    server_name localhost;

    location / {
        proxy_pass http://frontend:80;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }

    location /api/ {
        proxy_pass http://backend:8000/api/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }

    location /n8n/ {
        proxy_pass http://n8n:5678/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_buffering off;
        proxy_cache_bypass $http_upgrade;
    }
}
```

- `proxy_pass` targets use Docker Compose service names (`frontend`, `backend`, `n8n`) rather than static IPs, relying on Docker's internal DNS.
- The `/n8n/` block adds `proxy_http_version 1.1` plus the `Upgrade`/`Connection` headers and disables buffering — required for n8n's editor, which relies on WebSockets for live workflow updates.
- `X-Real-IP` and `X-Forwarded-For` are forwarded on `/` and `/n8n/` so upstream services can see the real client IP instead of Nginx's.

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

-- PostgreSQL NOTIFY trigger for n8n real-time alerting
CREATE OR REPLACE FUNCTION notify_new_event()
RETURNS TRIGGER AS $$
BEGIN
  PERFORM pg_notify('new_event', row_to_json(NEW)::text);
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE TRIGGER event_insert_trigger
AFTER INSERT ON event
FOR EACH ROW EXECUTE FUNCTION notify_new_event();
```

---

## Environment Variables

| Variable           | Description              | Default  |
| ------------------ | ------------------------ | -------- |
| `DB_NAME`          | PostgreSQL database name | `mpu_db` |
| `DB_USER`          | PostgreSQL username      | `mpu`    |
| `DB_PASSWORD`      | PostgreSQL user password | `123`    |
| `DB_ROOT_PASSWORD` | PostgreSQL root password | `root`   |

> Credentials are intentionally simple as per university project requirements.

---

## API Endpoints

All endpoints are reachable through Nginx under `/api/`.

| Method | Endpoint                 | Description                          |
| ------ | ------------------------ | ------------------------------------ |
| GET    | `/api/alerts/snort`      | Latest Snort alerts (default: 50)    |
| GET    | `/api/stats/summary`     | Total alert count and breakdown      |
| GET    | `/api/stats/by-protocol` | Alert count grouped by protocol      |
| GET    | `/api/stats/by-priority` | Alert count grouped by priority      |
| GET    | `/api/stats/timeline`    | Alert count per hour (last 24 hours) |
| GET    | `/api/docs`              | Auto-generated API documentation     |

---

## Telegram Alerting with n8n

n8n connects to PostgreSQL and listens on the `new_event` notification channel. When Snort detects an attack and `alerts_watcher` inserts a row into the `event` table, the PostgreSQL trigger fires a `NOTIFY` call, and n8n immediately delivers a formatted message to the configured Telegram bot — no polling involved.

The workflow:

```
Postgres Trigger (channel: new_event)
        --> Code node (formats alert message)
        --> Telegram node (sends to bot)
```

Sample message:

```
NIDS Alert
Source: Snort
Type: Nmap SYN Scan Detected
Severity: Low
Src IP: 192.168.0.10
Dst IP: 192.168.0.147
Ports: 54321 -> 8080
Time: 2026-04-21 11:05:30
```

n8n's editor is accessible through Nginx at `http://localhost/n8n/`. Workflow state is persisted in `./n8n_data` so workflows survive container restarts.

---

## Security Notes

- Snort runs with `privileged: true` and `network_mode: host` — required for raw packet capture
- Nginx is the only service exposed on the host beyond what's needed for development; all other internal services (frontend, backend, n8n) are reached only through the reverse proxy
- PostgreSQL port 5432 is exposed on the host for development convenience only; restrict it in production
- `.env` is excluded from version control via `.gitignore`
- WebGoat is deliberately vulnerable — never expose it on a public or production network
- Run this system on an isolated lab network only

---

## Roadmap

**Semester 1 — Completed**

- [x] Snort 3 containerized with host network access
- [x] alerts_watcher service writing Snort alerts to PostgreSQL
- [x] FastAPI backend with alert and stats endpoints
- [x] React dashboard with live data refresh
- [x] Nginx reverse proxy routing to frontend, backend, and n8n
- [x] WebGoat as attack simulation target
- [x] Real-time Telegram alerting via n8n and PostgreSQL NOTIFY

---

## License

This project is licensed under the MIT License.
