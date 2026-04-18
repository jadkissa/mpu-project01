# Snort IDS — Network Intrusion Detection System

Graduation Project — Security Engineering · DevOps

![Ubuntu](https://img.shields.io/badge/Ubuntu-24.04_LTS-E95420?style=flat&logo=ubuntu&logoColor=white)
![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?style=flat&logo=docker&logoColor=white)
![Python](https://img.shields.io/badge/Python-3.11-3776AB?style=flat&logo=python&logoColor=white)
![MariaDB](https://img.shields.io/badge/MariaDB-10.x-003545?style=flat&logo=mariadb&logoColor=white)
![Snort](https://img.shields.io/badge/Snort-2.9-FF0000?style=flat)
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

A full-stack Network Intrusion Detection System developed as a graduation project. The system uses **Snort 2.9** as the signature-based detection engine, with **Barnyard2** acting as the middleware that reads Snort's unified2 binary output and writes structured alerts into **MariaDB**. A **FastAPI** backend exposes the alert data to a **React** dashboard for real-time monitoring.

**WebGoat** runs as a deliberately vulnerable target application. Attacks are simulated from **Kali Linux** running in VirtualBox on the host machine.

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
|   Snort 2.9  (network_mode: host, privileged)            |
|   Reads packets directly from host interface             |
|   Outputs: unified2 binary log (/var/log/snort)          |
+---------------------------+------------------------------+
                            | shared volume (snort_logs)
                            v
+----------------------------------------------------------+
|   Docker Compose Network (mpu-network bridge)            |
|                                                          |
|   +--------------------------------------------------+   |
|   |   Barnyard2                                       |   |
|   |   Reads unified2 logs from shared volume          |   |
|   |   Writes structured alerts --> MariaDB            |   |
|   +--------------------------------------------------+   |
|                                                          |
|   +------------------+    +-------------------------+    |
|   |   MariaDB        |    |   WebGoat (attack target)|   |
|   |   :3306 internal |    |   :8080 / :9090          |   |
|   +--------+---------+    +-------------------------+    |
|            |                                             |
|   +--------v---------+    +-------------------------+    |
|   |   FastAPI        |    |   React Frontend        |    |
|   |   :8000          +<-->+   :3000                 |    |
|   +------------------+    +-------------------------+    |
+----------------------------------------------------------+

Attack Simulation:
  Kali Linux (VirtualBox) --> attacks --> WebGoat
                          --> Snort detects --> Barnyard2 --> MariaDB --> Dashboard
```

---

## Why This Design

### Why Snort with `network_mode: host`?

Snort needs direct access to the physical network interface to capture every packet before any routing or NAT processing happens. Running it inside a Docker bridge network would make it invisible to host-level traffic. `network_mode: host` gives the container full visibility over the host NIC while keeping the rest of the stack isolated inside the bridge network.

### Why Snort 2.9 and not Snort 3?

Barnyard2 has native, stable support for Snort 2.9's `unified2` output format. Snort 3 uses a different output pipeline that requires additional configuration to work with Barnyard2. For a graduation project focused on reliability and a clean integration story, Snort 2.9 is the correct choice.

### Why Barnyard2?

Barnyard2 is the standard middleware between Snort and a database backend. Snort writes fast binary `unified2` logs to disk and continues processing packets without waiting for a database write. Barnyard2 handles the slower database insertion asynchronously. This keeps Snort's performance high even under heavy traffic.

### Why MariaDB instead of PostgreSQL?

Barnyard2's native database output plugin (`output database`) was built for MySQL/MariaDB. Using MariaDB eliminates the need for additional compatibility layers or custom plugins, keeping the pipeline straightforward and well-documented.

### Why WebGoat as the attack target?

WebGoat is a purpose-built vulnerable application designed for security testing. It provides realistic, documented attack surfaces (SQL injection, XSS, CSRF, etc.) that generate meaningful Snort alerts without the legal and ethical complexity of targeting real systems.

---

## Project Structure

```
mpu-project01/
├── docker-compose.yml
├── .env                          # NOT in git
├── .env.example
├── .gitignore
├── README.md
│
├── database/
│   └── init.sql                  # Schema — runs automatically on first MariaDB start
│
├── snort/                        # Snort config (container uses network_mode: host)
│   ├── snort.conf
│   └── rules/
│       └── local.rules
│
├── barnyard2/
│   └── barnyard2.conf            # Barnyard2 config — points to MariaDB
│
├── snort_logs/                   # Shared volume between Snort and Barnyard2
│   └── (unified2 binary logs written here by Snort, read by Barnyard2)
│
└── dashboard/
    ├── backend/
    │   ├── Dockerfile
    │   ├── requirements.txt
    │   ├── main.py               # FastAPI app entrypoint
    │   ├── database.py           # MariaDB connection and query helper
    │   └── routes/
    │       ├── alerts.py         # /api/alerts/snort
    │       └── stats.py          # /api/stats/*
    └── frontend/
        ├── Dockerfile
        └── src/
            ├── App.js
            ├── api/
            │   └── index.js      # Axios calls to FastAPI
            └── components/
                ├── StatsCards.js
                ├── SnortAlerts.js
                └── ProtocolChart.js
```

---

## Components

### Snort 2.9 (Docker container — `network_mode: host`)

- Runs with `network_mode: host` and `privileged: true` to access the host NIC directly
- Signature-based detection engine — applies rules from `snort/rules/local.rules`
- On match: writes alert to `unified2` binary log file in the shared `snort_logs` volume
- Does not write to the database directly — that is Barnyard2's job

### Barnyard2 (Docker container — `mpu-network`)

- Reads Snort's `unified2` output from the shared `snort_logs` volume
- Parses binary alerts and writes structured records to MariaDB
- Acts as a buffer: Snort stays fast, Barnyard2 handles the slower DB writes
- Reconnects automatically if MariaDB is temporarily unavailable

### MariaDB (Docker container — `mpu-network`)

- Persistent storage for all Snort alerts
- Port 3306 — internal only, never exposed outside the Docker network
- Schema initialized automatically from `database/init.sql` on first start
- Volume: `db_data:/var/lib/mysql`

### FastAPI Backend (Docker container — `mpu-network`)

- REST API that reads alerts from MariaDB and serves them to the React frontend
- Port 8000 — exposed for browser access
- Auto-generated documentation at `/docs`
- Connects to MariaDB using `pymysql`

### React Frontend (Docker container — `mpu-network`)

- Real-time dashboard that polls the FastAPI backend every 30 seconds
- Port 3000 — accessible from browser
- Displays: stats cards, Snort alerts table, protocol distribution chart

### WebGoat (Docker container — `mpu-network`)

- Deliberately vulnerable Java web application
- Serves as the attack target for Kali Linux simulations
- Port 8080 / 9090

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

# 6. Check Snort logs
docker compose logs snort

# 7. Check Barnyard2 is writing to MariaDB
docker compose logs barnyard2

# 8. Open the dashboard
# http://localhost:3000

# 9. Open the API docs
# http://localhost:8000/docs
```

---

## Database Schema

The schema is initialized automatically from `database/init.sql` when MariaDB starts for the first time. It follows the standard Barnyard2 schema with an additional `statistics` table for the dashboard.

```sql
-- Barnyard2 standard tables
CREATE TABLE IF NOT EXISTS event (
    sid           INT UNSIGNED NOT NULL,
    cid           INT UNSIGNED NOT NULL,
    signature     INT UNSIGNED NOT NULL,
    timestamp     DATETIME NOT NULL,
    PRIMARY KEY (sid, cid)
);

CREATE TABLE IF NOT EXISTS signature (
    sig_id        INT UNSIGNED NOT NULL AUTO_INCREMENT,
    sig_name      TEXT NOT NULL,
    sig_class_id  INT UNSIGNED,
    sig_priority  INT UNSIGNED,
    sig_rev       INT UNSIGNED,
    sig_sid       INT UNSIGNED,
    sig_gid       INT UNSIGNED,
    PRIMARY KEY (sig_id)
);

CREATE TABLE IF NOT EXISTS iphdr (
    sid           INT UNSIGNED NOT NULL,
    cid           INT UNSIGNED NOT NULL,
    ip_src        INT UNSIGNED NOT NULL,
    ip_dst        INT UNSIGNED NOT NULL,
    ip_proto      TINYINT UNSIGNED NOT NULL,
    PRIMARY KEY (sid, cid)
);

CREATE TABLE IF NOT EXISTS tcphdr (
    sid           INT UNSIGNED NOT NULL,
    cid           INT UNSIGNED NOT NULL,
    tcp_sport     SMALLINT UNSIGNED NOT NULL,
    tcp_dport     SMALLINT UNSIGNED NOT NULL,
    PRIMARY KEY (sid, cid)
);

-- Dashboard statistics table
CREATE TABLE IF NOT EXISTS statistics (
    id                 INT UNSIGNED NOT NULL AUTO_INCREMENT,
    total_snort_alerts INT UNSIGNED DEFAULT 0,
    high_threats       INT UNSIGNED DEFAULT 0,
    medium_threats     INT UNSIGNED DEFAULT 0,
    updated_at         DATETIME DEFAULT NOW(),
    PRIMARY KEY (id)
);
```

---

## Environment Variables

| Variable          | Description          | Default  |
| ----------------- | -------------------- | -------- |
| `DB_NAME`         | MariaDB database name | `mpu_db` |
| `DB_USER`         | MariaDB username      | `mpu`    |
| `DB_PASSWORD`     | MariaDB user password | `123`    |
| `DB_ROOT_PASSWORD`| MariaDB root password | `root`   |

Copy `.env.example` to `.env`. Never commit `.env` to git.

> **Note:** These credentials are intentionally simple as per university project requirements.

---

## API Endpoints

| Method | Endpoint                  | Description                        |
| ------ | ------------------------- | ---------------------------------- |
| GET    | `/api/alerts/snort`       | Latest Snort alerts (default: 50)  |
| GET    | `/api/stats/summary`      | Total alerts, high/medium counts   |
| GET    | `/api/stats/by-protocol`  | Alert count grouped by protocol    |
| GET    | `/api/stats/by-priority`  | Alert count grouped by priority    |
| GET    | `/api/stats/timeline`     | Alert count per hour (last 24h)    |
| GET    | `/docs`                   | Auto-generated API documentation   |

---

## Security Notes

- Snort runs with `privileged: true` and `network_mode: host` — required for packet capture
- MariaDB port 3306 is never exposed outside the Docker network
- `.env` is excluded from git via `.gitignore`
- WebGoat is intentionally vulnerable — do not expose it to public networks
- Run this system on an isolated lab network or VM environment only

---

## Roadmap

**Semester 1 — Current**
- [x] Snort 2.9 containerized with host network access
- [x] Barnyard2 middleware writing to MariaDB
- [x] FastAPI backend with alert and stats endpoints
- [x] React dashboard with live data refresh
- [x] WebGoat as attack simulation target
- [ ] Full end-to-end integration test with Kali Linux attack scenarios

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
