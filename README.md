# 🛡️ AI-Powered Network Intrusion Detection System (NIDS)

> Graduation Project — Security Engineering · Machine Learning · DevOps

![Ubuntu](https://img.shields.io/badge/Ubuntu-22.04_LTS-E95420?style=flat&logo=ubuntu&logoColor=white)
![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?style=flat&logo=docker&logoColor=white)
![Python](https://img.shields.io/badge/Python-3.11-3776AB?style=flat&logo=python&logoColor=white)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-15-336791?style=flat&logo=postgresql&logoColor=white)
![Snort](https://img.shields.io/badge/Snort-IDS-FF0000?style=flat)
![License](https://img.shields.io/badge/License-MIT-green?style=flat)

---

## 📋 Table of Contents

- [Overview](#-overview)
- [Architecture](#-architecture)
- [Project Structure](#-project-structure)
- [Components](#-components)
- [Prerequisites](#-prerequisites)
- [Phase 1 — Infrastructure Setup](#-phase-1--infrastructure-setup)
- [Phase 2 — Docker Setup](#-phase-2--docker-setup)
- [Phase 3 — Snort IDS](#-phase-3--snort-ids)
- [Phase 4 — ML Model](#-phase-4--ml-model)
- [Phase 5 — Web Dashboard](#-phase-5--web-dashboard)
- [Phase 6 — Integration & Testing](#-phase-6--integration--testing)
- [Database Schema](#-database-schema)
- [Environment Variables](#-environment-variables)
- [Security Notes](#-security-notes)
- [Roadmap](#-roadmap)

---

## 🔍 Overview

A full-stack, containerized **Network Intrusion Detection System** that combines:

- **Snort IDS** for rule-based packet inspection
- **ML Model** for anomaly detection and attack classification
- **PostgreSQL** for persistent storage of alerts and events
- **Web Dashboard** for real-time monitoring and visualization
- All services orchestrated via **Docker Compose** on **Ubuntu Server 22.04**

### Key Targets

| Metric | Target |
|--------|--------|
| Detection Rate | 94%+ |
| Response Time | < 50ms |
| False Positive Rate | < 5% |
| Uptime | 99%+ |

---

## 🏗️ Architecture

```
Internet / Network Traffic
          │
          ▼
┌─────────────────────────────────────────────────┐
│              Ubuntu Server 22.04 LTS             │
│                                                  │
│  ┌───────────────────────────────────────────┐  │
│  │         Docker Engine (Compose)            │  │
│  │                                            │  │
│  │  ┌──────────┐        ┌──────────────────┐ │  │
│  │  │  Snort   │──────▶ │    ML Model      │ │  │
│  │  │  IDS     │        │  (FastAPI:8000)   │ │  │
│  │  │container │        └────────┬─────────┘ │  │
│  │  └────┬─────┘                 │            │  │
│  │       │                       │            │  │
│  │       └──────────┬────────────┘            │  │
│  │                  ▼                         │  │
│  │         ┌─────────────────┐                │  │
│  │         │   PostgreSQL    │                │  │
│  │         │  (port: 5432)   │                │  │
│  │         └────────┬────────┘                │  │
│  │                  │                         │  │
│  │         ┌────────▼────────┐                │  │
│  │         │  Web Dashboard  │                │  │
│  │         │  (port: 5000) ◀─┼──── Browser   │  │
│  │         └─────────────────┘                │  │
│  └───────────────────────────────────────────┘  │
└─────────────────────────────────────────────────┘
```

### Internal Data Flow

```
Raw Packets → Snort (JSON Alerts) → ML Model (Classification) → PostgreSQL → Dashboard (Real-time UI)
```

---

## 📁 Project Structure

```
nids-project/
├── docker-compose.yml          # Main orchestration file
├── .env                        # Environment variables (NOT in git)
├── .env.example                # Template for .env
├── .gitignore
├── README.md
│
├── database/
│   ├── init.sql                # Schema creation
│   └── seed.sql                # Sample data for testing
│
├── snort/
│   ├── Dockerfile
│   ├── config/
│   │   └── snort.conf          # Main Snort config
│   ├── rules/
│   │   └── local.rules         # Custom detection rules
│   └── scripts/
│       └── alert_to_db.py      # Parse alerts → PostgreSQL
│
├── ml-model/
│   ├── Dockerfile
│   ├── requirements.txt
│   ├── app/
│   │   ├── main.py             # FastAPI entrypoint
│   │   ├── model.py            # ML inference logic
│   │   ├── database.py         # DB connection
│   │   └── schemas.py          # Pydantic models
│   └── models/
│       └── anomaly_model.pkl   # Trained model (generated)
│
├── dashboard/
│   ├── Dockerfile
│   ├── requirements.txt
│   ├── app.py                  # Flask/FastAPI backend
│   ├── templates/
│   │   └── index.html
│   └── static/
│       ├── css/
│       └── js/
│
└── docs/
    ├── architecture.png
    └── setup-guide.md
```

---

## 📦 Components

### 1️⃣ Snort IDS Container
- **Base Image:** `ubuntu:24
- **Role:** Captures live traffic, applies rule-based inspection
- **Network Mode:** `host` (required to see real traffic)
- **Output:** Structured JSON alerts → written to PostgreSQL
- **Capabilities Required:** `NET_ADMIN`, `NET_RAW`

### 2️⃣ ML Model Container
- **Base Image:** `python:3.11-slim`
- **Role:** Classifies attack types, detects anomalies
- **Framework:** FastAPI + scikit-learn
- **Dataset:** CICIDS2018 / UNSW-NB15
- **Internal Port:** `8000`
- **Input:** Reads new alerts from PostgreSQL every 30s
- **Output:** Writes predictions back to `ml_predictions` table

### 3️⃣ PostgreSQL Container
- **Image:** `postgres:15-alpine`
- **Role:** Persistent storage for all alerts, predictions, and stats
- **Internal Port:** `5432` (never exposed externally)
- **Volume:** `postgres-data:/var/lib/postgresql/data`

### 4️⃣ Web Dashboard Container
- **Base Image:** `python:3.11-slim`
- **Role:** Real-time monitoring UI
- **Framework:** Flask + Chart.js
- **Exposed Port:** `5000` → accessible from browser
- **Features:** Live alerts table, traffic graphs, severity levels

---

## ✅ Prerequisites

| Requirement | Version | Check Command |
|-------------|---------|---------------|
| Ubuntu Server | 24.04 LTS | `lsb_release -a` |
| Docker CE | 24.x+ | `docker --version` |
| Docker Compose | v2.x+ | `docker compose version` |
| RAM | 8 GB recommended | `free -h` |
| Storage | 40 GB minimum | `df -h` |
| CPU | 4 cores recommended | `nproc` |

---

## 🚀 Phase 1 — Infrastructure Setup

### Step 1 — Update the System

```bash
sudo apt update && sudo apt upgrade -y

sudo apt install -y \
    curl wget git \
    net-tools htop \
    ufw ca-certificates \
    gnupg lsb-release
```

### Step 2 — Install Docker

```bash
# Add Docker's official GPG key
sudo install -m 0755 -d /etc/apt/keyrings

curl -fsSL https://download.docker.com/linux/ubuntu/gpg | \
    sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg

sudo chmod a+r /etc/apt/keyrings/docker.gpg

# Add Docker repository
echo \
  "deb [arch=$(dpkg --print-architecture) \
  signed-by=/etc/apt/keyrings/docker.gpg] \
  https://download.docker.com/linux/ubuntu \
  $(lsb_release -cs) stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

# Install Docker Engine
sudo apt update
sudo apt install -y \
    docker-ce \
    docker-ce-cli \
    containerd.io \
    docker-buildx-plugin \
    docker-compose-plugin
```

### Step 3 — Post-install Configuration

```bash
# Enable Docker on boot
sudo systemctl enable docker
sudo systemctl start docker

# Add your user to docker group (no sudo needed)
sudo usermod -aG docker $USER
newgrp docker

# Verify installation
docker --version
docker compose version
docker run hello-world
```

### Step 4 — Configure Firewall (UFW)

```bash
sudo ufw enable
sudo ufw allow ssh          # Keep SSH access
sudo ufw allow 5000/tcp     # Dashboard port
# DO NOT open 5432 — PostgreSQL stays internal only
sudo ufw status verbose
```

### Step 5 — Create Project Structure

```bash
mkdir -p ~/nids-project
cd ~/nids-project

mkdir -p \
    snort/rules \
    snort/scripts \
    snort/config \
    ml-model/app \
    ml-model/models \
    dashboard/templates \
    dashboard/static \
    database \
    docs

touch docker-compose.yml .env .env.example .gitignore README.md
touch database/init.sql database/seed.sql
```

### Step 6 — Create .env File

```bash
cat > .env << 'EOF'
# PostgreSQL
POSTGRES_DB=nids_db
POSTGRES_USER=nids_user
POSTGRES_PASSWORD=Change_This_Strong_Password_123!
POSTGRES_HOST=postgres
POSTGRES_PORT=5432

# ML Model
ML_API_PORT=8000

# Dashboard
DASHBOARD_PORT=5000

# Environment
ENVIRONMENT=development
EOF

chmod 600 .env
```

### Step 7 — Create .gitignore

```bash
cat > .gitignore << 'EOF'
# Secrets
.env

# Python
__pycache__/
*.pyc
*.pyo
*.pyd
.Python
*.egg-info/
dist/
build/
.venv/
venv/

# ML Models (large files)
ml-model/models/*.pkl
ml-model/models/*.h5
ml-model/models/*.joblib

# Logs
*.log
snort/logs/

# OS
.DS_Store
Thumbs.db

# IDE
.vscode/
.idea/
EOF
```

### Phase 1 Checklist

```
□ Ubuntu Server 22.04 installed on VM
□ apt update && upgrade completed
□ Docker CE installed and running
□ docker run hello-world succeeded
□ UFW enabled with correct ports
□ Project folder structure created
□ .env file created and secured (chmod 600)
□ .gitignore configured
```

---

## 🐳 Phase 2 — Docker Setup

> 🔧 Coming next — `docker-compose.yml` full configuration for all 4 services.

---

## 🛡️ Phase 3 — Snort IDS

> 🔧 Coming next — Snort Dockerfile, config, rules, and DB integration script.

---

## 🧠 Phase 4 — ML Model

> 🔧 Coming next — FastAPI service, model training on CICIDS2018, anomaly classification.

---

## 📊 Phase 5 — Web Dashboard

> 🔧 Coming next — Flask app, real-time alerts UI, Chart.js visualizations.

---

## 🔗 Phase 6 — Integration & Testing

> 🔧 Coming next — End-to-end testing, attack simulation, performance benchmarks.

---

## 🗄️ Database Schema

```sql
-- Snort alerts table
CREATE TABLE snort_alerts (
    id            SERIAL PRIMARY KEY,
    timestamp     TIMESTAMP DEFAULT NOW(),
    src_ip        VARCHAR(45),
    dst_ip        VARCHAR(45),
    src_port      INTEGER,
    dst_port      INTEGER,
    protocol      VARCHAR(10),
    alert_msg     TEXT,
    severity      INTEGER,        -- 1:High  2:Medium  3:Low
    raw_payload   TEXT
);

-- ML predictions table
CREATE TABLE ml_predictions (
    id            SERIAL PRIMARY KEY,
    alert_id      INTEGER REFERENCES snort_alerts(id),
    timestamp     TIMESTAMP DEFAULT NOW(),
    is_anomaly    BOOLEAN,
    confidence    FLOAT,          -- 0.0 to 1.0
    attack_type   VARCHAR(50)     -- DDoS, PortScan, BruteForce, etc.
);

-- Traffic statistics table
CREATE TABLE traffic_stats (
    id            SERIAL PRIMARY KEY,
    timestamp     TIMESTAMP DEFAULT NOW(),
    total_packets INTEGER,
    blocked_count INTEGER,
    anomaly_count INTEGER
);
```

---

## 🔐 Environment Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `POSTGRES_DB` | Database name | `nids_db` |
| `POSTGRES_USER` | DB username | `nids_user` |
| `POSTGRES_PASSWORD` | DB password | `Strong_Pass_123!` |
| `POSTGRES_HOST` | DB hostname (Docker service name) | `postgres` |
| `POSTGRES_PORT` | DB port | `5432` |
| `ML_API_PORT` | ML model internal port | `8000` |
| `DASHBOARD_PORT` | Dashboard exposed port | `5000` |
| `ENVIRONMENT` | Runtime environment | `development` |

Copy `.env.example` to `.env` and fill in your values. **Never commit `.env` to git.**

---

## 🔒 Security Notes

- **PostgreSQL** port `5432` is never exposed outside Docker network
- **`.env`** file has `chmod 600` permissions and is in `.gitignore`
- **Snort container** requires `NET_ADMIN` and `NET_RAW` capabilities — do not grant more
- In production, replace `.env` passwords with **Docker Secrets** or **HashiCorp Vault**
- Dashboard should be behind a reverse proxy (Nginx) with HTTPS in production

---

## 🗺️ Roadmap

- [x] Phase 1 — Infrastructure Setup
- [ ] Phase 2 — Docker Compose Configuration
- [ ] Phase 3 — Snort IDS Container
- [ ] Phase 4 — ML Model Container
- [ ] Phase 5 — Web Dashboard Container
- [ ] Phase 6 — Integration & Testing
- [ ] Phase 7 (Planned) — Redis Message Queue for high-traffic resilience
- [ ] Phase 7 (Planned) — Threat Intelligence (IP reputation mapping)
- [ ] Phase 7 (Planned) — Auto Response Engine (block IPs, trigger firewall rules)
- [ ] Phase 7 (Planned) — CI/CD Pipeline with GitHub Actions


## 📄 License

This project is licensed under the MIT License.
