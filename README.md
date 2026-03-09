# 🛡️ AI-Powered Network Intrusion Detection System (NIDS)

> Graduation Project — Security Engineering · Machine Learning · DevOps

![Ubuntu](https://img.shields.io/badge/Ubuntu-24.04_LTS-E95420?style=flat&logo=ubuntu&logoColor=white)
![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?style=flat&logo=docker&logoColor=white)
![Python](https://img.shields.io/badge/Python-3.11-3776AB?style=flat&logo=python&logoColor=white)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-15-336791?style=flat&logo=postgresql&logoColor=white)
![Snort](https://img.shields.io/badge/Snort-3.x-FF0000?style=flat)
![License](https://img.shields.io/badge/License-MIT-green?style=flat)

---

## 📋 Table of Contents

- [Overview](#-overview)
- [Architecture](#-architecture)
- [Why This Design?](#-why-this-design)
- [Project Structure](#-project-structure)
- [Components](#-components)
- [Prerequisites](#-prerequisites)
- [Phase 1 — Infrastructure Setup](#-phase-1--infrastructure-setup)
- [Phase 2 — Snort IDS](#-phase-2--snort-ids)
- [Phase 3 — Docker Setup](#-phase-3--docker-setup)
- [Phase 4 — ML Model](#-phase-4--ml-model)
- [Phase 5 — Web Dashboard](#-phase-5--web-dashboard)
- [Phase 6 — Integration & Testing](#-phase-6--integration--testing)
- [Database Schema](#-database-schema)
- [Environment Variables](#-environment-variables)
- [Security Notes](#-security-notes)
- [Roadmap](#-roadmap)

---

## 🔍 Overview

A full-stack **Network Intrusion Detection System** that combines two complementary detection approaches:

- **Snort IDS** — rule-based detection, installed directly on the host server
- **ML Model** — anomaly-based detection using Isolation Forest, learns the behavior of *our own network*
- **PostgreSQL** — persistent storage for all alerts, predictions, and traffic stats
- **Web Dashboard** — real-time monitoring and visualization
- ML Model, PostgreSQL, and Dashboard run as **Docker containers** orchestrated via Docker Compose

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
┌─────────────────────────────────────────────────────┐
│                Ubuntu Server 24.04 LTS               │
│                                                      │
│  ┌─────────────────────────────────────────────┐    │
│  │         Snort IDS  (installed on host)       │    │
│  │                                              │    │
│  │  Reads live traffic directly from NIC        │    │
│  │  Applies signature-based rules               │    │
│  │  Writes alerts → PostgreSQL                  │    │
│  └───────────────────┬─────────────────────────┘    │
│                      │                               │
│                      ▼                               │
│  ┌─────────────────────────────────────────────┐    │
│  │         Docker Compose Network               │    │
│  │                                              │    │
│  │   ┌─────────────┐      ┌─────────────────┐  │    │
│  │   │  PostgreSQL │◀────▶│    ML Model     │  │    │
│  │   │  :5432      │      │  (Python :8000) │  │    │
│  │   └──────┬──────┘      └─────────────────┘  │    │
│  │          │                                   │    │
│  │   ┌──────▼──────┐                            │    │
│  │   │  Dashboard  │◀──────────── Browser       │    │
│  │   │  :5000      │                            │    │
│  │   └─────────────┘                            │    │
│  └─────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────┘
```

### Internal Data Flow

```
Network Traffic
      │
      ▼
Snort IDS ──── Signature Match? ──▶ Alert ──▶ PostgreSQL
      │                                            │
      │                                            ▼
      │                                       ML Model
      │                                  (Anomaly Detection)
      │                                            │
      └──── Raw Traffic Stats ──────────────────▶ │
                                                   ▼
                                             PostgreSQL
                                                   │
                                                   ▼
                                             Dashboard
                                          (Real-time UI)
```

---

## 🤔 Why This Design?

### Why is Snort installed on the host (not in a container)?

Snort is a **network-level tool** — it needs direct access to the physical network interface to capture every packet *before* any routing or processing happens.

Running it in a container adds unnecessary complexity and latency. Even with `network_mode: host`, containerizing Snort provides no benefit and introduces potential issues with interface detection. The right tool in the right place.

### Why two detection layers?

| Layer | Method | Strength | Weakness |
|-------|--------|----------|----------|
| Snort | Signature-based | Catches all *known* attacks instantly | Blind to new/unknown attacks |
| ML Model | Anomaly-based | Catches *unknown* attacks and zero-days | Needs time to learn normal behavior |

Together they cover each other's blind spots.

### Why does the ML Model learn from our own network?

A pre-trained dataset (e.g., CICIDS2018) was captured on a different network, in a different environment, in 2018. Training only on it means the model learns someone else's "normal."

Our model uses a **two-phase approach:**

```
Phase A — Bootstrap (Day 1):
  Train on CICIDS2018 so the model isn't blind from the start

Phase B — Behavioral Baseline (Ongoing):
  Model observes our real network traffic
  Builds a profile of what "normal" looks like for us specifically
  Gradually replaces the generic knowledge with network-specific knowledge
```

This is exactly how enterprise security tools like Darktrace and CrowdStrike work.

---

## 📁 Project Structure

```
nids-project/
├── docker-compose.yml          # Orchestrates ML Model, PostgreSQL, Dashboard
├── .env                        # Environment variables (NOT in git)
├── .env.example                # Safe template to commit
├── .gitignore
├── README.md
│
├── database/
│   ├── init.sql                # Schema creation
│   └── seed.sql                # Sample data for testing
│
├── snort/                      # Snort config (runs on host, not in Docker)
│   ├── config/
│   │   └── snort.conf          # Main Snort configuration
│   ├── rules/
│   │   └── local.rules         # Custom detection rules
│   └── scripts/
│       └── alert_to_db.py      # Parses Snort alerts → PostgreSQL
│
├── ml-model/
│   ├── Dockerfile
│   ├── requirements.txt
│   ├── app/
│   │   ├── main.py             # Service entrypoint (runs every 30s)
│   │   ├── model.py            # Isolation Forest logic
│   │   ├── trainer.py          # Training + retraining logic
│   │   ├── database.py         # PostgreSQL connection
│   │   └── schemas.py          # Data models
│   └── models/
│       └── anomaly_model.pkl   # Saved model (generated, not in git)
│
├── dashboard/
│   ├── Dockerfile
│   ├── requirements.txt
│   ├── app.py                  # Flask backend
│   ├── templates/
│   │   └── index.html
│   └── static/
│       ├── css/
│       └── js/
│
└── docs/
    ├── architecture.md
    └── setup-guide.md
```

---

## 📦 Components

### 1️⃣ Snort IDS — Host Service
- **Installed:** Directly on Ubuntu Server 24.04 (not containerized)
- **Role:** Captures live traffic from the NIC, applies signature-based rules
- **Why on host:** Needs direct hardware-level access to the network interface
- **Output:** Structured alerts written to PostgreSQL via `alert_to_db.py`

### 2️⃣ ML Model — Docker Container
- **Base Image:** `python:3.11-slim`
- **Role:** Anomaly detection using Isolation Forest
- **Two-phase learning:**
  - Bootstrap: trained on CICIDS2018 dataset
  - Ongoing: learns behavioral baseline from our real network traffic
- **Internal Port:** `8000`
- **Schedule:** Analyzes new alerts every 30 seconds, retrains periodically
- **Output:** Writes anomaly scores and predictions to `ml_predictions` table

### 3️⃣ PostgreSQL — Docker Container
- **Image:** `postgres:15-alpine`
- **Role:** Persistent storage for alerts, predictions, and traffic stats
- **Internal Port:** `5432` — never exposed outside Docker network
- **Volume:** `postgres-data:/var/lib/postgresql/data`

### 4️⃣ Web Dashboard — Docker Container
- **Base Image:** `python:3.11-slim`
- **Role:** Real-time monitoring and visualization UI
- **Framework:** Flask + Chart.js
- **Exposed Port:** `5000` → accessible from browser
- **Features:** Live alerts, anomaly scores, traffic graphs, severity levels

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

# ML Models (large binary files)
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
□ Ubuntu Server 24.04 installed on VM
□ apt update && upgrade completed
□ Docker CE installed and running
□ docker run hello-world succeeded
□ UFW enabled with correct ports
□ Project folder structure created
□ .env file created and secured (chmod 600)
□ .gitignore configured
```

---

## 🛡️ Phase 2 — Snort IDS

> 🔧 Coming next — Installing Snort 3 directly on Ubuntu 24.04, writing detection rules, and connecting alerts to PostgreSQL via `alert_to_db.py`

---

## 🐳 Phase 3 — Docker Setup

> 🔧 Coming next — `docker-compose.yml` for ML Model, PostgreSQL, and Dashboard containers.

---

## 🧠 Phase 4 — ML Model

> 🔧 Coming next — Isolation Forest implementation, two-phase training (CICIDS2018 bootstrap + live network behavioral baseline), anomaly scoring.

---

## 📊 Phase 5 — Web Dashboard

> 🔧 Coming next — Flask app, real-time alerts UI, anomaly score visualization, Chart.js graphs.

---

## 🔗 Phase 6 — Integration & Testing

> 🔧 Coming next — End-to-end testing, simulated attack scenarios, performance benchmarks.

---

## 🗄️ Database Schema

```sql
-- Snort alerts (written by alert_to_db.py running on host)
CREATE TABLE snort_alerts (
    id            SERIAL PRIMARY KEY,
    timestamp     TIMESTAMP DEFAULT NOW(),
    src_ip        VARCHAR(45),
    dst_ip        VARCHAR(45),
    src_port      INTEGER,
    dst_port      INTEGER,
    protocol      VARCHAR(10),
    alert_msg     TEXT,
    severity      INTEGER        -- 1:High  2:Medium  3:Low
);

-- ML anomaly detection results
CREATE TABLE ml_predictions (
    id              SERIAL PRIMARY KEY,
    alert_id        INTEGER REFERENCES snort_alerts(id),
    timestamp       TIMESTAMP DEFAULT NOW(),
    is_anomaly      BOOLEAN,
    anomaly_score   FLOAT,       -- Isolation Forest score (-1 to 1)
    confidence      FLOAT,       -- 0.0 to 1.0
    attack_type     VARCHAR(50)  -- DDoS, PortScan, BruteForce, Unknown...
);

-- Raw traffic statistics (for ML baseline learning)
CREATE TABLE traffic_stats (
    id              SERIAL PRIMARY KEY,
    timestamp       TIMESTAMP DEFAULT NOW(),
    src_ip          VARCHAR(45),
    dst_ip          VARCHAR(45),
    protocol        VARCHAR(10),
    packet_count    INTEGER,
    byte_count      INTEGER,
    duration_ms     INTEGER
);

-- ML model training history
CREATE TABLE model_versions (
    id              SERIAL PRIMARY KEY,
    trained_at      TIMESTAMP DEFAULT NOW(),
    training_source VARCHAR(50),  -- 'CICIDS2018' or 'live_network'
    samples_count   INTEGER,
    model_path      TEXT
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

- **Snort** runs on the host with only the permissions it needs — no unnecessary capabilities
- **PostgreSQL** port `5432` is never exposed outside the Docker network
- **`.env`** has `chmod 600` permissions and is excluded from git
- **ML model files** (`.pkl`) are excluded from git — too large and contain sensitive training data
- In production, replace `.env` passwords with **Docker Secrets** or **HashiCorp Vault**
- Dashboard should sit behind an **Nginx reverse proxy** with HTTPS in production

---

## 🗺️ Roadmap

- [x] Phase 1 — Infrastructure Setup
- [ ] Phase 2 — Snort IDS (host install)
- [ ] Phase 3 — Docker Compose Configuration
- [ ] Phase 4 — ML Anomaly Detection Model
- [ ] Phase 5 — Web Dashboard
- [ ] Phase 6 — Integration & Testing
- [ ] Phase 7 *(Planned)* — Redis Message Queue for high-traffic resilience
- [ ] Phase 7 *(Planned)* — Threat Intelligence (IP reputation mapping)
- [ ] Phase 7 *(Planned)* — Auto Response Engine (block IPs, trigger firewall rules)
- [ ] Phase 7 *(Planned)* — CI/CD Pipeline with GitHub Actions

---

## 👥 Authors

| Role | Name |
|------|------|
| Senior DevOps / Security Engineer | Mentor |
| Junior Developer | Student |

---

## 📄 License

This project is licensed under the MIT License.
