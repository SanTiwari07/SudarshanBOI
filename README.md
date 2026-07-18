# 🛡️ Sudarshan Enterprise — Android Malware Intelligence Platform

**Sudarshan** is an enterprise-grade Android APK analysis platform designed for banking fraud detection. It combines static analysis (Androguard / MobSF), dynamic behavioral instrumentation (Frida), threat correlation, and AI-powered intelligence reporting into a single deployable Docker stack.

---

## 🚀 Quick Start

> Make sure your Android Emulator (AVD) is running before you start.

```powershell
.\start.ps1
```

This single command handles everything:
- Restarting ADB, enabling TCP mode
- Starting `frida-server` on the emulator
- Launching Docker Compose (backend + frontend + MobSF)

| Service   | URL                                       |
|-----------|-------------------------------------------|
| Frontend  | http://localhost:5173                     |
| Backend   | http://localhost:8000                     |
| MobSF     | http://localhost:8008 (mobsf / mobsf)     |
| API Docs  | http://localhost:8000/docs                |

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    SUDARSHAN ENTERPRISE                     │
│                                                             │
│  ┌──────────┐    ┌──────────────┐    ┌───────────────────┐  │
│  │  React   │───▶│   FastAPI    │───▶│  MobSF (Docker)   │  │
│  │ Frontend │    │   Backend    │    └───────────────────┘  │
│  └──────────┘    │              │                           │
│                  │  ┌────────┐  │    ┌───────────────────┐  │
│                  │  │Andro-  │  │    │ Android Emulator  │  │
│                  │  │guard   │  │    │  (host machine)   │  │
│                  │  └────────┘  │    │                   │  │
│                  │              │◀───│  frida-server     │  │
│                  │  ┌────────┐  │    │  (ADB TCP 5555)   │  │
│                  │  │Frida   │  │    └───────────────────┘  │
│                  │  │Engine  │  │                           │
│                  │  └────────┘  │    ┌───────────────────┐  │
│                  │              │───▶│  SQLite (cases DB)│  │
│                  │  ┌────────┐  │    └───────────────────┘  │
│                  │  │AI/LLM  │  │                           │
│                  │  │Report  │  │                           │
│                  │  └────────┘  │                           │
│                  └──────────────┘                           │
└─────────────────────────────────────────────────────────────┘
```

### Analysis Pipeline

```
APK Upload → Static Analysis → MobSF → Frida Dynamic Sandbox
    → Threat Correlation (VT / AbuseIPDB / OTX)
    → FRS Score → AI Intelligence Report → Dashboard
```

---

## 📊 Risk Scoring

### Fraud Risk Score (FRS)

```
FRS = 0.25×STEI + 0.35×BFCI + 0.20×Correlation + 0.20×BankingImpact
```

### Banking Fraud Confidence Index (BFCI)

```
BFCI = (0.35×Accessibility) + (0.25×SMS) + (0.20×Overlay)
     + (0.10×BankingTarget) + (0.05×Network) + (0.05×Persistence)
```

| Score Range | Risk Band     |
|-------------|---------------|
| 0 – 29      | Low Risk      |
| 30 – 49     | Suspicious    |
| 50 – 74     | High Risk     |
| 75 – 100    | Critical      |

---

## 🗂️ Project Structure

```
Sudarshan BOI/
├── start.ps1                    # ⚡ One-command startup script
├── docker-compose.yml           # Docker stack definition
├── .env                         # Environment configuration
├── backend/
│   ├── Dockerfile
│   ├── requirements.txt
│   ├── README_FRIDA.md          # Frida setup guide
│   └── app/
│       ├── main.py              # FastAPI entrypoint
│       ├── routes/
│       │   ├── upload.py        # APK analysis pipeline
│       │   ├── auth.py          # JWT authentication
│       │   └── cases.py         # Case history
│       ├── engines/
│       │   ├── frida_sandbox.py   # Frida/ADB controller
│       │   ├── multi_stage_engine.py # Multi-stage analysis
│       │   ├── ui_explorer.py     # Automated UI interaction
│       │   ├── risk_engine.py     # FRS/BFCI scoring
│       │   ├── mobsf_client.py    # MobSF integration
│       │   └── frida_hooks/
│       │       └── banking_trojan.js  # Frida instrumentation script
│       ├── models/
│       │   └── schemas.py         # Pydantic API schemas
│       └── db/
│           └── database.py        # SQLite persistence
└── frontend/
    ├── src/
    │   ├── App.tsx               # Main app + type definitions
    │   ├── pages/
    │   │   ├── Upload.tsx        # APK upload page
    │   │   ├── FraudCard.tsx     # Executive risk card
    │   │   ├── TechnicalView.tsx # SOC analyst view
    │   │   ├── ThreatIntelView.tsx # Threat intelligence panel
    │   │   ├── History.tsx       # Case history
    │   │   └── Login.tsx         # Authentication
    │   └── utils/
    │       └── derive.ts         # UI data derivation helpers
    └── vite.config.ts
```

---

## 🔧 Configuration

Key environment variables (`.env` file):

| Variable | Description |
|----------|-------------|
| `ADB_HOST` | Host where emulator runs (`host.docker.internal` for Docker Desktop) |
| `ADB_PORT` | ADB TCP port (default: `5555`) |
| `MOBSF_URL` | MobSF API URL (default: `http://mobsf:8000`) |
| `MOBSF_API_KEY` | MobSF REST API key |
| `JWT_SECRET` | JWT signing key for authentication |
| `GEMINI_API_KEY` | Google Gemini API key (optional, for AI reports) |
| `OLLAMA_URL` | Local Ollama URL (optional, fallback LLM) |

---

## 📡 API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/v1/analyze` | Synchronous APK analysis |
| `POST` | `/api/v1/analyze/async` | Async APK analysis (returns job_id) |
| `GET`  | `/api/v1/status/{job_id}` | Poll async job status |
| `GET`  | `/api/v1/sandbox/status` | Check Frida/ADB sandbox readiness |
| `GET`  | `/api/v1/cases` | List historical analysis cases |
| `GET`  | `/api/v1/cases/{sha256}` | Get case by SHA-256 |
| `POST` | `/api/v1/auth/login` | Get JWT token |
| `POST` | `/api/v1/auth/register` | Register new analyst |

---

## 🔐 Authentication

The API uses JWT Bearer tokens. Default credentials (development only):

```
Username: admin
Password: (set via ADMIN_PASSWORD in .env)
```

To get a token:
```bash
curl -X POST http://localhost:8000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "your_password"}'
```

---

## 📋 CHANGELOG

See [CHANGELOG.md](./CHANGELOG.md) for a full list of changes by date.

---

## ⚠️ Known Limitations

- `frida-server` must be re-started after each emulator reboot (handled automatically by `start.ps1`).
- The `frida-server` binary (~106 MB) cannot be stored in Git — must be pushed to the emulator manually (one-time setup).
- Ollama-based AI reports require a running local Ollama instance. If unavailable, the platform uses Gemini API or provides a static analysis-only report.
- Advanced malware with root detection or hardware attestation may evade the AVD emulator environment.

---

## 📄 License

Internal use — Sudarshan Enterprise Platform.
