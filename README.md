<div align="center">
  <h1>🛡️ Sudarshan</h1>
  <p><b>Enterprise-Grade AI-Powered Mobile Security & Threat Intelligence Platform</b></p>
  <p>
    <a href="https://github.com/your-org/sudarshan/actions"><img src="https://img.shields.io/github/actions/workflow/status/your-org/sudarshan/ci.yml?branch=main" alt="Build Status"></a>
    <a href="https://github.com/your-org/sudarshan/blob/main/LICENSE"><img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="License"></a>
    <a href="https://github.com/your-org/sudarshan/releases"><img src="https://img.shields.io/github/v/release/your-org/sudarshan" alt="Release"></a>
  </p>
</div>

---

## 📖 Project Overview

**Sudarshan** is a comprehensive, production-grade cybersecurity platform engineered to detect, analyze, and mitigate threats targeting mobile applications and APIs.

### Why Sudarshan Exists
The mobile ecosystem is evolving rapidly, and so are the threats targeting it. Traditional static analysis tools lack the context and deep reasoning required to identify sophisticated malware, fraudulent behavior, and obfuscated attack vectors. Sudarshan exists to bridge this gap by introducing **Large Language Models (LLMs)** and **AI Agents** into the core of the mobile security analysis pipeline.

### The Cybersecurity Problem
Modern threats such as banking trojans, spyware, and API abuse are designed to evade standard signature-based detection. Security analysts suffer from alert fatigue and struggle to keep up with the volume of obfuscated payloads. Sudarshan solves this by combining powerful static/dynamic analysis with AI-driven reasoning, allowing security teams to automatically triage, investigate, and score risks at scale.

### Who It Is For
- **Security Researchers & Analysts**: For deep-diving into malware behavior.
- **DevSecOps Teams**: For integrating automated security gates into CI/CD pipelines.
- **Financial Institutions**: For detecting fraud indicators in mobile applications.
- **Enterprise Security Operations Centers (SOC)**: For continuous threat monitoring and intelligence gathering.

---

## ✨ Features

Sudarshan provides an end-to-end suite of analysis tools:

- 🔍 **Static Analysis**: Deep decompilation, manifest parsing, and code flow analysis to uncover vulnerabilities without executing the application.
- ⚡ **Dynamic Analysis**: Real-time behavior monitoring, hooking, and memory introspection to detect runtime evasion techniques.
- 🦠 **Malware Detection**: Multi-engine scanning combining heuristics, signatures, and AI models to identify known and zero-day malware.
- 💳 **Fraud Detection**: specialized detection for banking trojans, overlay attacks, and SMS interception mechanisms.
- 🧠 **LLM Investigation**: Utilize local or cloud-based LLMs to semantically analyze decompiled code, providing plain-English explanations of malicious intent.
- 🤖 **AI Agents**: Autonomous agents that can trace execution paths, hunt for specific vulnerabilities, and construct attack narratives.
- 📊 **Risk Scoring**: A unified, quantifiable risk score (0-100) generated for every application based on aggregated threat vectors.
- 📱 **APK Analysis**: End-to-end pipeline for unpacking, parsing, and analyzing Android application packages.
- 🔗 **MobSF Integration**: Seamlessly integrates with the Mobile Security Framework for enterprise-grade static analysis reporting.
- 🪝 **Frida Integration**: Automated Frida script generation and injection for advanced dynamic analysis and hooking on physical or emulated devices.
- 🐳 **Docker Deployment**: Fully containerized architecture ensuring consistent environments and effortless scaling.
- 🌐 **REST APIs**: Comprehensive, well-documented APIs enabling easy integration with external SIEMs and orchestration tools.
- 📈 **Dashboard**: A React-based, highly responsive dashboard for visualizing threats, managing tasks, and reviewing analysis results.
- 📄 **Report Generation**: Automated generation of compliance-ready PDF and HTML security reports.

---

## 🛠️ Technology Stack

Sudarshan leverages modern, scalable technologies to deliver high performance:

| Component | Technology | Description |
|-----------|------------|-------------|
| **Backend** | Python, FastAPI | High-performance async REST API and core orchestration engine. |
| **Frontend** | React, Vite, Tailwind CSS | Lightning-fast, modern single-page application for the user interface. |
| **AI** | Ollama, LangChain | Local LLM execution for privacy-preserving AI investigations. |
| **Docker** | Docker, Docker Compose | Containerization and orchestration of the microservices. |
| **Database** | PostgreSQL, Redis | Persistent storage and high-speed caching for analysis results. |
| **Security** | MobSF, Frida, APKTool | Industry-standard tools for static and dynamic analysis. |
| **Networking** | ADB, TCP/IP | Device communication and service meshing. |
| **Automation** | GitHub Actions | CI/CD pipelines for testing and deployment. |

---

## 📁 Folder Structure

```text
Sudarshan/
├── backend/            # FastAPI server, AI agents, analyzers, and API routes
├── frontend/           # React SPA, components, pages, and UI assets
├── docs/               # Advanced documentation (Architecture, API references)
├── scripts/            # Utility scripts for CI/CD and automation
├── docker/             # Additional Dockerfiles and container configurations
├── configs/            # Global configuration files and environment templates
├── models/             # Local machine learning models and embeddings
├── assets/             # Static assets, branding, and placeholder images
├── tests/              # E2E tests and integration testing suite
├── .github/            # GitHub Actions workflows and issue templates
├── .env.example        # Example environment variables file
├── docker-compose.yml  # Docker orchestration file for the entire stack
├── Dockerfile          # Root-level multi-stage Dockerfile (if applicable)
├── HOW_TO_RUN.md       # Step-by-step installation and execution guide
├── ARCHITECTURE.md     # Comprehensive 1000+ line architectural design document
├── CONTRIBUTING.md     # Guidelines for contributing to the project
├── CHANGELOG.md        # Version history and release notes
├── LICENSE             # Open-source license information
└── README.md           # This file
```

### Folder Breakdown
- **`backend/`**: Contains the core logic, API definitions (`api/`), business services (`services/`), AI agents (`agents/`), and threat analyzers (`analyzers/`).
- **`frontend/`**: Contains the UI logic (`src/`), React components (`components/`), custom hooks (`hooks/`), and styling.
- **`docs/`**: Deep technical documentation for maintainers and integrators.
- **`scripts/`**: Useful bash/python scripts for environment setup, database migrations, and testing.

---

## 🏗️ Architecture Overview

Sudarshan employs a microservices-oriented architecture designed for horizontal scalability and high throughput. 

At a high level, the system consists of:
1. **API Gateway (FastAPI)**: Routes requests, handles authentication, and orchestrates analysis pipelines.
2. **Analysis Workers**: Asynchronous task queues (e.g., Celery) processing heavy APK decompilation and dynamic analysis tasks.
3. **AI Reasoning Engine**: Interfaces with Ollama to parse static analysis results and infer malicious intent using RAG (Retrieval-Augmented Generation).
4. **Integration Layer**: Connects to MobSF via REST and Android Emulators via ADB/Frida.

*(For a comprehensive technical deep dive, see [ARCHITECTURE.md](ARCHITECTURE.md))*

---

## 🖼️ Screenshots

*(Placeholders for future UI screenshots)*

| Dashboard Overview | Threat Analysis Report | AI Investigation Chat |
|:---:|:---:|:---:|
| ![Dashboard](assets/placeholder_dashboard.png) | ![Report](assets/placeholder_report.png) | ![AI Chat](assets/placeholder_chat.png) |

---

## 🚀 Installation & Quick Start

Sudarshan is designed to be easy to spin up using Docker.

**For complete, step-by-step instructions, please read [HOW_TO_RUN.md](HOW_TO_RUN.md).**

### Quick Start (Docker)
```bash
git clone https://github.com/your-org/sudarshan.git
cd sudarshan
cp .env.example .env
docker-compose up --build
```
Access the dashboard at `http://localhost:5173` and the API at `http://localhost:8000/docs`.

---

## ⚙️ Configuration & Environment Variables

The system relies on environment variables defined in the `.env` file. Key variables include:

- `VITE_API_URL`: The URL for the frontend to communicate with the backend.
- `MOBSF_API_KEY`: Authentication key for the MobSF instance.
- `OLLAMA_HOST`: The endpoint for the local LLM reasoning engine.
- `ADB_HOST` & `ADB_PORT`: Configuration for dynamic analysis device connection.

---

## 📖 API Overview

The backend provides a comprehensive OpenAPI specification (Swagger UI) accessible at `/docs` when the server is running. It includes endpoints for:
- `/api/v1/upload`: Upload an APK for analysis.
- `/api/v1/analysis/{id}`: Retrieve analysis status and results.
- `/api/v1/ai/investigate`: Trigger an AI agent to investigate a specific finding.
- `/api/v1/reports`: Generate and download PDF/HTML reports.

---

## 🗺️ Future Roadmap

- [ ] **Cloud-Native Deployment**: Kubernetes Helm charts for distributed cloud deployment.
- [ ] **iOS Support**: Integration with iOS static/dynamic analysis tools.
- [ ] **Multi-Agent Collaboration**: Enabling multiple AI agents to debate and consensus-score risks.
- [ ] **Threat Intelligence Feeds**: Native integration with external MISP and VirusTotal APIs.

---

## 🤝 Contribution Guide

We welcome contributions from the community! Whether it's adding new threat signatures, improving the UI, or fixing bugs, your help is appreciated.
Please review our [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on code standards, pull requests, and setting up the development environment.

---

## ❓ Troubleshooting

Encountering issues? 
- Check the [HOW_TO_RUN.md](HOW_TO_RUN.md) Troubleshooting section for common errors (Port conflicts, Docker issues, ADB connection failures).
- Open an issue on GitHub with your logs and environment details.

---

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
