from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.routes import upload, report
from app.routes.cases import router as cases_router
from app.auth.auth import router as auth_router
from app.db.database import init_db
from app.workers.analysis_queue import start_workers, stop_workers
from app.auth.auth import hash_password, username_exists, create_user
import os
import logging

logger = logging.getLogger(__name__)

app = FastAPI(
    title="Sudarshan Enterprise Banking Threat Intelligence Platform",
    version="2.1.0",
    description=(
        "APK malware analysis engine with Androguard/MobSF static analysis, "
        "Frida dynamic behavioral sandbox, RAG-grounded Ollama intelligence, "
        "threat correlation (VT/OTX/AbuseIPDB), 5-axis STEI scoring, "
        "JWT auth, persistent SQLite case store, and async job queue."
    ),
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─── Routers ─────────────────────────────────────────────────────────────────

app.include_router(auth_router,       prefix="/api/v1",         tags=["Authentication"])
app.include_router(upload.router,     prefix="/api/v1",         tags=["Analysis"])
app.include_router(report.router,     prefix="/api/v1",         tags=["Reports & Export"])
app.include_router(cases_router,      prefix="/api/v1",         tags=["Case History"])


# ─── Startup / Shutdown ───────────────────────────────────────────────────────

@app.on_event("startup")
async def startup():
    # 1. Initialize SQLite tables
    await init_db()
    logger.info("[Startup] Database initialized")

    # 2. Seed default admin user if none exists
    admin_user = os.getenv("ADMIN_USERNAME", "admin")
    admin_pass = os.getenv("ADMIN_PASSWORD", "sudarshan_admin_2024")

    if not await username_exists(admin_user):
        hashed = hash_password(admin_pass)
        await create_user(admin_user, hashed, role="admin")
        logger.info(f"[Startup] Seeded default admin user: {admin_user}")

    # 3. Start async analysis worker pool
    await start_workers()
    logger.info("[Startup] Analysis worker pool started")


@app.on_event("shutdown")
async def shutdown():
    await stop_workers()
    logger.info("[Shutdown] Analysis workers stopped")


# ─── Root Endpoints ───────────────────────────────────────────────────────────

@app.get("/")
def read_root():
    return {
        "status": "Sudarshan Enterprise Banking Threat Intelligence Platform Online",
        "version": "2.1.0",
        "engines": ["androguard", "mobsf (if configured)", "frida (if emulator connected)"],
        "scoring": [
            "5-axis STEI (CT×0.60 + BT×0.20 + PR×0.10 + OB×0.05 + IR×0.05)",
            "BFCI (frida dynamic behavioral formula)",
            "FRS = 0.25×STEI + 0.35×BFCI + 0.20×Correlation + 0.20×BankingImpact",
        ],
        "intelligence": ["rag", "qwen3:8b (ollama)", "virustotal", "otx", "abuseipdb"],
        "export": ["stix-2.1", "ioc-csv"],
        "auth": "JWT Bearer",
        "storage": "SQLite (persistent case store + IOC cache)",
        "queue": "asyncio worker pool",
    }


@app.get("/health")
def health():
    return {"status": "ok"}
