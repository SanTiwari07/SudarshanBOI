"""
Sudarshan Async Analysis Job Queue
====================================
Provides non-blocking APK analysis via an asyncio Queue.

Flow:
  POST /api/v1/analyze/async  → enqueue → return {job_id, status: "queued"}
  GET  /api/v1/status/{job_id}  → poll for result

Workers are started as background asyncio tasks when the FastAPI app starts.
Number of workers is configurable via ANALYSIS_WORKERS env var (default: 2).

Job lifecycle:
  queued → processing → done | failed

Results are held in memory _jobs dict AND persisted to SQLite via save_case().
"""

import asyncio
import logging
import os
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

ANALYSIS_WORKERS = int(os.getenv("ANALYSIS_WORKERS", "2"))

# ─── In-Memory Job Store ──────────────────────────────────────────────────────

_jobs: Dict[str, Dict[str, Any]] = {}
_queue: asyncio.Queue = asyncio.Queue()


def create_job() -> str:
    """Allocate a new job ID and register it as queued."""
    job_id = str(uuid.uuid4())
    _jobs[job_id] = {
        "job_id": job_id,
        "status": "queued",
        "queued_at": datetime.now(timezone.utc).isoformat(),
        "started_at": None,
        "completed_at": None,
        "result": None,
        "error": None,
    }
    return job_id


def get_job(job_id: str) -> Optional[Dict[str, Any]]:
    return _jobs.get(job_id)


def _set_processing(job_id: str) -> None:
    if job_id in _jobs:
        _jobs[job_id]["status"] = "processing"
        _jobs[job_id]["started_at"] = datetime.now(timezone.utc).isoformat()


def _set_done(job_id: str, result: Dict[str, Any]) -> None:
    if job_id in _jobs:
        _jobs[job_id]["status"] = "done"
        _jobs[job_id]["result"] = result
        _jobs[job_id]["completed_at"] = datetime.now(timezone.utc).isoformat()


def _set_failed(job_id: str, error: str) -> None:
    if job_id in _jobs:
        _jobs[job_id]["status"] = "failed"
        _jobs[job_id]["error"] = error
        _jobs[job_id]["completed_at"] = datetime.now(timezone.utc).isoformat()


# ─── Queue Interface ──────────────────────────────────────────────────────────

async def enqueue(job_id: str, temp_path: str, filename: str, sha256_hash: str, analyst_id: Optional[int] = None) -> None:
    """Push a job onto the queue."""
    await _queue.put({
        "job_id": job_id,
        "temp_path": temp_path,
        "filename": filename,
        "sha256_hash": sha256_hash,
        "analyst_id": analyst_id,
    })
    logger.info(f"[Queue] Job enqueued: {job_id} file={filename}")


# ─── Worker ───────────────────────────────────────────────────────────────────

async def _worker(worker_id: int) -> None:
    """
    Pull jobs from the queue and run the full analysis pipeline.
    Mirrors the logic in upload.py but driven by the queue.
    """
    # Lazy imports to avoid circular dependency at module load
    import hashlib
    import tempfile
    import os as _os

    from app.ai.ollama_client import analyze_with_llm
    from app.analyzers.apk_analyzer import analyze_apk
    from app.engines.classification_engine import classify_family
    from app.engines.risk_engine import calculate_risk_score, build_threat_scenario_table
    from app.engines.frida_sandbox import run_frida_analysis, get_sandbox_status
    from app.models.schemas import StaticAnalysisFlags
    from app.services.threat_correlator import correlate
    from app.services.mobsf_client import MobSFClient, MobSFAnalysisError, MobSFNotAvailable
    from app.db.database import save_case

    mobsf = MobSFClient()
    logger.info(f"[Queue] Worker {worker_id} started")

    while True:
        try:
            item = await _queue.get()
            job_id     = item["job_id"]
            temp_path  = item["temp_path"]
            filename   = item["filename"]
            sha256_hash = item["sha256_hash"]
            analyst_id = item.get("analyst_id")

            _set_processing(job_id)
            logger.info(f"[Queue] Worker {worker_id} processing job {job_id}")

            try:
                # ── Static Analysis ───────────────────────────────────────────
                analysis_mode = "androguard"
                flags_dict: Dict[str, Any] = {}
                all_permissions: list = []
                package_name = "Unknown"
                suspicious_strings: list = []

                mobsf_available = await mobsf.is_available()
                mobsf_report = None

                if mobsf_available:
                    try:
                        mobsf_report = await mobsf.analyze(temp_path)
                        analysis_mode = "mobsf"
                        package_name = mobsf_report.get("package_name") or "Unknown"
                        all_permissions = mobsf.get_all_permissions(mobsf_report)
                        flags_dict = mobsf.extract_flags(mobsf_report)
                    except (MobSFAnalysisError, MobSFNotAvailable):
                        mobsf_available = False

                if not mobsf_available:
                    ag_out = await asyncio.to_thread(analyze_apk, temp_path)
                    package_name = ag_out.package_name
                    all_permissions = ag_out.permissions or []
                    flags_dict = {
                        "has_accessibility_abuse": ag_out.flags.has_accessibility_abuse,
                        "has_sms_read_write": ag_out.flags.has_sms_read_write,
                        "has_system_alert_window": ag_out.flags.has_system_alert_window,
                        "dangerous_apis_found": ag_out.flags.dangerous_apis_found,
                        "hardcoded_urls_ips": ag_out.flags.hardcoded_urls_ips,
                        "targets_indian_banks": ag_out.flags.targets_indian_banks,
                        "indian_bank_packages_found": ag_out.flags.indian_bank_packages_found,
                        "obfuscation_score": ag_out.flags.obfuscation_score,
                        "has_reflection": ag_out.flags.has_reflection,
                    }
                    suspicious_strings = ag_out.suspicious_strings

                # ── Frida Dynamic ─────────────────────────────────────────────
                dynamic_result = None
                frida_status = get_sandbox_status()
                if frida_status["ready"]:
                    try:
                        dynamic_result = await run_frida_analysis(temp_path, package_name=package_name)
                        if not dynamic_result.get("available"):
                            dynamic_result = None
                    except Exception as fe:
                        logger.warning(f"[Queue] Frida failed: {fe}")

                # ── Classification ────────────────────────────────────────────
                flags_model = StaticAnalysisFlags(**flags_dict)
                family_class, matched_rule = classify_family(flags_model)
                ai_confidence = 1.0 if family_class == "Unknown" else 1.2

                # ── Threat Correlation ────────────────────────────────────────
                try:
                    correlation_raw = await correlate(
                        sha256=sha256_hash,
                        urls=flags_dict.get("hardcoded_urls_ips", []),
                        package_name=package_name,
                    )
                except Exception:
                    correlation_raw = {"available": False}

                if correlation_raw.get("known_family") and family_class == "Unknown":
                    family_class = correlation_raw["known_family"]
                    ai_confidence = 1.15

                # ── Risk Score ────────────────────────────────────────────────
                risk_result = calculate_risk_score(
                    flags=flags_dict,
                    ai_confidence=ai_confidence,
                    dynamic_result=dynamic_result,
                    correlation_result=correlation_raw,
                    family=family_class,
                    all_permissions=all_permissions,
                )

                # ── LLM Intelligence ──────────────────────────────────────────
                llm_response = await analyze_with_llm(
                    flags=flags_dict,
                    family=family_class,
                    matched_rule=matched_rule,
                    package_name=package_name,
                    risk_result=risk_result,
                    correlation=correlation_raw,
                    dynamic=dynamic_result,
                )

                # ── Build slim result for job store ───────────────────────────
                result = {
                    "job_id": job_id,
                    "sha256": sha256_hash,
                    "package_name": package_name,
                    "analysis_mode": analysis_mode,
                    "family_classification": family_class,
                    "final_risk_score": risk_result["final_risk_score"],
                    "risk_band": risk_result["risk_band"],
                    "confidence": risk_result.get("confidence", 70.0),
                    "dynamic_available": bool(dynamic_result and dynamic_result.get("available")),
                    "obfuscation_score": flags_dict.get("obfuscation_score", 0.0),
                    "has_reflection": flags_dict.get("has_reflection", False),
                    "frs_breakdown": risk_result.get("frs_breakdown", {}),
                    "threat_scenario_table": risk_result.get("threat_scenario_table", []),
                    "intelligence_report": llm_response,
                    "has_accessibility_abuse": flags_dict.get("has_accessibility_abuse", False),
                    "has_sms_read_write": flags_dict.get("has_sms_read_write", False),
                    "has_system_alert_window": flags_dict.get("has_system_alert_window", False),
                    "hardcoded_urls_ips": flags_dict.get("hardcoded_urls_ips", []),
                    "targets_indian_banks": flags_dict.get("targets_indian_banks", False),
                    "threat_correlation": correlation_raw,
                }

                # Persist to DB
                await save_case(sha256_hash, result, analyst_id=analyst_id)

                _set_done(job_id, result)
                logger.info(f"[Queue] Worker {worker_id} completed job {job_id} score={result['final_risk_score']}")

            except Exception as e:
                logger.exception(f"[Queue] Worker {worker_id} failed job {job_id}: {e}")
                _set_failed(job_id, str(e))
            finally:
                try:
                    _os.remove(temp_path)
                except Exception:
                    pass

            _queue.task_done()

        except asyncio.CancelledError:
            logger.info(f"[Queue] Worker {worker_id} shutting down")
            break
        except Exception as e:
            logger.exception(f"[Queue] Worker {worker_id} unexpected error: {e}")
            await asyncio.sleep(1)


# ─── Startup / Shutdown ───────────────────────────────────────────────────────

_worker_tasks: list = []


async def start_workers() -> None:
    """Launch ANALYSIS_WORKERS background worker coroutines."""
    global _worker_tasks
    _worker_tasks = [
        asyncio.create_task(_worker(i + 1), name=f"analysis-worker-{i + 1}")
        for i in range(ANALYSIS_WORKERS)
    ]
    logger.info(f"[Queue] {ANALYSIS_WORKERS} analysis worker(s) started")


async def stop_workers() -> None:
    """Cancel all running worker tasks on app shutdown."""
    for task in _worker_tasks:
        task.cancel()
    await asyncio.gather(*_worker_tasks, return_exceptions=True)
    logger.info("[Queue] Analysis workers stopped")
