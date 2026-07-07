# backend/app/engines/frida_sandbox.py
"""
SUDARSHAN — Frida Dynamic Analysis Sandbox Controller
======================================================
Drives an Android emulator (AVD via Android Studio) to perform
runtime behavioral analysis of a suspicious APK using Frida hooks.

Prerequisites:
  1. Android Studio installed with an AVD (Emulator) created.
  2. frida-server deployed on the emulator (see README_FRIDA.md).
  3. ADB available in PATH (comes with Android Studio).
  4. pip install frida frida-tools  (already done)

Pipeline:
  APK → ADB install → Launch target package → Frida attach → 
  Hook APIs → Collect events (30s) → Compute BFCI → Return result

BFCI Formula (from Sudarshan proposal):
  BFCI = (wa × A) + (ws × S) + (wo × O) + (wb × B) + (wn × N) + (wp × P)
  
  Where:
    wa = 0.35  → Accessibility abuse score (0–100)
    ws = 0.25  → SMS interception score (0–100)
    wo = 0.20  → Overlay attack score (0–100)
    wb = 0.10  → Banking interaction score (0–100)
    wn = 0.05  → Network C2 communication score (0–100)
    wp = 0.05  → Persistence mechanism score (0–100)
"""

import asyncio
import json
import logging
import os
import subprocess
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# ─── Configuration ─────────────────────────────────────────────────────────────

# Path to the Frida JS hooks script
_HOOKS_SCRIPT = Path(__file__).parent / "frida_hooks" / "banking_trojan.js"

# ADB executable — tries PATH first, then common Android Studio locations
_ADB_CANDIDATES = [
    "adb",
    r"C:\Users\{user}\AppData\Local\Android\Sdk\platform-tools\adb.exe",
    r"C:\Program Files\Android\Android Studio\sdk\platform-tools\adb.exe",
]

# Default analysis duration in seconds
ANALYSIS_DURATION_SECONDS = int(os.getenv("FRIDA_ANALYSIS_DURATION", "30"))

# ── Docker / TCP ADB support ───────────────────────────────────────────────────
# When running in Docker, the Android emulator is on the HOST machine.
# Set ADB_HOST=host.docker.internal and ADB_PORT=5555 in docker-compose.yml.
# The backend will automatically run: adb connect <ADB_HOST>:<ADB_PORT>
ADB_HOST = os.getenv("ADB_HOST", "")   # e.g. host.docker.internal
ADB_PORT = os.getenv("ADB_PORT", "5555")

# ─── BFCI Weights (from proposal) ─────────────────────────────────────────────

BFCI_WEIGHTS = {
    "accessibility": 0.35,   # wa — heaviest: present in 87% of banking trojans
    "sms":           0.25,   # ws — OTP theft
    "overlay":       0.20,   # wo — phishing screens
    "banking":       0.10,   # wb — confirms target is a banking app
    "network":       0.05,   # wn — C2 communication
    "persistence":   0.05,   # wp — device admin / lockdown
}

# ─── ADB Helpers ──────────────────────────────────────────────────────────────

def _find_adb() -> Optional[str]:
    """Find the adb executable on this system."""
    import shutil
    # Try PATH first
    adb = shutil.which("adb")
    if adb:
        return adb
    # Try common Android Studio paths
    user = os.environ.get("USERNAME", "user")
    for candidate in _ADB_CANDIDATES[1:]:
        path = candidate.replace("{user}", user)
        if os.path.exists(path):
            return path
    return None


def _adb(*args: str, timeout: int = 30) -> Tuple[bool, str]:
    """Run an adb command. Returns (success, output)."""
    adb = _find_adb()
    if not adb:
        return False, "adb not found"
    try:
        result = subprocess.run(
            [adb] + list(args),
            capture_output=True, text=True, timeout=timeout
        )
        output = result.stdout + result.stderr
        return result.returncode == 0, output.strip()
    except subprocess.TimeoutExpired:
        return False, "adb command timed out"
    except Exception as e:
        return False, str(e)


def get_connected_emulators() -> List[str]:
    """
    Return list of connected emulator/device serials.

    Docker mode: if ADB_HOST env var is set, automatically connects to
    the host-machine emulator via ADB TCP before listing devices.
    """
    # ── Docker TCP mode: auto-connect to host emulator ─────────────────────────
    if ADB_HOST:
        tcp_target = f"{ADB_HOST}:{ADB_PORT}"
        ok, out = _adb("connect", tcp_target, timeout=10)
        if ok:
            logger.info(f"[Frida] ADB TCP connected to host emulator: {tcp_target}")
        else:
            logger.warning(f"[Frida] ADB TCP connect failed ({tcp_target}): {out}")

    ok, output = _adb("devices")
    if not ok:
        return []
    devices = []
    for line in output.splitlines()[1:]:
        if "\t" in line:
            serial, state = line.split("\t", 1)
            if state.strip() == "device":
                # Accept both local emulators and TCP-connected devices
                if "emulator" in serial or ":" in serial:
                    devices.append(serial.strip())
    return devices


def _adb_install_apk(apk_path: str, device: str) -> Tuple[bool, str]:
    """Install an APK onto the target device."""
    return _adb("-s", device, "install", "-r", "-t", apk_path, timeout=120)


def _get_package_name_from_apk(apk_path: str) -> Optional[str]:
    """Extract package name from APK using aapt or aapt2."""
    import shutil
    for tool in ["aapt2", "aapt"]:
        aapt = shutil.which(tool)
        if aapt:
            try:
                result = subprocess.run(
                    [aapt, "dump", "badging", apk_path],
                    capture_output=True, text=True, timeout=30
                )
                for line in result.stdout.splitlines():
                    if line.startswith("package: name="):
                        # package: name='com.example.app' versionCode='1' ...
                        parts = line.split("'")
                        if len(parts) >= 2:
                            return parts[1]
            except Exception:
                pass
    return None


def _launch_app(device: str, package_name: str) -> bool:
    """Launch the app's main activity via monkey."""
    ok, _ = _adb(
        "-s", device, "shell",
        f"monkey -p {package_name} -c android.intent.category.LAUNCHER 1",
        timeout=15
    )
    return ok

# ─── BFCI Score Calculation ────────────────────────────────────────────────────

def _score_component(events: List[Dict], max_events: int = 5) -> float:
    """
    Convert an event list to a 0–100 component score.
    More unique hook types = higher score, capped at max_events.
    """
    if not events:
        return 0.0
    unique_hooks = len(set(e["data"].get("hook", "") for e in events))
    score = min(unique_hooks / max_events, 1.0) * 100.0
    return round(score, 2)


def calculate_bfci(collected_events: Dict[str, List[Dict]]) -> Tuple[float, Dict[str, float], List[str]]:
    """
    Compute the Behavioral Fraud Confidence Index (BFCI).

    BFCI = (wa × A) + (ws × S) + (wo × O) + (wb × B) + (wn × N) + (wp × P)

    Returns:
        (bfci_score, component_scores, evidence_list)
    """
    components = {
        "accessibility": _score_component(collected_events.get("accessibility", []), max_events=3),
        "sms":           _score_component(collected_events.get("sms", []),           max_events=2),
        "overlay":       _score_component(collected_events.get("overlay", []),        max_events=2),
        "banking":       _score_component(collected_events.get("banking", []),        max_events=3),
        "network":       _score_component(collected_events.get("network", []),        max_events=10),
        "persistence":   _score_component(collected_events.get("persistence", []),    max_events=2),
    }

    bfci = sum(BFCI_WEIGHTS[k] * v for k, v in components.items())
    bfci = round(min(bfci, 100.0), 2)

    # Build evidence strings
    evidence: List[str] = []
    weight_labels = {
        "accessibility": ("A", "Accessibility abuse"),
        "sms":           ("S", "SMS/OTP interception"),
        "overlay":       ("O", "Overlay window attack"),
        "banking":       ("B", "Banking app targeting"),
        "network":       ("N", "C2 network communication"),
        "persistence":   ("P", "Persistence mechanism"),
    }
    for key, (symbol, label) in weight_labels.items():
        score = components[key]
        weight = BFCI_WEIGHTS[key]
        if score > 0:
            contribution = round(weight * score, 2)
            event_count = len(collected_events.get(key, []))
            evidence.append(
                f"[{symbol}] {label}: {event_count} runtime event(s) detected "
                f"— component score {score:.0f} × weight {weight} = +{contribution:.1f} to BFCI"
            )

    return bfci, components, evidence

# ─── Frida Session Manager ────────────────────────────────────────────────────

class FridaSession:
    """Manages a Frida instrumentation session against a target app."""

    def __init__(self, device_serial: str, package_name: str):
        self.device_serial = device_serial
        self.package_name = package_name
        self.collected_events: Dict[str, List[Dict]] = {
            "accessibility": [], "sms": [], "overlay": [],
            "banking": [], "network": [], "persistence": [],
            "dangerous_apis": [], "files_accessed": [],
        }
        self.hook_errors: List[str] = []
        self._session = None
        self._script = None

    def _on_message(self, message: Dict, data: Any) -> None:
        """Handle messages sent from the Frida JS script."""
        if message.get("type") == "send":
            payload = message.get("payload", {})
            msg_type = payload.get("type")

            if msg_type == "event":
                event = payload.get("payload", {})
                category = event.get("category")
                if category in self.collected_events:
                    self.collected_events[category].append(event)
                    logger.debug(f"[Frida] {category}: {event.get('data', {}).get('hook')}")

            elif msg_type == "hook_error":
                err = f"Hook failed: {payload.get('hook')} — {payload.get('error')}"
                self.hook_errors.append(err)
                logger.warning(f"[Frida] {err}")

            elif msg_type == "ready":
                logger.info(f"[Frida] {payload.get('message')}")

        elif message.get("type") == "error":
            logger.error(f"[Frida] Script error: {message.get('description')}")

    def run(self, duration_seconds: int = ANALYSIS_DURATION_SECONDS) -> bool:
        """
        Attach Frida to the target app and collect events for `duration_seconds`.
        Returns True if instrumentation was successful.
        """
        try:
            import frida
        except ImportError:
            logger.error("frida package not installed. Run: pip install frida")
            return False

        if not _HOOKS_SCRIPT.exists():
            logger.error(f"Frida hooks script not found: {_HOOKS_SCRIPT}")
            return False

        script_source = _HOOKS_SCRIPT.read_text(encoding="utf-8")

        try:
            logger.info(f"[Frida] Connecting to device {self.device_serial}")
            manager = frida.get_device_manager()
            device = manager.get_device(self.device_serial, timeout=10)

            logger.info(f"[Frida] Attaching to {self.package_name}")
            pid = device.spawn([self.package_name])
            self._session = device.attach(pid)
            self._script = self._session.create_script(script_source)
            self._script.on("message", self._on_message)
            self._script.load()
            device.resume(pid)

            logger.info(f"[Frida] Monitoring for {duration_seconds}s...")
            time.sleep(duration_seconds)

            self._script.unload()
            self._session.detach()
            logger.info(f"[Frida] Session complete — collected {sum(len(v) for v in self.collected_events.values())} events")
            return True

        except Exception as e:
            logger.error(f"[Frida] Session failed: {type(e).__name__}: {e}")
            return False

# ─── Main Analysis Entry Point ─────────────────────────────────────────────────

async def run_frida_analysis(apk_path: str, package_name: Optional[str] = None) -> Dict[str, Any]:
    """
    Full Frida dynamic analysis pipeline:
      1. Find connected emulator
      2. Install APK
      3. Extract package name
      4. Launch app + attach Frida
      5. Collect behavioral events
      6. Compute BFCI
      7. Return structured result (compatible with risk_engine.py)

    Returns a dict matching the dynamic_result schema expected by calculate_risk_score().
    Falls back gracefully with available=False if anything fails.
    """
    base_result: Dict[str, Any] = {
        "available": False,
        "engine": "frida",
        "bfci": 0.0,
        "bfci_components": {},
        "bfci_weights": BFCI_WEIGHTS,
        "activities_triggered": [],
        "network_logs": [],
        "api_calls": [],
        "files_accessed": [],
        "screenshots": [],
        "logcat": "",
        "evidence": [],
        "hook_errors": [],
        "duration_seconds": ANALYSIS_DURATION_SECONDS,
    }

    # ── Step 1: Find emulator ──────────────────────────────────────────────────
    emulators = get_connected_emulators()
    if not emulators:
        logger.warning("[Frida] No Android emulators connected. Start an AVD in Android Studio.")
        base_result["error"] = "No emulator connected. Start an AVD in Android Studio."
        return base_result

    device_serial = emulators[0]
    logger.info(f"[Frida] Using emulator: {device_serial}")

    # ── Step 2: Extract package name ───────────────────────────────────────────
    if not package_name:
        loop = asyncio.get_event_loop()
        package_name = await loop.run_in_executor(None, _get_package_name_from_apk, apk_path)
        
    if not package_name:
        logger.warning("[Frida] Could not extract package name from APK")
        base_result["error"] = "Could not extract package name from APK. Ensure aapt/aapt2 is in PATH."
        return base_result

    logger.info(f"[Frida] Target package: {package_name}")

    # ── Step 3: Install APK ────────────────────────────────────────────────────
    ok, output = await loop.run_in_executor(None, _adb_install_apk, apk_path, device_serial)
    if not ok:
        logger.error(f"[Frida] APK install failed: {output}")
        base_result["error"] = f"APK install failed: {output}"
        return base_result
    logger.info(f"[Frida] APK installed: {package_name}")

    # ── Step 4: Run Frida session ──────────────────────────────────────────────
    session = FridaSession(device_serial, package_name)

    def _run_sync():
        return session.run(duration_seconds=ANALYSIS_DURATION_SECONDS)

    success = await loop.run_in_executor(None, _run_sync)

    if not success:
        base_result["error"] = "Frida attach failed. Ensure frida-server is running on emulator."
        return base_result

    # ── Step 5: Compute BFCI ───────────────────────────────────────────────────
    bfci, components, evidence = calculate_bfci(session.collected_events)

    # ── Step 6: Build structured result ───────────────────────────────────────
    # Flatten API calls for risk_engine.py compatibility
    api_calls = [
        e["data"].get("hook", "")
        for category in ["accessibility", "sms", "overlay", "dangerous_apis"]
        for e in session.collected_events.get(category, [])
    ]

    network_logs = [
        e["data"].get("url", "")
        for e in session.collected_events.get("network", [])
        if e.get("data", {}).get("url")
    ]

    files_accessed = [
        e["data"].get("path", "")
        for e in session.collected_events.get("files_accessed", [])
        if e.get("data", {}).get("path")
    ]

    # Map to risk_engine.py's expected _calculate_dynamic_score() keys
    # This makes the BFCI directly usable by the existing pipeline
    result = {
        **base_result,
        "available": True,
        "engine": "frida",
        "package_name": package_name,
        "device": device_serial,

        # BFCI result (new fields for the updated risk_engine)
        "bfci": bfci,
        "bfci_components": components,
        "bfci_evidence": evidence,

        # Legacy fields expected by risk_engine._calculate_dynamic_score()
        # Maps Frida events → string signals the existing engine checks
        "api_calls": list(set(api_calls))[:30],
        "network_logs": network_logs[:20],
        "files_accessed": list(set(files_accessed))[:20],
        "screenshots": [],  # Not implemented in static sandbox
        "activities_triggered": [package_name],

        # Metadata
        "hook_errors": session.hook_errors,
        "evidence": evidence,
        "raw_event_counts": {k: len(v) for k, v in session.collected_events.items()},
    }

    logger.info(
        f"[Frida] Analysis complete: BFCI={bfci:.1f} "
        f"components={components}"
    )
    return result


# ─── Sandbox Status Check ──────────────────────────────────────────────────────

def get_sandbox_status() -> Dict[str, Any]:
    """
    Return the current status of the Frida sandbox environment.
    Called by the /api/v1/sandbox/status endpoint.
    """
    try:
        import frida
        frida_version = frida.__version__
        frida_available = True
    except ImportError:
        frida_version = None
        frida_available = False

    adb_path = _find_adb()
    emulators = get_connected_emulators() if adb_path else []

    hooks_ok = _HOOKS_SCRIPT.exists()

    ready = frida_available and adb_path is not None and len(emulators) > 0 and hooks_ok

    # Determine connection mode
    if ADB_HOST:
        mode = "docker-tcp"
        connection_info = (
            f"Docker mode: connecting to Android emulator at {ADB_HOST}:{ADB_PORT} via ADB TCP. "
            f"Ensure: (1) Emulator is running on host, (2) 'adb tcpip 5555' was run on host."
        )
    else:
        mode = "local"
        connection_info = "Local mode: looking for USB/AVD emulator connected via adb devices."

    return {
        "ready": ready,
        "mode": mode,
        "connection_info": connection_info,
        "frida_available": frida_available,
        "frida_version": frida_version,
        "adb_found": adb_path is not None,
        "adb_path": adb_path,
        "adb_host": ADB_HOST or None,
        "adb_port": ADB_PORT if ADB_HOST else None,
        "emulators_connected": emulators,
        "hooks_script_present": hooks_ok,
        "hooks_script_path": str(_HOOKS_SCRIPT),
        "analysis_duration_seconds": ANALYSIS_DURATION_SECONDS,
        "bfci_weights": BFCI_WEIGHTS,
        "message": (
            "Frida sandbox is ready for dynamic analysis."
            if ready else
            "Frida sandbox not fully configured. See status fields for missing components."
        ),
    }
