# SUDARSHAN — Frida Dynamic Analysis Setup Guide

This document explains how to set up the Frida-based dynamic behavioral analysis
sandbox for the Sudarshan platform.

## Prerequisites

| Requirement | Status | Notes |
|---|---|---|
| `frida` (Python) | ✅ In `requirements.txt` | Auto-installed via `pip` / Docker build |
| `adb` | ✅ In `Dockerfile` | `android-sdk-platform-tools` installed in container |
| Android Studio (AVD) | ⚙️ On your HOST machine | Runs the Android emulator |
| `frida-server` | ⚙️ One-time emulator setup | Steps below |

---

## Running with Docker (Recommended)

The backend Docker container has `adb` and `frida`/`frida-tools` pre-installed.
The Android emulator still runs on your **host machine** (via Android Studio AVD).
The container reaches the emulator over **ADB TCP** using `host.docker.internal`.

### One-time host setup (run these on your Windows machine, NOT inside Docker)

```powershell
# 1. Start your AVD emulator in Android Studio

# 2. Add ADB to PATH (run once, then restart terminal):
#    C:\Users\sansk\AppData\Local\Android\Sdk\platform-tools\

# 3. Switch the emulator's ADB to TCP mode:
adb tcpip 5555

# 4. Verify:
adb devices
# Should show: emulator-5554   device
```

### Then start the full stack:

```powershell
docker compose up --build
```

The backend will automatically call `adb connect host.docker.internal:5555` on startup
(driven by `ADB_HOST=host.docker.internal` in `docker-compose.yml`).

### Verify it worked — check the sandbox status endpoint:

```
GET http://localhost:8000/api/v1/sandbox/status
```

Expected response when Docker + emulator are configured correctly:
```json
{
  "ready": true,
  "mode": "docker-tcp",
  "frida_available": true,
  "frida_version": "17.15.3",
  "adb_found": true,
  "adb_host": "host.docker.internal",
  "adb_port": "5555",
  "emulators_connected": ["host.docker.internal:5555"],
  "hooks_script_present": true,
  "message": "Frida sandbox is ready for dynamic analysis."
}
```

> **Note:** If `ready` is `false`, the platform still works — it automatically falls back
> to static-only analysis (Androguard / MobSF). No errors are thrown.

---

## Architecture

```
APK Uploaded
     │
     ▼
Static Analysis (Androguard / MobSF)
     │
     ▼
[FRIDA SANDBOX]
  ├─ ADB installs APK on Android Emulator (AVD)
  ├─ Frida attaches to the running process
  ├─ banking_trojan.js hooks dangerous Android APIs:
  │     [A] Accessibility Service  (wa = 0.35)
  │     [S] SMS Interception       (ws = 0.25)
  │     [O] Overlay Windows        (wo = 0.20)
  │     [B] Banking App Detection  (wb = 0.10)
  │     [N] Network / C2           (wn = 0.05)
  │     [P] Persistence            (wp = 0.05)
  └─ Behavioral events collected for 30 seconds
     │
     ▼
BFCI = (wa × A) + (ws × S) + (wo × O) + (wb × B) + (wn × N) + (wp × P)
     │
     ▼
FRS = 0.25×STEI + 0.35×BFCI + 0.20×Correlation + 0.20×BankingImpact
     │
     ▼
Fraud Intelligence Card (via Ollama + RAG)
```

---

## Step 1 — Create an Android Emulator in Android Studio

1. Open **Android Studio → Virtual Device Manager** (Tools menu or side panel).
2. Click **Create Device**.
3. Choose **Pixel 5** (or any phone) → **Next**.
4. Select a system image — choose **API 29 (Android 10, x86_64)**.  
   > ⚠️ Use x86_64 for performance. Frida Server builds are available for x86_64.
5. Click **Finish**. The emulator will appear in the list.
6. Click **▶ Play** to start the emulator.

Verify it is recognized by ADB:
```powershell
adb devices
# Should show: emulator-5554   device
```

---

## Step 2 — Deploy frida-server on the Emulator

Frida requires `frida-server` running as root on the Android device.

### Download the correct frida-server binary

The version must match your installed Frida (17.15.3):

```powershell
# Check your frida version
frida --version
# → 17.15.3
```

Download from: https://github.com/frida/frida/releases/tag/17.15.3

Find the file: `frida-server-17.15.3-android-x86_64.xz`

### Install and run frida-server on the emulator

```powershell
# 1. Extract the .xz file (use 7-Zip or similar)
# You should now have: frida-server-17.15.3-android-x86_64

# 2. Push to the emulator
adb push frida-server-17.15.3-android-x86_64 /data/local/tmp/frida-server

# 3. Make it executable
adb shell chmod 755 /data/local/tmp/frida-server

# 4. Start frida-server as root (run this in a SEPARATE terminal — keep it running)
adb shell su -c "/data/local/tmp/frida-server &"
```

### Verify the connection

```powershell
frida-ps -D emulator-5554
# Should list running Android processes — you are connected!
```

---

## Step 3 — Add ADB to your PATH (if not already)

Android Studio installs ADB here:
```
C:\Users\<YourName>\AppData\Local\Android\Sdk\platform-tools\
```

Add this path to your Windows PATH environment variable, or Sudarshan's
`frida_sandbox.py` will auto-detect it.

---

## Step 4 — Verify the Sandbox via API

Start the Sudarshan backend, then call:

```
GET http://localhost:8000/api/v1/sandbox/status
```

You should see:
```json
{
  "ready": true,
  "frida_available": true,
  "frida_version": "17.15.3",
  "adb_found": true,
  "emulators_connected": ["emulator-5554"],
  "hooks_script_present": true,
  "bfci_weights": {
    "accessibility": 0.35,
    "sms": 0.25,
    "overlay": 0.20,
    "banking": 0.10,
    "network": 0.05,
    "persistence": 0.05
  },
  "message": "Frida sandbox is ready for dynamic analysis."
}
```

---

## How the BFCI Formula is Implemented

When a suspicious APK is uploaded and the sandbox is ready, the platform:

1. **Installs** the APK onto the emulator via ADB.
2. **Spawns** the app's process and attaches Frida to it.
3. **Injects** `banking_trojan.js` which hooks 15+ dangerous Android APIs.
4. **Monitors** for 30 seconds, collecting events per category.
5. **Computes** the BFCI using the exact weighted formula:

```
BFCI = (0.35 × A) + (0.25 × S) + (0.20 × O) + (0.10 × B) + (0.05 × N) + (0.05 × P)
```

Where each component is a 0–100 score based on event frequency and hook variety.

6. **Feeds** the BFCI into the FRS formula:
```
FRS = 0.25×STEI + 0.35×BFCI + 0.20×Correlation + 0.20×BankingImpact
```

The `dynamic_available: true` field in the API response will confirm that Frida
data was used in the scoring.

---

## Files Reference

| File | Purpose |
|---|---|
| `app/engines/frida_sandbox.py` | Python controller — ADB, install, attach, BFCI computation |
| `app/engines/frida_hooks/banking_trojan.js` | Frida JS — hooks 15+ dangerous Android APIs |
| `app/engines/risk_engine.py` | `_calculate_bfci_from_frida()` — uses proper BFCI formula |
| `app/routes/upload.py` | Step 1.5 — calls Frida sandbox if ready |

---

## Graceful Degradation

If the sandbox is not configured (no emulator, no frida-server), the platform
automatically falls back to static-only analysis using Androguard/MobSF.
The STEI weight is redistributed from 25% to 50% in the FRS formula to
compensate for the missing dynamic component. No errors are raised.
