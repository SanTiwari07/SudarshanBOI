# How to Run Sudarshan

This guide will walk you through the complete setup of the Sudarshan cybersecurity platform, from installing dependencies to running the services and performing health checks. Even if you have zero prior knowledge, following these steps will get the project running locally on Windows, Mac, or Linux.

---

## 1. Prerequisites

Ensure you have the following software installed on your machine:

### Core Dependencies
1. **Python 3.10+**: Required for the backend services. [Download Python](https://www.python.org/downloads/)
2. **Node.js 18+ (and npm)**: Required for the frontend React application. [Download Node.js](https://nodejs.org/)
3. **Docker Desktop**: Required to run MobSF and containerized components. [Download Docker](https://www.docker.com/products/docker-desktop/)

### Mobile Security Dependencies
4. **Android Studio (with Android Emulator)**: Required for dynamic analysis. [Download Android Studio](https://developer.android.com/studio)
   - Setup an Android Virtual Device (AVD).
5. **ADB (Android Debug Bridge)**: Included with Android SDK. Ensure `adb` is in your system's PATH.
6. **Frida**: Required for hooking and dynamic analysis.
7. **Ollama**: Required for running Local LLM models for AI-driven risk scoring. [Download Ollama](https://ollama.com/download)

---

## 2. Environment Setup

### Clone the Repository
If you haven't already:
```bash
git clone https://github.com/your-org/sudarshan.git
cd sudarshan
```

### Environment Variables
We provide an example environment file. Copy it to `.env` in the root folder:
```bash
# On Linux / Mac
cp .env.example .env

# On Windows
copy .env.example .env
```
Open `.env` and fill in any required API keys (e.g., `MOBSF_API_KEY`). Ensure your `VITE_API_URL` points to `http://localhost:8000`.

---

## 3. Backend Setup

The backend handles AI processing, REST APIs, and analysis pipelines.

1. **Navigate to the backend folder**:
   ```bash
   cd backend
   ```
2. **Create a Python Virtual Environment**:
   ```bash
   # On Windows
   python -m venv venv
   .\venv\Scripts\activate

   # On Mac / Linux
   python3 -m venv venv
   source venv/bin/activate
   ```
3. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```
4. **Run the Backend Server**:
   ```bash
   uvicorn main:app --reload --host 0.0.0.0 --port 8000
   ```
   *The backend should now be running at `http://localhost:8000`.*

---

## 4. Frontend Setup

The frontend provides the interactive dashboard and reports.

1. **Open a new terminal and navigate to the frontend folder**:
   ```bash
   cd frontend
   ```
2. **Install Node Modules**:
   ```bash
   npm install
   ```
3. **Run the Development Server**:
   ```bash
   npm run dev
   ```
   *The frontend should now be running at `http://localhost:5173`.*

---

## 5. Third-Party Integrations Setup

### 5.1 MobSF (Mobile Security Framework)
MobSF is run via Docker for static analysis.
1. Open Docker Desktop.
2. In the root directory of the project, start MobSF via Docker Compose:
   ```bash
   docker-compose up mobsf -d
   ```
3. MobSF will be available at `http://localhost:8001`.

### 5.2 Ollama (Local AI)
Ollama powers the intelligence engine.
1. Ensure Ollama is running in the background.
2. Pull the required model (e.g., Llama 3 or Mistral):
   ```bash
   ollama run llama3
   ```
3. Ensure the Ollama API is exposed at `http://localhost:11434`.

### 5.3 Frida & Android Emulator (Dynamic Analysis)
To perform dynamic analysis, an Android emulator must be running and the Frida Server must be active.

**Step 1: Setup Emulator**
1. Open Android Studio -> Virtual Device Manager.
2. Create an **API 29, Android 10, x86_64** emulator. *(Do not use the 32-bit x86 image!)*
3. Start the emulator.

**Step 2: Install Frida Server**
1. Download the `frida-server-17.15.3-android-x86_64.xz` file from [Frida Releases](https://github.com/frida/frida/releases) and extract the binary file.
2. Open PowerShell and push it to the emulator's temp folder:
   ```powershell
   # Change this path to where you extracted the file/folder!
   adb push C:\path\to\frida-server-17.15.3-android-x86_64 /data/local/tmp/
   
   # Make the folder and its contents executable
   adb shell chmod -R 777 /data/local/tmp/frida-server-17.15.3-android-x86_64
   ```

**Step 3: Start Frida & Expose to Docker**
Run these commands every time you restart the emulator to get it ready for Sudarshan:
```powershell
# 1. Ensure ADB is running as root
adb root

# 2. Start Frida Server in the background (no output means success)
adb shell "cd /data/local/tmp/frida-server-17.15.3-android-x86_64 && ./frida* &"

# 3. Expose ADB to TCP so the Docker container can reach it
adb tcpip 5555
```

*Note: The `docker-compose.yml` file shares your Windows `~/.android` ADB keys with Docker, so the backend container is automatically authorized to connect. You won't see any "Allow USB Debugging" popups!*

---

## 6. Running with Docker (Recommended)

If you prefer to run the entire stack (Backend, Frontend, and MobSF) in isolated containers without setting up Node and Python locally, use Docker Compose.

1. Ensure Docker Desktop is running.
2. Build and start all services:
   ```bash
   docker-compose up --build
   ```
3. **Access the services**:
   - Frontend Dashboard: `http://localhost:5173`
   - Backend API Docs (Swagger): `http://localhost:8000/docs`
   - MobSF Dashboard: `http://localhost:8001`

---

## 7. Verification and Health Checks

To verify that the platform is running correctly, perform these health checks:

- **Backend API**: Navigate to `http://localhost:8000/health`. You should receive a JSON response: `{"status": "ok"}`.
- **Frontend App**: Navigate to `http://localhost:5173`. You should see the Sudarshan Dashboard.
- **MobSF Integration**: Ensure `http://localhost:8001` loads the MobSF UI.
- **Ollama**: Run `curl http://localhost:11434/api/tags` and verify it returns a list of models.

---

## 8. Common Errors & Troubleshooting

### Port Conflicts
- **Error**: `listen EADDRINUSE: address already in use :::8000`
- **Solution**: Another service is using port 8000. Identify the process (`netstat -ano | findstr :8000` on Windows or `lsof -i :8000` on Mac/Linux) and terminate it, or change the backend port.

### Docker Issues
- **Error**: `Cannot connect to the Docker daemon`
- **Solution**: Ensure Docker Desktop is open and fully initialized.

### ADB & Frida Issues
- **Error**: `device offline` or `frida-server not found`
- **Solution**: Ensure the emulator is completely booted before running `adb tcpip 5555`. You may need to manually install `frida-server` on the emulator that matches your host's frida version.

### GPU / CPU Mode (Ollama)
- **Issue**: Ollama inference is extremely slow.
- **Solution**: If you have a dedicated GPU, ensure Ollama is utilizing it (check Task Manager/Activity Monitor). If running on CPU only, expect slower responses.

### Windows vs Linux/Mac Execution
- On Windows, always use `.\venv\Scripts\activate`. On Unix systems, use `source venv/bin/activate`.
- If `host.docker.internal` fails on Linux, verify `extra_hosts` in `docker-compose.yml`.
