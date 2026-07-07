FROM python:3.11-slim

WORKDIR /app

# ── System deps ───────────────────────────────────────────────────────────────
# Download adb directly from Google's official platform-tools.
# The Debian apt package 'android-sdk-platform-tools' is unreliable on slim
# images. The Google binary zip is the authoritative source and always works.
RUN apt-get update && apt-get install -y --no-install-recommends \
        curl \
        unzip \
        aapt \
    && rm -rf /var/lib/apt/lists/* \
    && curl -sSL \
        "https://dl.google.com/android/repository/platform-tools-latest-linux.zip" \
        -o /tmp/platform-tools.zip \
    && unzip -q /tmp/platform-tools.zip -d /opt/ \
    && rm /tmp/platform-tools.zip \
    && ln -s /opt/platform-tools/adb /usr/local/bin/adb

# ── Python dependencies ───────────────────────────────────────────────────────
# requirements.txt already includes: frida frida-tools
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
