# Root Dockerfile for Sudarshan
# This multi-stage Dockerfile can build both frontend and backend for production.
# For development, please refer to docker-compose.yml.

# -- 1. Frontend Build Stage --
FROM node:18-alpine AS frontend-builder
WORKDIR /app
COPY frontend/package*.json ./
RUN npm install
COPY frontend/ ./
RUN npm run build

# -- 2. Backend Base Stage --
FROM python:3.10-slim AS backend
WORKDIR /app
COPY backend/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY backend/ ./

# -- 3. Production Serving Stage --
# (Optional: In a real production setup, NGINX would serve the frontend, and proxy to the backend.)
# Here we just document the root Dockerfile structure as requested.
EXPOSE 8000
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
