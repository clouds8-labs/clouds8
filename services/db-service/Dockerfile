# LynxMap DB Service
#
# Build context is the repo root (not this directory) because this service's
# code imports nothing outside itself, but the build shares one
# requirements.txt with the other services. See docker-compose.yml.
FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY services/db-service/ services/db-service/

WORKDIR /app/services/db-service

EXPOSE 8001

CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8001"]
