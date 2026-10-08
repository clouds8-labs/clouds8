# LynxMap Backend API
#
# Build context is the repo root: this service imports collectors/,
# playbooks/, reports/, db/ (the HTTP facade) and shared/ (the client SDK)
# from their current top-level locations via sys.path, not from inside
# services/backend-api/ itself. See services/backend-api/app.py's docstring
# for why those haven't been physically relocated yet.
FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY collectors/ collectors/
COPY playbooks/ playbooks/
COPY reports/ reports/
COPY db/ db/
COPY shared/ shared/
COPY services/backend-api/ services/backend-api/

WORKDIR /app/services/backend-api

EXPOSE 8002

CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8002"]
