# LynxMap Web UI (React)
#
# Build context is the repo root (see docker-compose.yml) purely for
# consistency with the other Dockerfiles - this app has no cross-directory
# imports, everything it needs lives under frontend/.
#
# Vite bakes VITE_* env vars into the JS bundle at build time, and the
# resulting bundle runs in the user's browser - not inside the Docker
# network - so these must be the ports docker-compose PUBLISHES to the
# host (localhost:8001/8002), not the internal service hostnames
# (db-service/backend-api) that server-side callers like the old Dash UI
# use.
FROM node:22-slim AS build
WORKDIR /app
COPY frontend/package.json frontend/package-lock.json* ./
RUN npm install
COPY frontend/ ./
ARG VITE_DB_SERVICE_URL=http://localhost:8001
ARG VITE_BACKEND_API_URL=http://localhost:8002
ENV VITE_DB_SERVICE_URL=$VITE_DB_SERVICE_URL
ENV VITE_BACKEND_API_URL=$VITE_BACKEND_API_URL
RUN npm run build

FROM nginx:alpine
COPY --from=build /app/dist /usr/share/nginx/html
COPY frontend/nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 80
