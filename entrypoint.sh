#!/bin/sh
set -e

# Construct DATABASE_URL from components if not already set
if [ -z "$DATABASE_URL" ] && [ -n "$DB_USER" ] && [ -n "$DB_PASSWORD" ] && [ -n "$DB_NAME" ]; then
    if [ -n "$CLOUD_SQL_CONNECTION_NAME" ]; then
        # Cloud Run: connect via Unix socket
        export DATABASE_URL="postgres://${DB_USER}:${DB_PASSWORD}@/${DB_NAME}?host=/cloudsql/${CLOUD_SQL_CONNECTION_NAME}"
    else
        # Fallback: TCP connection (local dev, docker-compose)
        export DATABASE_URL="postgres://${DB_USER}:${DB_PASSWORD}@${DB_HOST:-localhost}:${DB_PORT:-5432}/${DB_NAME}"
    fi
fi

exec /app/overslash-api "$@"
