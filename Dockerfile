# Cabcrawl in a container: the same Python and server as production (waitress), run as a
# non-root user. docker-compose.yml runs it with PostgreSQL; see "Run it with Docker" in the README.
FROM python:3.11-slim-bookworm

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    MPLCONFIGDIR=/tmp/matplotlib

WORKDIR /app

# Every requirement ships as a wheel for this platform, so no compiler is needed.
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .

# The app writes only to these (the same list as the systemd unit's ReadWritePaths).
RUN useradd --system --uid 10001 --home-dir /app --no-create-home cabcrawl \
 && mkdir -p instance uploads backups logs static/maintenance_photos static/profile_pics \
 && chown -R cabcrawl instance uploads backups logs static/maintenance_photos static/profile_pics
USER cabcrawl

EXPOSE 5000

HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:5000/api/v1/health', timeout=4)"

ENTRYPOINT ["docker/entrypoint.sh"]
CMD ["web"]
