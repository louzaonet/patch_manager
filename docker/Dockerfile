# =============================================================================
# Patch Manager AI: container image for the FastAPI/LangGraph service
# =============================================================================
FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PATCH_AI_ENV_FILE=""

WORKDIR /app

COPY requirements.txt requirements.lock ./
# Pinned versions, every file checked by hash (see requirements.lock).
RUN pip install --require-hashes -r requirements.lock

COPY app/ ./app/

# Unprivileged runtime user
RUN useradd --system --uid 10001 --home-dir /app --shell /usr/sbin/nologin patchai
USER 10001

EXPOSE 8501

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8501/api/health', timeout=4).status == 200 else 1)"

# Trusted proxy: FORWARDED_ALLOW_IPS (docker-compose.yml sets nginx's address);
# uvicorn's default without it is 127.0.0.1.
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8501", "--proxy-headers"]
