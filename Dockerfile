FROM mcr.microsoft.com/mirror/docker/library/python:3.11-slim AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

ENV VENV_PATH=/opt/venv

WORKDIR /build

COPY requirements.runtime.txt .
RUN python -m venv "$VENV_PATH" \
    && "$VENV_PATH/bin/pip" install --upgrade pip \
    && "$VENV_PATH/bin/pip" install --no-cache-dir --no-compile -r requirements.runtime.txt \
    && find "$VENV_PATH" -type d -name "__pycache__" -prune -exec rm -rf {} + \
    && find "$VENV_PATH" -type f -name "*.pyc" -delete


FROM mcr.microsoft.com/mirror/docker/library/python:3.11-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    VENV_PATH=/opt/venv \
    PATH=/opt/venv/bin:$PATH

WORKDIR /app

COPY --from=builder /opt/venv /opt/venv

# Copy only runtime files to keep image lean.
COPY src ./src
COPY ui ./ui
COPY governance ./governance

RUN mkdir -p reports session \
    && useradd --create-home --shell /usr/sbin/nologin appuser \
    && chown -R appuser:appuser /app

USER appuser

EXPOSE 8503

CMD ["streamlit", "run", "ui/app.py", "--server.headless=true", "--server.address=0.0.0.0", "--server.port=8503"]