# Berebrum - Dockerfile con Python 3.14
FROM python:3.14-slim

LABEL maintainer="Berebrum Team"
LABEL description="AI-Powered Red Team Platform"
LABEL python.version="3.14"

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

# Instalar dependencias del sistema
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    curl \
    wget \
    git \
    && rm -rf /var/lib/apt/lists/*

# Crear usuario no-root
RUN useradd -m -u 1000 berebrum && \
    mkdir -p /app /database /data /logs && \
    chown -R berebrum:berebrum /app /database /data /logs

WORKDIR /app

# Copiar y instalar dependencias
COPY requirements.txt .
RUN pip install --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copiar código
COPY --chown=berebrum:berebrum . .

USER berebrum

EXPOSE 8501

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s \
    CMD python -c "import sys; sys.exit(0)" || exit 1

CMD ["python", "cli/main.py"]