# Service d'inférence M1 (FastAPI). Construit depuis ml/m1.
FROM python:3.13-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONPATH=/app/src \
    M1_HOST=:: \
    M1_PORT=8001

WORKDIR /app

COPY requirements-service.txt ./
RUN pip install -r requirements-service.txt

COPY src ./src
COPY config ./config
COPY models ./models

# Pas de root dans le conteneur.
RUN useradd --system --uid 10001 --no-create-home m1
USER m1

EXPOSE 8001
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
  CMD python -c "import os,urllib.request as u; u.urlopen('http://127.0.0.1:%s/health' % os.environ.get('M1_PORT','8001'), timeout=3)"

# M1_SERVICE_TOKEN (16 caractères au moins) est OBLIGATOIRE : sans lui, le service refuse de démarrer.
CMD ["python", "-m", "m1", "service"]
