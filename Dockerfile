# Multi-stage-free but deliberately minimal: no build toolchain in the runtime image.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    ITOPS_DB=/app/data/itops.db

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY src/ ./src/
COPY tests/ ./tests/
COPY demo.py .

# Seed at build time and run the suite. If a security invariant is broken, the
# image does not get built. Accuracy of the permission model is treated as a
# build-breaking property, the same as a compile error.
RUN python src/seed.py && python -m pytest tests/ -q

# Runs as a non-root user. The gateway mediates privileged actions; it should not
# itself hold privilege it does not need.
RUN useradd --create-home --shell /usr/sbin/nologin appuser \
 && chown -R appuser:appuser /app
USER appuser

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://localhost:8000/ready').status==200 else 1)"

CMD ["uvicorn", "src.api:app", "--host", "0.0.0.0", "--port", "8000"]
