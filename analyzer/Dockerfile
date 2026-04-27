FROM python:3.12-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN groupadd -g 1000 analyzer \
 && useradd -u 1000 -g 1000 -m -s /usr/sbin/nologin analyzer

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY src/ ./src/
RUN mkdir -p /logs /out && chown -R 1000:1000 /app /logs /out

USER 1000:1000
ENV PYTHONPATH=/app/src

ENTRYPOINT ["python", "-m", "analyzer"]
CMD ["--log-dir", "/logs", "--out-dir", "/out"]
