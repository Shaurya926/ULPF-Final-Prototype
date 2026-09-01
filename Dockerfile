FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    ULPF_DB_PATH=/data/ulpf.db \
    ULPF_PLUGIN_DIR=/app/plugins

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN mkdir -p /data && useradd --create-home --uid 10001 ulpf && chown -R ulpf:ulpf /app /data
USER ulpf
EXPOSE 8000
CMD ["uvicorn", "ulpf.api:app", "--host", "0.0.0.0", "--port", "8000"]
