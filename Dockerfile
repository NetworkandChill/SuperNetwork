FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY server.py schema_empty.sql import_report.json /app/
COPY web/ /app/web/
RUN useradd --uid 10001 --create-home crm && mkdir -p /data && chown crm:crm /data
USER crm
ENV NC_HOST=0.0.0.0 NC_ALLOW_REMOTE=1 NC_PUBLIC_TLS=1 NC_DB=/data/nc_club.sqlite3
CMD ["python", "server.py"]