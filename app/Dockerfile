FROM python:3.12-slim
WORKDIR /app
COPY app/requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt
COPY app /app/app
COPY samples /app/samples
# Only public CA certificate (never private keys)
COPY wazuh/config/wazuh_indexer_ssl_certs/root-ca.pem /app/certs/root-ca.pem
RUN chmod 644 /app/certs/root-ca.pem
ENV DB_PATH=/data/demo.sqlite SAMPLES_PATH=/app/samples/events.json
RUN useradd --create-home --uid 10001 soc && mkdir /data && chown soc:soc /data
USER soc
EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
