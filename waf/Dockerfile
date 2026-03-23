FROM python:3.9-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
# Patch pyicap to enforce bytes for headers
RUN sed -i 's/def set_icap_header(self, header, value):/def set_icap_header(self, header, value):\n        if isinstance(header, str): header = header.encode()\n        if isinstance(value, str): value = value.encode()/' /usr/local/lib/python3.9/site-packages/pyicap.py && \
    sed -i 's/def set_enc_header(self, header, value):/def set_enc_header(self, header, value):\n        if isinstance(header, str): header = header.encode()\n        if isinstance(value, str): value = value.encode()/' /usr/local/lib/python3.9/site-packages/pyicap.py && \
    sed -i 's/def set_enc_status(self, status):/def set_enc_status(self, status):\n        if isinstance(status, str): status = status.encode()/' /usr/local/lib/python3.9/site-packages/pyicap.py
COPY server.py .
EXPOSE 1344
CMD ["python", "-u", "server.py"]
