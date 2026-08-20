FROM python:3.13-slim
ENV PYTHONUNBUFFERED=1

WORKDIR /app

# Install apt dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    ripgrep \
    tar

# Install and extract the Nessus plugin archive
ADD https://storage.googleapis.com/secmet-public-archive/nessus_plugins.tar.gz /tmp/nessus_plugins.tar.gz
RUN mkdir -p /opt/nessus/lib/nessus/plugins/ && \
    tar -xzf /tmp/nessus_plugins.tar.gz -C /opt/nessus/lib/nessus/plugins/ && \
    rm /tmp/nessus_plugins.tar.gz

# Install the scan_tech_assistant package and its dependencies
COPY . .
RUN pip install --no-cache-dir .

# Index the Nessus plugins by ID -> file path for fast lookup at runtime
RUN cd scan_tech_assistant && python build_index.py

WORKDIR /app/scan_tech_assistant
EXPOSE 8000

CMD ["chainlit", "run", "app.py", "--host", "0.0.0.0", "--port", "8000"]