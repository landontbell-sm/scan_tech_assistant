FROM python:3.14-slim
ENV PYTHONUNBUFFERED=1
# Resolve scan_tech_assistant imports to the source tree (where prompts/ and plugin_index.json live)
ENV PYTHONPATH=/app

WORKDIR /app

# Install apt dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    ripgrep \
    tar && \
    rm -rf /var/lib/apt/lists/*

# Install and extract the Nessus plugin archive
ADD https://storage.googleapis.com/secmet-public-archive/nessus_plugins.tar.gz /tmp/nessus_plugins.tar.gz
RUN mkdir -p /opt/nessus/lib/nessus/plugins/ && \
    tar -xzf /tmp/nessus_plugins.tar.gz -C /opt/nessus/lib/nessus/plugins/ && \
    rm /tmp/nessus_plugins.tar.gz

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Index the Nessus plugins by ID -> file path for fast lookup at runtime.
# Only the indexing modules are copied first so app changes don't trigger a re-index.
COPY scan_tech_assistant/__init__.py scan_tech_assistant/build_index.py scan_tech_assistant/nasl_regex.py scan_tech_assistant/
RUN python -m scan_tech_assistant.build_index

# Copy the rest of the app
COPY scan_tech_assistant/ scan_tech_assistant/

WORKDIR /app/scan_tech_assistant
EXPOSE 8000

CMD ["chainlit", "run", "app.py", "--host", "0.0.0.0", "--port", "8000"]
