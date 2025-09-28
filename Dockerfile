FROM ubuntu:22.04

# Install Python and required packages
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    python3-dev \
    gcc \
    && rm -rf /var/lib/apt/lists/* \
    && ln -sf /usr/bin/python3 /usr/bin/python \
    && ln -sf /usr/bin/pip3 /usr/bin/pip

# Set working directory
WORKDIR /app

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy and install wheel file (if present)
# COPY *.whl ./
# RUN pip install --no-cache-dir *.whl || echo "No wheel files found, skipping..."

# Copy application code
COPY kcn-lcn-stratum-proxy.py .
COPY entrypoint.sh .

# Make entrypoint script executable
RUN chmod +x /app/entrypoint.sh

# Create directory for submit history
RUN mkdir -p /app/submit_history

# Expose stratum port
EXPOSE 54321

# Run the proxy
CMD ["/app/entrypoint.sh"]