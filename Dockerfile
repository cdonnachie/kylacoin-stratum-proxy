FROM python:3.11-slim

# Install required system packages
RUN apt-get update && apt-get install -y \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

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