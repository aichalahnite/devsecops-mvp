FROM python:3.12-slim-bookworm

WORKDIR /app

# Install system dependencies + Docker CLI
RUN apt-get update && \
    apt-get install -y \
    git \
    unzip \
    curl \
    docker.io \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements
COPY app/requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY app/ .

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
