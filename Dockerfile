FROM python:3.12-slim-bookworm

WORKDIR /app

# Install system dependencies (minimal now)
RUN apt-get update && \
    apt-get install -y git unzip curl && \
    rm -rf /var/lib/apt/lists/*

# Copy requirements
COPY app/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy app
COPY app/ .

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
