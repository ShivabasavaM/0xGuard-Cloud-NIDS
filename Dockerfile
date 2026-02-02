# Lightweight Python
FROM python:3.9-slim

# Working Dir
WORKDIR /app

# Copy dependencies
COPY requirements.txt .

# Install ONLY what the API needs (Fast, Small)
RUN pip install --no-cache-dir fastapi uvicorn scikit-learn pandas joblib

# Copy the API and Model
COPY api.py .
COPY models/ ./models/

# Expose Web Port
EXPOSE 80

# Run with API Key support (passed via env var)
CMD ["uvicorn", "api:app", "--host", "0.0.0.0", "--port", "80"]