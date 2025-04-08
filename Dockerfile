# Use the smaller 'slim' version of Python to reduce image size
FROM python:3.12-slim

# Set environment variables for better Cloud Run compatibility
ENV PYTHONUNBUFFERED=True
ENV APP_HOME=/app
ENV PORT=8080

WORKDIR ${APP_HOME}

# Copy only essential files first to leverage Docker's caching
COPY requirements.txt ./

# Install dependencies efficiently
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy the rest of the app source code
COPY . ./

# Expose the port for Cloud Run
EXPOSE ${PORT}

# Run uvicorn with multiple workers for better performance
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8080", "--workers", "8", "--limit-concurrency", "60", "--timeout-keep-alive", "120"]
