# Use the smaller 'slim' version of Python to reduce image size
FROM python:3.12-slim@sha256:e97cf9a2e84d604941d9902f00616db7466ff302af4b1c3c67fb7c522efa8ed9

# Set environment variables for better Cloud Run compatibility
ENV PYTHONUNBUFFERED=True
ENV APP_HOME=/app
ENV PORT=8080

WORKDIR ${APP_HOME}

# Create a non-root user
RUN adduser --system --group app

# Copy only essential files first to leverage Docker's caching
COPY requirements.txt ./
COPY .github/requirements-pip.txt ./.github/requirements-pip.txt

# Install dependencies efficiently
RUN pip install --no-cache-dir --require-hashes -r .github/requirements-pip.txt && \
    pip install --no-cache-dir -r requirements.txt

# Copy the rest of the app source code
COPY . ./

# Change ownership of the app directory to the non-root user
RUN chown -R app:app ${APP_HOME}

# Switch to non-root user
USER app

# Expose the port for Cloud Run
EXPOSE ${PORT}

CMD exec uvicorn main:app --host 0.0.0.0 --port ${PORT} --workers ${WEB_CONCURRENCY:-$(nproc)} --limit-concurrency 100 --timeout-keep-alive 120 --log-level info
