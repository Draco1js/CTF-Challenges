# Use the official Python image with version 3.9
FROM python:3.9-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Set working directory
WORKDIR /app

# Install netcat and other required packages
RUN apt-get update && apt-get install -y socat && rm -rf /var/lib/apt/lists/*

# Copy the crypto challenge script and flag file
COPY main.py /app/


# Copy the entrypoint script
COPY docker-entrypoint.sh /tmp/docker-entrypoint.sh
RUN chmod +x /tmp/docker-entrypoint.sh

# Expose port 1337 for netcat
EXPOSE 1337

# Set the entry point
ENTRYPOINT ["/tmp/docker-entrypoint.sh"]