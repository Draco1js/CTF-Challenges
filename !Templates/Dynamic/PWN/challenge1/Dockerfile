# Use the official Python image with version 3.9
FROM python:3.9-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Set working directory
WORKDIR /app

# Install gcc and other required packages
RUN apt-get update && \
    apt-get install -y gcc libc6-dev socat && \
    rm -rf /var/lib/apt/lists/*

# Copy the source code for compilation
COPY challenge1.c /app/

# Compile challenge1.c with specified GCC flags (yaha jis trah binary compile hoti wo command)
RUN gcc -o challenge1 challenge1.c -no-pie -fno-stack-protector -z execstack

# Copy the entrypoint script
COPY docker-entrypoint.sh /tmp/docker-entrypoint.sh
RUN chmod +x /tmp/docker-entrypoint.sh

# Expose port 1337 for socat
EXPOSE 1337

# Set the entry point
ENTRYPOINT ["/tmp/docker-entrypoint.sh"]
