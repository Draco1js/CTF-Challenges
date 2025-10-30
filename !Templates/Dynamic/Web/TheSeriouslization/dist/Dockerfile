FROM php:8.0-cli

# Set environment variable (optional, keeps consistency)
ENV CHAL_NAME=theSeriouslization

# Set working directory
WORKDIR /app

# Copy the application file
COPY index.php /app/

# Copy the entrypoint script and set permissions
COPY docker-entrypoint.sh /tmp/docker-entrypoint.sh
RUN chmod +x /tmp/docker-entrypoint.sh

# Expose port 80 for the web server
EXPOSE 80

# Set the entrypoint
ENTRYPOINT [ "/tmp/docker-entrypoint.sh" ]