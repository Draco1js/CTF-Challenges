FROM node:18

# Set working directory
WORKDIR /app

# Copy package files and install dependencies
COPY package*.json ./
RUN npm install

# Copy application code and other necessary files
COPY index.js /app/
COPY public /app/public/
COPY keys /app/keys/

# Copy the entrypoint script and set permissions
COPY docker-entrypoint.sh /tmp/docker-entrypoint.sh
RUN chmod +x /tmp/docker-entrypoint.sh

# Expose port 3000 for the Node.js application
EXPOSE 3000

# Set the entrypoint
ENTRYPOINT [ "/tmp/docker-entrypoint.sh" ]