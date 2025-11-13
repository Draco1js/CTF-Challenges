FROM node:alpine

# Set environment variable
ENV CHAL_NAME=Enumeration
ENV NODE_ENV=production
ENV PORT=3000
ENV FLAG=flag{A3GFCwlH8xwG}

# Set working directory
WORKDIR /app

# Copy package files
COPY package.json package-lock.json* ./

# Install dependencies
RUN npm install

# Copy application files
COPY tsconfig.json ./
COPY src/ ./src/
COPY public/ ./public/
COPY .env ./env

# # Copy the entrypoint script and set permissions
# COPY docker-entrypoint.sh /tmp/docker-entrypoint.sh
# RUN chmod +x /tmp/docker-entrypoint.sh

# Expose port 3000
EXPOSE 3000

CMD ["npm", "start"]


# Set the entrypoint
# ENTRYPOINT [ "/tmp/docker-entrypoint.sh" ]