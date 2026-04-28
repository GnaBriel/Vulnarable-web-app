FROM node:20-alpine

WORKDIR /app

# Copy package files
COPY app/package*.json ./

# Install dependencies
RUN npm install

# Copy app source
COPY app/ .

# Copy database
COPY database/ ../database/

# Expose port
EXPOSE 3000

# FOR EDUCATIONAL PURPOSES ONLY
CMD ["node", "server.js"]
