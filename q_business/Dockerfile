# Use an official Node.js runtime as a parent image
FROM node:20.8.1

# Set the working directory inside the container
WORKDIR /app

# Copy package.json and package-lock.json before installing dependencies
COPY package.json package-lock.json server.js ./

# Install dependencies
RUN npm install

# Install PM2 globally
RUN npm install -g pm2

# Expose the application port
EXPOSE 8080

# Start the application using PM2
CMD ["pm2-runtime", "start", "server.js"]
