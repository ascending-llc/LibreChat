# Use an official Node.js runtime as a parent image
FROM node:20.8.1

# Set the working directory inside the container
WORKDIR /app

# Copy package.json and package-lock.json before installing dependencies
COPY package.json package-lock.json ./

# Install dependencies
RUN npm install

# Copy the rest of the application files
COPY . .

# Expose the application port
EXPOSE 8080

# Start the application
CMD ["node", "server.js"]