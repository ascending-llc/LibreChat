FROM python:3.10-slim

WORKDIR /app

# Install necessary dependencies for FastAPI and boto3
RUN pip install fastapi uvicorn boto3 requests pyjwt

# Copy the server code
COPY server.py /app/

EXPOSE 8080

CMD ["uvicorn", "server:app", "--host", "0.0.0.0", "--port", "8080"]
