FROM python:3.10-slim

WORKDIR /app

# Copy requirements.txt from root into Docker context
COPY ../requirements.txt .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the server files
COPY . .

CMD ["python", "server.py"]
