FROM python:3.10-slim

WORKDIR /app

COPY . .

RUN pip install mysql-connector-python bcrypt

CMD ["python", "server.py"]
