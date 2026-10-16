FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app

# HTTP: 8000, DNS: 53 (UDP+TCP). 53'ü dinlemek için konteynere yetki gerekir.
EXPOSE 8000
EXPOSE 53/udp
EXPOSE 53/tcp

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
