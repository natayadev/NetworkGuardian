FROM python:3.13-slim

WORKDIR /app

RUN apt-get update && apt-get install -y git && rm -rf /var/lib/apt/lists/*

RUN git clone https://github.com/natayadev/NetworkGuardian.git .

RUN pip install --no-cache-dir -r requirements.txt

EXPOSE 80

CMD ["python", "bot.py"]
