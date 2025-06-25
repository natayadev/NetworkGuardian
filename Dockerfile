# Instructions to build and run the Docker container
# docker run --rm -it --network host -v $(pwd)/trusted_devices.json:/app/trusted_devices.json -v $(pwd)/whitelist.json:/app/whitelist.json mybotimage

FROM python:3.13-slim

WORKDIR /app

RUN apt-get update && apt-get install -y git iproute2 iputils-ping tcpdump libcap2-bin && rm -rf /var/lib/apt/lists/*

COPY . /app

RUN pip install --no-cache-dir -r requirements.txt

RUN setcap cap_net_raw,cap_net_admin=eip /usr/local/bin/python3.13

EXPOSE 80

CMD ["python", "bot.py"]
