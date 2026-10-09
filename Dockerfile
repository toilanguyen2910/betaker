FROM kalilinux/kali-rolling

LABEL description="BetHacker Sandbox - Kali Linux Security Environment"

ENV DEBIAN_FRONTEND=noninteractive
ENV HOME=/root

# Cài đặt Python và các công cụ pentest cơ bản
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    python3 \
    python3-pip \
    python3-venv \
    curl \
    wget \
    git \
    nmap \
    nikto \
    whatweb \
    dnsutils \
    net-tools \
    iputils-ping \
    sqlmap \
    gobuster \
    whois && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Cài đặt requirements
COPY requirements.txt .
RUN pip3 install --no-cache-dir --break-system-packages -r requirements.txt

# Copy mã nguồn
COPY . .

ENTRYPOINT ["python3", "main.py"]
