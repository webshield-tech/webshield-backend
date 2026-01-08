FROM ubuntu:22.04

RUN apt-get update && apt-get install -y \
    nodejs \
    npm \
    nmap \
    nikto \
    sqlmap \
    sslscan \
    curl \
    python3 \
    python3-pip \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY package*.json ./
RUN npm install

COPY . .

EXPOSE 4000

# Run from src folder
CMD ["node", "src/index.js"]