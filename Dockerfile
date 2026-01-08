FROM node:18-alpine

RUN apk add --no-cache \
    nmap \
    nikto \
    sslscan \
    curl \
    python3 \
    py3-pip \
    git

RUN pip3 install sqlmap

WORKDIR /app

COPY package*.json ./
RUN npm install

COPY . .

EXPOSE 4000

CMD ["node", "index.js"]
