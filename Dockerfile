FROM node:20-slim
RUN apt-get update && apt-get install -y --no-install-recommends php-cli && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY package.json .
RUN npm install --omit=dev 2>/dev/null || npm install
COPY . .
EXPOSE 3000
CMD ["node", "server.js"]
