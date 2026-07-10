FROM node:latest AS deps

ARG API_TOKEN=example
WORKDIR /app
COPY package*.json ./
RUN npm install

FROM node:latest AS runner
WORKDIR /app
COPY . .
CMD ["node", "server.js"]
