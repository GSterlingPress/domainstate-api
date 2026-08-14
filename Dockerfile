FROM node:20-alpine
WORKDIR /app
COPY package.json ./
COPY . .
ENV PORT=8789
EXPOSE 8789
CMD ["node","server.mjs"]
