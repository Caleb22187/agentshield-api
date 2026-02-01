FROM node:20-slim
WORKDIR /app
COPY package*.json ./
RUN npm ci --production
COPY . .
EXPOSE 3847
ENV PORT=3847
CMD ["node", "server.js"]
