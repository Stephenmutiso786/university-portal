FROM node:20-alpine

WORKDIR /app/backend

COPY backend/package*.json ./
RUN npm ci --omit=dev

COPY backend ./
COPY frontend ../frontend
RUN npx prisma generate

ENV NODE_ENV=production
ENV PORT=4000
ENV DATA_FILE=/app/backend/data/store.json

EXPOSE 4000

CMD ["node", "index.js"]
