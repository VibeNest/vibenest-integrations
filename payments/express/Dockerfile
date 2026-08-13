FROM node:22.18.0-alpine
WORKDIR /app
ENV NODE_ENV=production PORT=3000
COPY package.json package-lock.json ./
RUN npm ci --omit=dev
COPY --chown=node:node . .
EXPOSE 3000
USER node
CMD ["node", "src/server.mjs"]
