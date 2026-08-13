FROM node:22.18.0-alpine
WORKDIR /app
ENV NODE_ENV=production PORT=8080
COPY package.json package-lock.json ./
RUN npm ci --omit=dev
COPY --chown=node:node . .
EXPOSE 8080
USER node
CMD ["node", "src/server.mjs"]
