FROM node:24-bookworm AS dependencies

WORKDIR /app

COPY package.json package-lock.json ./

RUN npm ci --omit=dev --ignore-scripts \
    && npm cache clean --force

FROM node:24-bookworm-slim AS runtime

ENV NODE_ENV=production

WORKDIR /app

COPY --from=dependencies --chown=node:node /app/node_modules ./node_modules
COPY --chown=node:node package.json *.js ./

USER node

CMD ["node", "index.js"]