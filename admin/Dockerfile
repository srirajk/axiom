FROM node:20-alpine@sha256:fb4cd12c85ee03686f6af5362a0b0d56d50c58a04632e6c0fb8363f609372293 AS builder
WORKDIR /app
COPY admin/package*.json ./
RUN npm ci
COPY admin .
ARG VITE_AXIOM_ISSUER=http://localhost:8086
ARG VITE_AXIOM_API_URL=http://localhost:8086
ENV VITE_AXIOM_ISSUER=$VITE_AXIOM_ISSUER
ENV VITE_AXIOM_API_URL=$VITE_AXIOM_API_URL
RUN npm run build

FROM nginx:alpine@sha256:4a73073bd557c65b759505da037898b61f1be6cbcc3c2c3aeac22d2a470c1752
COPY --from=builder /app/dist /usr/share/nginx/html
COPY admin/nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 80
HEALTHCHECK --interval=10s --timeout=3s CMD wget -qO- http://127.0.0.1/ || exit 1
