# syntax=docker/dockerfile:1
# Build the dashboard and serve the static assets with nginx. The nginx config
# (SPA routing + /graphql proxy to the backend) is supplied at deploy time by
# the Helm chart via a mounted ConfigMap.

FROM node:20-alpine AS build
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build

FROM nginx:1.27-alpine
COPY --from=build /app/dist /usr/share/nginx/html
EXPOSE 80
