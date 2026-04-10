FROM node:20-alpine AS builder

WORKDIR /app

COPY package*.json ./
RUN npm install --registry=https://registry.npmmirror.com --legacy-peer-deps && npm install less@4.1.3 --registry=https://registry.npmmirror.com --legacy-peer-deps

COPY . .
RUN npm run build:normal

FROM nginx:alpine

RUN apk add --no-cache tzdata
ENV TZ=Asia/Shanghai

COPY --from=builder /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
