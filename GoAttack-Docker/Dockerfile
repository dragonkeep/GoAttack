# Stage 1: Build gobuster (requires Go 1.25+)
FROM golang:alpine AS stage-gobuster
RUN apk add --no-cache git
ENV GOPROXY=https://goproxy.cn,direct
RUN go install github.com/OJ/gobuster/v3@latest

# Stage 2: Build main app (requires Go 1.24 for stability/compatibility)
FROM golang:1.24-alpine AS stage-api
WORKDIR /app
ENV GOPROXY=https://goproxy.cn,direct
RUN apk add --no-cache gcc musl-dev linux-headers nmap nmap-scripts libpcap-dev git

COPY go.mod go.sum ./
COPY service/lib/nuclei/ service/lib/nuclei/
RUN go mod download

COPY . .
RUN CGO_ENABLED=1 go build -trimpath -ldflags="-w -s" -o goattack main.go

# Stage 3: Final image
FROM alpine:3.19
WORKDIR /app
RUN apk add --no-cache nmap nmap-scripts tzdata libpcap chromium nss freetype harfbuzz ca-certificates fontconfig font-noto-cjk ttf-freefont && fc-cache -f

ENV TZ=Asia/Shanghai
ENV CHROME_PATH=/usr/bin/chromium-browser
RUN mkdir -p /app/logs /app/uploads /app/data /app/common/sql /app/service/plugins/gobuster

COPY --from=stage-api /app/goattack .
COPY --from=stage-gobuster /go/bin/gobuster /usr/bin/gobuster

COPY --from=stage-api /app/common/sql/init.sql ./common/sql/init.sql
COPY --from=stage-api /app/service/lib ./service/lib
COPY --from=stage-api /app/service/plugins ./service/plugins
COPY --from=stage-api /app/service/dict ./service/dict

# Create symlink for gobuster plugin
RUN ln -sf /usr/bin/gobuster /app/service/plugins/gobuster/gobuster

# Create a default configuration (assuming environment variables can override)
# In production, users should mount their own config directory

EXPOSE 3000

CMD ["./goattack"]
