# بیلد باینری سبک Go
FROM golang:1.22-alpine AS builder
WORKDIR /build
COPY main.go .
RUN go mod init bermuda-panel && \
    CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o bermuda-panel main.go

# رانتایم کانتینر با دانلود مستقیم آخرین ریلیز پایدار هسته Xray
FROM alpine:3.20
WORKDIR /app

RUN apk add --no-cache curl ca-certificates tzdata && \
    mkdir -p /usr/local/bin /app/data && \
    curl -L -s https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-64.zip -o xray.zip && \
    unzip -q xray.zip xray -d /usr/local/bin/ && \
    chmod +x /usr/local/bin/xray && \
    rm xray.zip

ENV GOMEMLIMIT=384MiB
ENV GOMAXPROCS=2
ENV GOGC=50

COPY config.json /app/config.json
COPY --from=builder /build/bermuda-panel /app/bermuda-panel

EXPOSE 8080
CMD ["/app/bermuda-panel"]
