FROM golang:1.26.0-alpine AS builder

WORKDIR /app

RUN apk add --no-cache tzdata

COPY go.mod go.sum ./
RUN go mod download -x

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o auth-service ./cmd/api/main.go

FROM scratch

WORKDIR /app

COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo

COPY --from=builder /app/auth-service .
COPY --from=builder /app/private_key.pem .

EXPOSE 8081

CMD ["./auth-service"]