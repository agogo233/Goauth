# Build stage
FROM golang:1.26-alpine AS builder

RUN apk add --no-cache gcc musl-dev sqlite-dev

WORKDIR /build

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=1 go build -ldflags="-s -w" -o /goauth ./cmd/server

# Runtime stage
FROM alpine:3.21

RUN apk add --no-cache ca-certificates sqlite-libs tzdata

WORKDIR /app

COPY --from=builder /goauth /app/goauth
COPY --from=builder /build/web /app/web

RUN mkdir -p /app/data

EXPOSE 3000

VOLUME ["/app/data"]

ENTRYPOINT ["/app/goauth"]
CMD ["serve"]
