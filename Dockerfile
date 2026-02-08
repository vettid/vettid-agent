FROM golang:1.24-alpine AS builder

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build \
    -ldflags "-X main.version=$(cat VERSION 2>/dev/null || echo dev) -X main.commit=$(git rev-parse --short HEAD 2>/dev/null || echo unknown)" \
    -o /vettid-agent ./cmd/vettid-agent

FROM alpine:3.21
RUN apk add --no-cache ca-certificates
COPY --from=builder /vettid-agent /usr/local/bin/vettid-agent

# Agent connector listens on localhost only — expose for container networking
EXPOSE 7443

ENTRYPOINT ["vettid-agent"]
CMD ["start"]
