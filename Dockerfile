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

# SECURITY (#66): drop root. The agent only needs to read its own
# config dir, write the connection.enc envelope, and bind to a
# user-writable socket / port — none of that needs uid 0.
#
# Explicit numeric UID/GID 10001 so Kubernetes runAsNonRoot policies
# and distroless overlays can pin against it. -S = system group/
# user (no shell, no password), -D = no password, -H = no home
# auto-create (handled explicitly below).
RUN addgroup -S -g 10001 vettid \
 && adduser -S -D -H -u 10001 -G vettid vettid

COPY --from=builder /vettid-agent /usr/local/bin/vettid-agent

# Default config dir for the non-root user. Mount over this with a
# host volume or Kubernetes Secret-backed path to persist creds.
RUN mkdir -p /home/vettid/.vettid-agent \
 && chown -R vettid:vettid /home/vettid

USER vettid:vettid
WORKDIR /home/vettid

# Agent connector listens on localhost only — expose for container networking
EXPOSE 7443

ENTRYPOINT ["vettid-agent"]
CMD ["start"]
