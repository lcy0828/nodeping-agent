# syntax=docker/dockerfile:1

FROM --platform=$BUILDPLATFORM golang:1.25-alpine AS builder

ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_DATE=unknown

WORKDIR /src

RUN apk add --no-cache ca-certificates tzdata

COPY go.mod go.sum ./
RUN go mod download

COPY cmd ./cmd
COPY internal ./internal

RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build \
    -trimpath \
    -ldflags="-s -w -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.buildDate=${BUILD_DATE}" \
    -o /out/nodeping-agent ./cmd/nodeping-agent

FROM alpine:3.22

RUN apk add --no-cache ca-certificates tzdata iputils traceroute mtr \
    && addgroup -S nodeping \
    && adduser -S -G nodeping -h /var/lib/nodeping-agent nodeping \
    && mkdir -p /var/lib/nodeping-agent \
    && chown -R nodeping:nodeping /var/lib/nodeping-agent

COPY --from=builder /out/nodeping-agent /usr/local/bin/nodeping-agent

ENV NODEPING_AGENT_TOKEN_FILE=/var/lib/nodeping-agent/agent-token
VOLUME ["/var/lib/nodeping-agent"]

USER nodeping
STOPSIGNAL SIGTERM
ENTRYPOINT ["/usr/local/bin/nodeping-agent"]
