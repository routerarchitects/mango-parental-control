############################
# Stage 1: Builder
# ############################
FROM golang:1.25.1-alpine AS builder

RUN apk add --no-cache git ca-certificates build-base

WORKDIR /src/mango-parental-control

# Cache dependencies
COPY go.mod go.sum* ./
RUN go mod download

# Copy source code
COPY . .

ARG VERSION
ARG BUILD_TIMESTAMP
ARG COMMIT_HASH
ARG APP_NAME=mango-parental-control

ENV CGO_ENABLED=0 \
    GOOS=linux \
    GOFLAGS=-buildvcs=false

# Run tests before compiling
RUN go test ./...

# Compile with LDFlags for buildinfo package injection
RUN mkdir -p /out && \
    VERSION_VALUE="${VERSION:-$(git describe --tags 2>/dev/null || echo -n 'v0.1.0')}" && \
    BUILD_TIMESTAMP_VALUE="${BUILD_TIMESTAMP:-$(date -u +%s)}" && \
    COMMIT_HASH_VALUE="${COMMIT_HASH:-$(git rev-parse --short HEAD 2>/dev/null || echo unknown)}" && \
    go build -trimpath \
      -ldflags="-s -w \
      -X github.com/routerarchitects/ra-common-mods/buildinfo.version=${VERSION_VALUE} \
      -X github.com/routerarchitects/ra-common-mods/buildinfo.buildTimestamp=${BUILD_TIMESTAMP_VALUE} \
      -X github.com/routerarchitects/ra-common-mods/buildinfo.commitHash=${COMMIT_HASH_VALUE}" \
      -o "/out/${APP_NAME}" "./cmd"

############################
# Stage 2: Runtime
# ############################
FROM alpine:3.20

RUN apk add --no-cache ca-certificates bash curl

WORKDIR /app

ARG APP_NAME=mango-parental-control
ARG VERSION
ARG BUILD_TIMESTAMP
ARG COMMIT_HASH
ARG DEPLOYMENT_ENV=dev

ENV SERVICE_VERSION="${VERSION}" \
    BUILD_TIMESTAMP="${BUILD_TIMESTAMP}" \
    COMMIT_HASH="${COMMIT_HASH}" \
    ENVIRONMENT="${DEPLOYMENT_ENV}"

# Copy compiled binary from builder
COPY --from=builder /out/${APP_NAME} /app/${APP_NAME}

# Copy database schema migrations
COPY --from=builder /src/mango-parental-control/db /app/db

# Create non-root user for security execution
RUN adduser -D -u 65532 appuser
USER appuser

# Expose Public Port (16008) and Private/System Port (17008)
EXPOSE 16008 17008

ENTRYPOINT ["/app/mango-parental-control"]
