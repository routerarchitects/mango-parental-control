# ==============================================================================
# Development Makefile for mango-parental-control
# ==============================================================================

APP_NAME = mango-parental-control
VERSION ?= v0.1.0
COMMIT_HASH = $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
BUILD_TIMESTAMP = $(shell date -u +%s)
LDFLAGS = -X github.com/routerarchitects/ra-common-mods/buildinfo.version=$(VERSION) \
          -X github.com/routerarchitects/ra-common-mods/buildinfo.buildTimestamp=$(BUILD_TIMESTAMP) \
          -X github.com/routerarchitects/ra-common-mods/buildinfo.commitHash=$(COMMIT_HASH)

.PHONY: all build run test tidy fmt lint clean docker-build docker-run

all: build

build:
	@echo "Compiling mango-parental-control binary..."
	go build -ldflags="-s -w $(LDFLAGS)" -o $(APP_NAME) ./cmd

certs:
	@if [ ! -f certs/restapi-cert.pem ] || [ ! -f certs/restapi-key.pem ]; then \
		echo "Generating self-signed TLS certificates under ./certs..."; \
		mkdir -p certs; \
		openssl req -newkey rsa:2048 -nodes -keyout certs/restapi-key.pem \
			-x509 -days 365 -out certs/restapi-cert.pem \
			-subj "/C=US/ST=State/L=City/O=Organization/OU=Unit/CN=localhost" 2>/dev/null; \
		cp certs/restapi-cert.pem certs/restapi-ca.pem; \
	fi

run: certs
	@echo "Running mango-parental-control locally..."
	@if [ -f configs/local-dev.env ]; then \
		set -a && . ./configs/local-dev.env && set +a && go run ./cmd; \
	else \
		go run ./cmd; \
	fi

test:
	@echo "Running unit and integration tests..."
	go test -v -race ./...

tidy:
	@echo "Tidying module dependencies..."
	go mod tidy

fmt:
	@echo "Formatting source files..."
	go fmt ./...

lint:
	@echo "Analyzing source code..."
	go vet ./...

clean:
	@echo "Cleaning build outputs..."
	rm -f $(APP_NAME)

docker-build:
	@echo "Building Docker image $(APP_NAME):latest..."
	docker build \
		--build-arg APP_NAME=$(APP_NAME) \
		--build-arg VERSION=$(VERSION) \
		--build-arg BUILD_TIMESTAMP=$(BUILD_TIMESTAMP) \
		--build-arg COMMIT_HASH=$(COMMIT_HASH) \
		-t $(APP_NAME):latest .

docker-run: certs
	@echo "Starting Docker container $(APP_NAME) in foreground..."
	docker run --rm -it \
		--env-file deployments/docker-compose/$(APP_NAME).env \
		-v $(PWD)/certs:/app/certs \
		-p 16008:16008 -p 17008:17008 \
		$(APP_NAME):latest
