# Mango Cloud Go Foundation Service

A standardized, production-ready microservice foundation skeleton for the Mango Cloud (OpenWiFi) environment. This service provides a pre-configured architecture featuring dual-port HTTP server separation, PostgreSQL integration, automated schema migrations, and Service Discovery out-of-the-box.

---

## Folder Structure

```text
├── .github/
│   └── workflows/
│       └── ci.yaml              # Continuous Integration workflow configuration
├── cmd/
│   └── main.go                  # Boilerplate entrypoint (Config load, Logger init, runs App, OS signals)
├── db/
│   └── schema/                  # SQL schema migrations directory
│       └── 0001_initial.sql     # Placeholder SQL table setup
├── docs/                        # Specifications and API contracts templates
│   ├── requirements.md          # Requirements template
│   ├── design.md                # Technical design doc template
│   └── openapi.yaml             # OpenAPI (Swagger) api definition
├── configs/                     # Configurations for development/testing
│   └── local-dev.env            # Env configuration for local running (outside Docker)
├── deployments/                 # Deployment-related configurations
│   └── docker-compose/
│       ├── docker-compose.env   # Env template for Docker Compose execution
│       └── docker-compose.yaml  # Docker Compose deployment integration template
├── external/                    # Third-party API client integration wrappers
│   └── README.md                # Developer guide for external adapters
├── internal/
│   ├── app/                     # Application wiring and dependency injection
│   │   └── app.go               # Dynamic struct creation, DB pool, and module boot
│   ├── config/                  # caarlos0/env environment parsing
│   ├── db/                      # Connection pool (pgxpool) & migration engine
│   ├── http/                    # Routing, middleware, and Dual TLS engine
│   │   ├── handlers/            # REST API endpoint handlers
│   │   │   ├── handlers.go      # Implementation of route logic
│   │   │   └── handlers_test.go # Focused unit tests for handler helpers & validation
│   │   └── routes/              # HTTP router setup and path registration
│   │       ├── routes.go        # Router configuration
│   │       └── routes_test.go   # Integration tests for route paths
│   ├── models/                  # Domain-level request/response model structs
│   └── services/                # Business logic interfaces and services
├── .dockerignore                # Exclusions for Docker build context
├── .gitignore                   # Exclusions for Git repository
├── Dockerfile                   # Multi-stage production container configuration
├── Makefile                     # Build, run, test, and containerize commands
├── README.md                    # This developer guide
```

---

## Running Tests

### Full Test Suite (requires running PostgreSQL DB)
```bash
make test
```

### Unit Tests Only (no database required)
```bash
go test -v ./internal/http/handlers
```

---

## Phase 1: Scaffolding a New Service

To initialize a new repository using this foundation template:

1. **Clone both the template and your new repository in a workspace:**
   ```bash
   mkdir <workspace-dir>
   cd <workspace-dir>
   git clone git@github.com:routerarchitects/mango-parental-control.git
   git clone git@github.com:routerarchitects/<new-service-name>.git
   ```

2. **Copy the template files into your new repository:**
   ```bash
   cd <new-service-name>
   git checkout -b base-service-scaffold
   cp -rf ../mango-parental-control/!(.git|.idea|.vscode|tmp|bin) .
   ```

3. **Commit and push the scaffold as the first commit:**
   ```bash
   git add .
   git commit -m "Initial service scaffold"
   git push origin base-service-scaffold
   ```

---

## Phase 2: Configuring your New Service

Once you have initialized the repository (Phase 1), run the following commands to customize the service name and port bindings:

1. **Customize the service name and ports**:
   Define your service settings as environment variables, then run the customization and rename commands:
   ```bash
   # 1. Define your new service configurations (e.g. PUBLIC_PORT="16008", PRIVATE_PORT="17008"):
   export NEW_SERVICE_NAME="<new-service-name>"
   export PUBLIC_PORT="<public-port>"
   export PRIVATE_PORT="<private-port>"

   # 2. Customize all files using the variables:
   find . -type f -not -path '*/.git/*' -exec sed -i \
       -e "s/mango-parental-control/${NEW_SERVICE_NAME}/g" \
       -e "s/mango-parental-control/${NEW_SERVICE_NAME}/g" \
       -e "s/16008/${PUBLIC_PORT}/g" \
       -e "s/17008/${PRIVATE_PORT}/g" {} +

   # 3. Rename the compose environment file:
   mv deployments/docker-compose/docker-compose.env deployments/docker-compose/${NEW_SERVICE_NAME}.env
   ```

2. **Commit your customization changes**:
   ```bash
   git add .
   git commit -m "refactor: rename service and customize ports"
   ```

---

## Phase 3: Docker Integration

### 1. Build the Image
```bash
make docker-build
```

### 2. Integrate with Mango Cloud Compose Stack
1. Copy the customized environment file manually:
   ```bash
   cp deployments/docker-compose/${NEW_SERVICE_NAME}.env /path_to/mango-cloud-deployment/docker-compose/
   ```

2. Paste the service block from `deployments/docker-compose/docker-compose.yaml` inside the `services:` block of your deployment's `docker-compose.yml`.

3. Re-launch the compose deployment:
   ```bash
   docker compose up
   ```


