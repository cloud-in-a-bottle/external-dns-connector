default: test

# Install the Python test dependencies and the playwright chromium browser.
setup:
    uv sync
    uv run playwright install chromium

# Run the app locally on http://localhost:8080 against a scratch database.
run:
    OPENHOST_APP_NAME=external-dns-connector OPENHOST_SQLITE_MAIN=./local.db \
      go run ./cmd/dns-connector

# Fast feedback: the Go unit and HTTP-level tests. No podman needed.
test-go:
    go test ./...

# The full suite: Go tests, then the containerized integration tests through the real router.
test: test-go
    uv run pytest

# Format, vet, and typecheck.
check:
    gofmt -l -w .
    go vet ./...
    go build ./...

# Build the container image.
build:
    podman build -t external-dns-connector .
