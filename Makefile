.PHONY: build test generate check
build:
	go build -trimpath -o bin/uptimeify ./cmd/uptimeify
test:
	go test ./...
generate:
	go run ./internal/gen/cmd -spec spec/openapi.json -overrides internal/gen/overrides.json -out internal/commands/ops.json
check: test
	go vet ./...
	go run golang.org/x/vuln/cmd/govulncheck@v1.10.0 ./...
