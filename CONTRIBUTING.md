# Contributing to Fluxgate

Thank you for your interest in contributing to Fluxgate.

## Getting Started

1. Fork the repository and clone your fork.
2. Ensure you have Go 1.22 or later installed.
3. Run `go mod download` to fetch dependencies.

## Development Workflow

### Run Tests

```bash
go test ./...
```

### Format Code

```bash
gofmt -w .
```

### Vet Code

```bash
go vet ./...
```

### Build

```bash
go build ./cmd/fluxgate
```

## Submitting Changes

1. Create a feature branch from `main`.
2. Make your changes, ensuring all tests pass.
3. Format your code with `gofmt`.
4. Write clear commit messages.
5. Open a pull request against `main`.

## Adding Detection Rules

New rules should:
- Follow the existing rule function signature in `internal/scanner/rules.go`.
- Include a unique rule ID (e.g., `FG-006`).
- Have corresponding test fixtures in `test/fixtures/`.
- Include unit tests in `internal/scanner/rules_test.go`.

## Code of Conduct

Be respectful and constructive. We are all working toward safer CI/CD pipelines.

## License

By contributing, you agree that your contributions will be licensed under the Apache 2.0 License.
