# Contributing

- Go standard library only; open an issue before adding a dependency.
- Run `gofmt -l .`, `go vet ./...` and `go test -race ./...` before a PR. CI runs the same on Go 1.24.0 and the latest release.
- A bug fix comes with a test that fails without the fix.
- Behavior changes update the README and CHANGELOG in the same PR.
- Tests must not need root, network or a real container; use `internal/podman/podmantest` and fake binaries as the existing tests do.
