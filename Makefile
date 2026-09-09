# Convenience targets for caeruleus. The Go toolchain handles the real build;
# these wrappers exist so common workflows are one keystroke away and so
# CI invocations don't need to remember subcommand layouts.

CAERULEUS := ./caeruleus
HARNESS   := ./shell-harness
ADDR      ?=

.PHONY: build install harness test test-unit test-shell test-shell-device clean cli-docs

build:
	go build -o $(CAERULEUS) ./cmd/caeruleus

# Install the caeruleus binary onto $PATH (into $GOBIN, else $GOPATH/bin).
# Equivalent to: go install github.com/praetorian-inc/caeruleus/cmd/caeruleus@latest
install:
	go install ./cmd/caeruleus

harness:
	go build -o $(HARNESS) ./cmd/shell-harness

test: test-unit build harness test-shell

# Pure Go unit tests - no BLE peripheral required. Safe to run in CI.
test-unit:
	go test ./...

# Shell tests - no BLE peripheral required. Safe to run in CI.
test-shell: build harness
	$(HARNESS) --keep-running

# Tests against a real BLE peripheral. Usage:
#   make test-shell-device ADDR=XX:XX:XX:XX:XX:XX
test-shell-device: build harness
	@if [ -z "$(ADDR)" ]; then \
		echo "ADDR=XX:XX:XX:XX:XX:XX is required for device tests" >&2; \
		exit 2; \
	fi
	$(HARNESS) --addr $(ADDR) --keep-running

cli-docs:
	@GOWORK=off go test ./internal/cli -list 'TestCLISurface' | grep -qE '^TestCLISurface$$' \
	  || { echo "cli-docs: 'go test -list' did not report TestCLISurface in ./internal/cli. Either the -update writer was renamed, or the package failed to build -- run 'go build ./internal/cli' to tell which. 'go test -run' exits 0 when its pattern matches nothing, so without this check the target would report success having regenerated nothing at all."; exit 1; }
	GOWORK=off go test ./internal/cli -run 'TestCLISurface' -count=1 -update

clean:
	rm -f $(CAERULEUS) $(HARNESS)
