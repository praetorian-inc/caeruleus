# Convenience targets for caeruleus. The Go toolchain handles the real build;
# these wrappers exist so common workflows are one keystroke away and so
# CI invocations don't need to remember subcommand layouts.

CAERULEUS := ./caeruleus
HARNESS   := ./shell-harness
ADDR      ?=

.PHONY: build harness test test-unit test-shell test-shell-device clean

build:
	go build -o $(CAERULEUS) ./cmd/caeruleus

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

clean:
	rm -f $(CAERULEUS) $(HARNESS)
