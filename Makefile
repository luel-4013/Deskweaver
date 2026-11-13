BINARY  := deskweaver
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo 0.1.0-dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
DATE    ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

LDFLAGS := -s -w \
	-X github.com/luel-4013/deskweaver/internal/version.Version=$(VERSION) \
	-X github.com/luel-4013/deskweaver/internal/version.Commit=$(COMMIT) \
	-X github.com/luel-4013/deskweaver/internal/version.BuildDate=$(DATE)

.PHONY: all build test vet fmt fmt-check check install snapshot clean

all: build

build:
	CGO_ENABLED=0 go build -trimpath -ldflags '$(LDFLAGS)' -o $(BINARY) ./cmd/deskweaver

test:
	go test ./...

vet:
	go vet ./...

fmt:
	gofmt -w cmd internal

fmt-check:
	@out="$$(gofmt -l cmd internal)"; \
	if [ -n "$$out" ]; then \
		echo "gofmt required for:"; echo "$$out"; exit 1; \
	fi

check: fmt-check vet test

install:
	CGO_ENABLED=0 go install -trimpath -ldflags '$(LDFLAGS)' ./cmd/deskweaver

snapshot:
	goreleaser release --snapshot --clean

clean:
	rm -f $(BINARY)
	rm -rf dist
