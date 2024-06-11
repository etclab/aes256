all: vet

vet: fmt
	go vet ./...

fmt:
	go fmt ./...

.PHONY: all fmt vet
