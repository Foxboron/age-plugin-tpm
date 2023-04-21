
all: build

build: age-plugin-tpm

age-plugin-tpm:
	go build -o age-plugin-tpm ./cmd/age-plugin-tpm

test:
	go test ./...

check:
	staticcheck ./...

.PHONY: test
