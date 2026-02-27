.PHONY: build test

build:
	go build -v -o bin/slamhound ./cmd/slamhound

test:
	go test -race -v ./...
