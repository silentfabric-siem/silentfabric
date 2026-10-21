.PHONY: build test lint-rules up down

build:
	CGO_ENABLED=0 go build -o bin/silentfabric ./cmd/silentfabric

test:
	go vet ./...
	go test ./...

lint-rules: build
	bin/silentfabric rules check rules
	bin/silentfabric rules test rules testdata/events.ndjson

up:
	docker compose up -d --build

down:
	docker compose down
