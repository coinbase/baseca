SERVICE := baseca
BUILD := $(shell git rev-parse --short HEAD)
GITHUB_REPO := github.com/coinbase/baseca

TARGET=target
BIN=$(TARGET)/bin
LDFLAGS=-ldflags "-X=main.Version=$(VERSION) -X=main.Build=$(BUILD)"

.PHONY: usage
usage:
	@ echo "Usage: make [`cat Makefile | grep "^[A-z\%\-]*:" | awk '{print $$1}' | sed "s/://g" | sed "s/%/[1-3]/g" | xargs`]"

.PHONY: info
info:
	@ echo SERVICE: $(SERVICE)
	@ echo BUILD: $(BUILD)

.PHONY: clean
clean: info
	@ rm -rf target

.PHONY: dependencies
dependencies: info clean
	@ go mod tidy

.PHONY: test
test: info clean dependencies
	@ go test -v -cover -short $$(go list ./... | grep -v /examples)

.PHONY: build
build: info clean
	@ GOOS=darwin GOARCH=amd64 go build $(LDFLAGS) -o $(BIN)/amd64/$(SERVICE) cmd/baseca/server.go
	@ GOOS=darwin GOARCH=arm64 go build $(LDFLAGS) -o $(BIN)/arm64/$(SERVICE) cmd/baseca/server.go

.PHONY: build_amd64
build_amd64: info clean
	@ GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o $(BIN)/linux/$(SERVICE) cmd/baseca/server.go

.PHONY: build_arm64
build_arm64: info clean
	@ GOOS=linux GOARCH=arm64 go build $(LDFLAGS) -o $(BIN)/linux/$(SERVICE) cmd/baseca/server.go

.PHONY: sqlc
sqlc:
	@ sqlc generate -f db/sqlc.yaml

.PHONY: mock
mock:
	@ mockgen --build_flags=--mod=mod -package mock -destination db/mock/store.go ${GITHUB_REPO}/db/sqlc Store

.PHONY: gen
gen: info clean
	@ buf generate protos --template protos/buf.gen.yaml

.PHONY: server 
server:
	@ database_credentials=${DATABASE_CREDENTIALS} \
		go run cmd/baseca/server.go

.PHONY: lint
lint:
	@ golangci-lint run

.PHONY: tools
tools:
	@ go install go.uber.org/mock/mockgen@latest
	@ go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.28
	@ go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.2
	@ go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
	@ which buf || (go install github.com/bufbuild/buf/cmd/buf@latest)

