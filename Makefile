.PHONY: gen test lint qa

gen:
	@moq -out ./_mock/session_store.go -pkg mock \
		${GOPATH}/src/github.com/swithek/sessionup Store:SessionStore
	@go generate ./...

test:
	@gocov test ./... -race -failfast -timeout 3m | gocov report | grep "Total Coverage"

lint:
	@golangci-lint run

qa: lint test
