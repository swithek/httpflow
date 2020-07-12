.PHONY: gen test lint

gen:
	@moq -out ./_mock/session_store.go -pkg mock \
		${GOPATH}/src/github.com/swithek/sessionup Store:SessionStore
	@go generate ./...

