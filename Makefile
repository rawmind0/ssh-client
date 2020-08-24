TARGETS := $(shell ls scripts)
GOFMT_FILES?=$$(find . -name '*.go' |grep -v vendor)
GOFMT_CHECK?=$$(gofmt -l -s ${GOFMT_FILES})

default: build

.dapper:
	@echo Downloading dapper
	@curl -sL https://releases.rancher.com/dapper/latest/dapper-$$(uname -s)-$$(uname -m) > .dapper.tmp
	@@chmod +x .dapper.tmp
	@./.dapper.tmp -v
	@mv .dapper.tmp .dapper

dapper-build: .dapper
	./.dapper build

dapper-ci: .dapper
	./.dapper ci

build: fmtcheck
	go install

build-rancher: validate-rancher
	@sh -c "'$(CURDIR)/scripts/gobuild.sh'"

validate-rancher: vet lint fmtcheck

package-rancher:
	@sh -c "'$(CURDIR)/scripts/gopackage.sh'"

test: fmtcheck
	go test $(TEST) || exit 1
	echo $(TEST) | \
		xargs -t -n4 go test $(TESTARGS) -timeout=30s -parallel=4

vet:
	@echo "==> Checking that code complies with go vet requirements..."
	@go vet $$(go list ./... | grep -v vendor/) ; if [ $$? -eq 1 ]; then \
		echo ""; \
		echo "Vet found suspicious constructs. Please check the reported constructs"; \
		echo "and fix them if necessary before submitting the code for review."; \
		exit 1; \
	fi

lint:
	@echo "==> Checking that code complies with golint requirements..."
	@GO111MODULE=${GO111MODULE} go get -u golang.org/x/lint/golint
	@if [ -n "$$(golint $$(go list ./...) | grep -v 'should have comment.*or be unexported' | tee /dev/stderr)" ]; then \
		echo ""; \
		echo "golint found style issues. Please check the reported issues"; \
		echo "and fix them if necessary before submitting the code for review."; \
    	exit 1; \
	fi

bin:
	go build -o ssh-client

fmt:
	gofmt -w -s $(GOFMT_FILES)

fmtcheck:
	@echo "==> Checking that code complies with gofmt requirements..."
	@if [ -n "${GOFMT_CHECK}" ]; then \
	    echo 'gofmt needs running on the following files:'; \
	    echo "${GOFMT_CHECK}"; \
	    echo "You can use the command: \`make fmt\` to reformat code."; \
	    exit 1; \
	fi

vendor:
	@echo "==> Updating vendor modules..."
	@GO111MODULE=on go mod vendor

.PHONY: bin build test testacc vet fmt fmtcheck vendor dapper-build dapper-ci dapper-testacc
