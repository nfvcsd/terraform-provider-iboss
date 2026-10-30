# Local commands mirror the CI workflow (.github/workflows/ci.yml).
# Every test target runs against the local iboss simulator only.

TERRAFORM          ?= terraform
# Pinned for CI and documentation; acceptance tests use whatever $(TERRAFORM) resolves to.
TERRAFORM_VERSION  ?= 1.16.6
# Use registry.opentofu.org when TERRAFORM points at OpenTofu.
TF_REGISTRY_HOST   ?= registry.terraform.io
GOVULNCHECK_VERSION ?= v1.7.0
PYTHON             ?= python3
BIN                := bin/terraform-provider-iboss
# Extra tfplugindocs flags, e.g. DOCS_FLAGS=--providers-schema=schema.json
DOCS_FLAGS         ?=

.PHONY: default check fmt fmt-check vet tidy-check test testacc build docs docs-check \
        examples-check py-test vuln api-inventory clean

default: check

## check: run every PR check that does not need network access beyond module/tool downloads
check: fmt-check vet tidy-check test testacc build docs-check examples-check py-test

fmt:
	gofmt -w .
	$(TERRAFORM) fmt -recursive examples

fmt-check:
	@out="$$(gofmt -l .)"; if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi
	$(TERRAFORM) fmt -check -recursive examples

vet:
	go vet ./...

tidy-check:
	go mod tidy -diff

## test: unit tests (client, simulator harness, schemas) with the race detector
test:
	go test -race -count=1 ./...

## testacc: simulated acceptance tests — real Terraform CLI, local simulator, no iboss credentials
testacc:
	TF_ACC=1 TF_ACC_TERRAFORM_PATH="$$(command -v $(TERRAFORM))" TF_ACC_PROVIDER_HOST=$(TF_REGISTRY_HOST) \
	CHECKPOINT_DISABLE=1 go test -race -count=1 -timeout 30m ./internal/provider/...

build:
	go build -trimpath -o $(BIN) .

docs:
	go tool tfplugindocs generate --provider-name iboss --rendered-provider-name iboss $(DOCS_FLAGS)

docs-check: docs
	go tool tfplugindocs validate --provider-name iboss $(DOCS_FLAGS)
	@git diff --exit-code -- docs/ || (echo "docs/ is out of date: run 'make docs' and commit the result"; exit 1)

## examples-check: terraform validate every example against the local build (offline)
examples-check: build
	$(PYTHON) tools/validate_examples.py --provider-dir bin --terraform $(TERRAFORM) --registry-host $(TF_REGISTRY_HOST)

py-test:
	$(PYTHON) -m unittest discover -s tools -p 'test_*.py'

vuln:
	go run golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION) ./...

## api-inventory: download the public Postman collection and regenerate docs/api-inventory.md
api-inventory:
	$(PYTHON) tools/postman_inventory.py fetch --out build/postman/iboss.json
	$(PYTHON) tools/postman_inventory.py inventory build/postman/iboss.json --out docs/api-inventory.md

clean:
	rm -rf bin build dist
