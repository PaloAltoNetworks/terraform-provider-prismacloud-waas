default: testacc

# Run acceptance tests
.PHONY: testacc
testacc:
	TF_ACC=1 go test ./... -v $(TESTARGS) -timeout 120m

# Build a local copy of the terraform plugin and move to expected location
.PHONY: build-local
build-local:
	go build .
	cp terraform-provider-prismacloud-waas terraform.local/PaloAltoNetworks/prismacloud-waas/0.0.1/darwin_amd64/terraform-provider-prismacloud-waas_v0.0.1