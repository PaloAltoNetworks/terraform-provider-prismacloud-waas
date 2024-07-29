default: testacc

# Run acceptance tests
.PHONY: testacc
testacc:
	TF_ACC=1 go test ./... -v $(TESTARGS) -timeout 120m

# Build a local copy of the terraform plugin and move to expected location
.PHONY: build-local
build-local:
	go build .
	mkdir -p terraform.local/paloaltonetworks/prismacloud-waas/1.0.4/darwin_amd64 && cp terraform-provider-prismacloud-waas terraform.local/paloaltonetworks/prismacloud-waas/1.0.4/darwin_amd64/terraform-provider-prismacloud-waas_v1.0.4
