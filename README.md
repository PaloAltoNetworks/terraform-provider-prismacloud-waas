# Terraform Provider for Palo Alto Networks Prisma Cloud Web Application & API Security (WAAS)

This provider allows for the management of Prisma Cloud Web Application & API Security (WAAS) policies. This provider was created using the [Terraform Plugin Framework](https://github.com/hashicorp/terraform-plugin-framework) and can be used as a standalone provider. In the  combined with the broader [Prisma Cloud Terraform Provider](https://github.com/PaloAltoNetworks/terraform-provider-prismacloud) via a [Plugin Mux](https://github.com/hashicorp/terraform-plugin-mux) to manage all Prisma Cloud resources.

## Requirements

- [Terraform](https://www.terraform.io/downloads.html) >= 1.7.4
- [Go](https://golang.org/doc/install) >= 1.22

## Building The Provider

1. Clone the repository
1. Enter the repository directory
1. Build the provider using the Go `install` command:

```shell
go install
```

## Adding Dependencies

This provider uses [Go modules](https://github.com/golang/go/wiki/Modules).
Please see the Go documentation for the most up-to-date information about using Go modules.

To add a new dependency `github.com/author/dependency` to your Terraform provider:

```shell
go get github.com/author/dependency
go mod tidy
```

Then commit the changes to `go.mod` and `go.sum`.

## Using the provider

If you're building the provider, follow the instructions to install it as a plugin. After placing it into your plugins directory, run `terraform init` to initialize it.

## TODO
See the Palo Alto Networks Prisma Cloud WAAS Provider documentation to get started using the provider.



## Developing the Provider

If you wish to modify on the provider, you'll first need [Go](http://www.golang.org) installed on your machine (see [Requirements](#requirements) above).

To compile the provider, run `go install`. This will build the provider and put the provider binary in the `$GOPATH/bin` directory.

To generate or update documentation, run `go generate`.
