resource "prismacloud-waas_collection" "ContainerExample" {
  name           = "Example"
  account_ids    = tolist(["*"])
  app_ids        = tolist(["*"])
  clusters       = tolist(["*"])
  code_repos     = tolist(["*"])
  color          = "#00FF00"
  containers     = tolist(["*"])
  description    = "this is an example Container Collection created via Terraform Provider"
  functions      = tolist(["*"])
  hosts          = tolist(["*"])
  images         = tolist(["*example:*"])
  labels         = tolist(["*"])
  namespaces     = tolist(["*"])
  required_types = toset(["containerPolicy"])
}

resource "prismacloud-waas_collection" "HostExample" {
  name           = "HostExample"
  account_ids    = tolist(["*"])
  app_ids        = tolist(["*"])
  clusters       = tolist(["*"])
  code_repos     = tolist(["*"])
  color          = "#00FF00"
  containers     = tolist(["*"])
  description    = "this is an example Host Collection created via Terraform Provider"
  functions      = tolist(["*"])
  hosts          = tolist(["gsindel*"])
  images         = tolist(["*"])
  labels         = tolist(["*"])
  namespaces     = tolist(["*"])
  required_types = toset(["hostPolicy"])
}
