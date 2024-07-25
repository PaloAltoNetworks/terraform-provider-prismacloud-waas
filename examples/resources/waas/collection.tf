resource "prismacloud-waas_collection" "Example" {
  name           = "Container Example"
  account_ids    = tolist(["*"])
  app_ids        = tolist(["*"])
  clusters       = tolist(["*"])
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
  name           = "Host Example"
  account_ids    = tolist(["*"])
  app_ids        = tolist(["*"])
  clusters       = tolist(["*"])
  color          = "#00FF00"
  containers     = tolist(["*"])
  description    = "this is an example Host created via Terraform Provider"
  functions      = tolist(["*"])
  hosts          = tolist(["host"])
  images         = tolist(["*"])
  labels         = tolist(["*"])
  namespaces     = tolist(["*"])
  required_types = toset(["hostPolicy"])
}
