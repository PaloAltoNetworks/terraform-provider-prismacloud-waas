resource "prismacloud-waas_collection" "Example" {
  name           = "Example"
  account_ids    = tolist(["*"])
  app_ids        = tolist(["*"])
  clusters       = tolist(["*"])
  code_repos     = tolist(["*"])
  color          = "#00FF00"
  containers     = tolist(["*"])
  description    = "this is an example Collection created via Terraform Provider"
  functions      = tolist(["*"])
  hosts          = tolist(["*"])
  images         = tolist(["*example:*"])
  labels         = tolist(["*"])
  namespaces     = tolist(["*"])
  required_types = toset(["containerPolicy"])
}
