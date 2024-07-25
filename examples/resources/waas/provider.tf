terraform {
  required_providers {
    prismacloud-waas = {
      source  = "terraform.local/paloaltonetworks/prismacloud-waas"
      version = "1.0.2"
    }
  }
}

variable "api_version" {
  type = string
  default = "v1"
}

variable "console_url" {
  type = string
}

variable "password" {
  type      = string
  sensitive = true
}

variable "username" {
  type = string
}

provider "prismacloud-waas" {
  api_version = var.api_version
  console_url = var.console_url
  password    = var.password
  username    = var.username
}
