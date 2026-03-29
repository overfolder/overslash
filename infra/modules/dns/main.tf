variable "base_prefix" {
  type = string
}

variable "domain" {
  type = string
}

locals {
  domain_parts = split(".", var.domain)
  root_domain  = join(".", slice(local.domain_parts, length(local.domain_parts) - 2, length(local.domain_parts)))
}

resource "google_dns_managed_zone" "zone" {
  name     = "${var.base_prefix}-dns"
  dns_name = "${local.root_domain}."

  description = "DNS zone for ${local.root_domain}"

  dnssec_config {
    state = "on"
  }
}

output "zone_name" {
  value = google_dns_managed_zone.zone.name
}

output "name_servers" {
  value = google_dns_managed_zone.zone.name_servers
}
