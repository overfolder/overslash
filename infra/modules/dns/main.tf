variable "domain" {
  type = string
}

# Managed DNS zone for the root domain
# Extract the root domain from a potential subdomain (e.g., api.overslash.com -> overslash.com)
locals {
  domain_parts = split(".", var.domain)
  root_domain  = join(".", slice(local.domain_parts, length(local.domain_parts) - 2, length(local.domain_parts)))
  zone_name    = replace(local.root_domain, ".", "-")
}

resource "google_dns_managed_zone" "overslash" {
  name     = local.zone_name
  dns_name = "${local.root_domain}."

  description = "DNS zone for ${local.root_domain}"

  dnssec_config {
    state = "on"
  }
}

output "zone_name" {
  value = google_dns_managed_zone.overslash.name
}

output "name_servers" {
  value = google_dns_managed_zone.overslash.name_servers
}
