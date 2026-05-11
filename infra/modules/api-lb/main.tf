# Global HTTPS load balancer that fronts the Cloud Run API service so
# `*.api.<apex>` resolves to a single anycast IP under one wildcard managed
# cert. Cloud Run's native `google_cloud_run_domain_mapping` is single-domain
# only (and DNS TXT-validated), so per-org subdomains can't be served without
# either provisioning a mapping per slug at runtime or this LB.
#
# Cert path: classic `google_compute_managed_ssl_certificate` cannot issue
# wildcards (HTTP-01 only). We use Certificate Manager — DNS authorization
# at the apex (one auth covers `<apex>` and `*.<apex>`), a managed cert
# bound to that auth, and a certificate map referenced by the HTTPS proxy.
# The single ACME CNAME is auto-published into Cloud DNS when
# `dns_zone_name` is supplied.
#
# Why no path/host rules in the URL map: every request flows to one Cloud
# Run backend; `subdomain_middleware` inside the API resolves the slug from
# the (preserved) Host header. The LB is just a wildcard-cert terminator
# and a pipe to Cloud Run's serverless NEG — keep it dumb on purpose.

variable "project_id" {
  type = string
}

variable "region" {
  type = string
}

variable "base_prefix" {
  type = string
}

variable "cloud_run_service" {
  type        = string
  description = "Name of the Cloud Run service to route traffic to (output of cloud-run module)."
}

variable "api_apex" {
  type        = string
  description = "Apex hostname, e.g. `api.overslash.com`. Used for the managed cert SAN list (apex + `*.<apex>`)."
}

variable "dns_zone_name" {
  type        = string
  default     = ""
  description = "Cloud DNS managed-zone name that hosts `api_apex`. When set, the ACME challenge CNAME emitted by the DNS authorization is published into this zone automatically. Leave empty if DNS lives outside Terraform — the record values are exposed via the `acme_challenge_*` outputs and must be created manually before the cert can issue."
}

resource "google_compute_global_address" "api_lb_ip" {
  name    = "${var.base_prefix}-api-lb-ip"
  project = var.project_id
}

resource "google_certificate_manager_dns_authorization" "api" {
  name        = "${var.base_prefix}-api-dns-auth"
  project     = var.project_id
  location    = "global"
  domain      = var.api_apex
  description = "DNS-01 authorization for ${var.api_apex} (covers wildcard SAN)."
}

# Optional: publish the ACME challenge CNAME into the project's Cloud DNS
# zone. Only created when the caller passes `dns_zone_name` — otherwise the
# operator wires the record up by hand using the `acme_challenge_*` outputs.
resource "google_dns_record_set" "acme_challenge" {
  count = var.dns_zone_name != "" ? 1 : 0

  project      = var.project_id
  managed_zone = var.dns_zone_name
  name         = google_certificate_manager_dns_authorization.api.dns_resource_record[0].name
  type         = google_certificate_manager_dns_authorization.api.dns_resource_record[0].type
  ttl          = 300
  rrdatas      = [google_certificate_manager_dns_authorization.api.dns_resource_record[0].data]
}

resource "google_certificate_manager_certificate" "api_cert" {
  name     = "${var.base_prefix}-api-cert"
  project  = var.project_id
  location = "global"

  managed {
    domains = [
      var.api_apex,
      "*.${var.api_apex}",
    ]
    dns_authorizations = [google_certificate_manager_dns_authorization.api.id]
  }
}

resource "google_certificate_manager_certificate_map" "api" {
  name        = "${var.base_prefix}-api-cert-map"
  project     = var.project_id
  description = "Certificate map for the API LB; one PRIMARY entry serves `${var.api_apex}` and all subdomains."
}

# PRIMARY = default cert returned for any SNI hostname not matched by a more
# specific entry. With one wildcard cert covering `<apex>` and `*.<apex>`,
# this single entry is sufficient — no per-hostname entries needed.
resource "google_certificate_manager_certificate_map_entry" "api_default" {
  name         = "${var.base_prefix}-api-cert-map-default"
  project      = var.project_id
  map          = google_certificate_manager_certificate_map.api.name
  certificates = [google_certificate_manager_certificate.api_cert.id]
  matcher      = "PRIMARY"
}

resource "google_compute_region_network_endpoint_group" "api_neg" {
  name                  = "${var.base_prefix}-api-neg"
  project               = var.project_id
  region                = var.region
  network_endpoint_type = "SERVERLESS"

  cloud_run {
    service = var.cloud_run_service
  }
}

resource "google_compute_backend_service" "api_backend" {
  name                  = "${var.base_prefix}-api-backend"
  project               = var.project_id
  protocol              = "HTTPS"
  load_balancing_scheme = "EXTERNAL_MANAGED"

  backend {
    group = google_compute_region_network_endpoint_group.api_neg.id
  }

  log_config {
    enable      = true
    sample_rate = 1.0
  }
}

resource "google_compute_url_map" "api" {
  name            = "${var.base_prefix}-api-urlmap"
  project         = var.project_id
  default_service = google_compute_backend_service.api_backend.id
  # No host_rule / path_matcher blocks: subdomain_middleware in the API
  # crate dispatches per slug. Adding routing here would just duplicate
  # state.
}

resource "google_compute_target_https_proxy" "api" {
  name    = "${var.base_prefix}-api-https-proxy"
  project = var.project_id
  url_map = google_compute_url_map.api.id

  # Certificate Manager hand-off: the proxy resolves SNI through the cert
  # map at request time, so adding/rotating certs is a Certificate Manager
  # change, not a proxy change.
  certificate_map = "//certificatemanager.googleapis.com/${google_certificate_manager_certificate_map.api.id}"
}

resource "google_compute_global_forwarding_rule" "api_https" {
  name                  = "${var.base_prefix}-api-https-fr"
  project               = var.project_id
  load_balancing_scheme = "EXTERNAL_MANAGED"
  ip_address            = google_compute_global_address.api_lb_ip.address
  ip_protocol           = "TCP"
  port_range            = "443"
  target                = google_compute_target_https_proxy.api.id
}

# Optional 80 → 443 redirect so `http://acme.api.overslash.com` upgrades
# automatically. Kept in the same module so the LB story is self-contained.
resource "google_compute_url_map" "api_http_redirect" {
  name    = "${var.base_prefix}-api-http-redirect"
  project = var.project_id

  default_url_redirect {
    https_redirect         = true
    redirect_response_code = "MOVED_PERMANENTLY_DEFAULT"
    strip_query            = false
  }
}

resource "google_compute_target_http_proxy" "api_http" {
  name    = "${var.base_prefix}-api-http-proxy"
  project = var.project_id
  url_map = google_compute_url_map.api_http_redirect.id
}

resource "google_compute_global_forwarding_rule" "api_http" {
  name                  = "${var.base_prefix}-api-http-fr"
  project               = var.project_id
  load_balancing_scheme = "EXTERNAL_MANAGED"
  ip_address            = google_compute_global_address.api_lb_ip.address
  ip_protocol           = "TCP"
  port_range            = "80"
  target                = google_compute_target_http_proxy.api_http.id
}

output "lb_ip" {
  value       = google_compute_global_address.api_lb_ip.address
  description = "Anycast IP for `<apex>` and `*.<apex>` A records."
}

output "cert_id" {
  value = google_certificate_manager_certificate.api_cert.id
}

output "cert_map_id" {
  value       = google_certificate_manager_certificate_map.api.id
  description = "Cert map referenced by the HTTPS target proxy. Add additional `google_certificate_manager_certificate_map_entry` resources against this map to serve extra certs (e.g. custom org domains)."
}

output "acme_challenge_name" {
  value       = google_certificate_manager_dns_authorization.api.dns_resource_record[0].name
  description = "CNAME record name for the ACME DNS-01 challenge. Already published when `dns_zone_name` was provided; otherwise create this record in your DNS provider before applying — the cert stays in PROVISIONING until it resolves."
}

output "acme_challenge_data" {
  value = google_certificate_manager_dns_authorization.api.dns_resource_record[0].data
}
