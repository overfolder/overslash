# Global HTTPS load balancer that fronts the Cloud Run API service so
# `*.api.<apex>` resolves to a single anycast IP under one wildcard managed
# cert. Cloud Run's native `google_cloud_run_domain_mapping` is single-domain
# only (and DNS TXT-validated), so per-org subdomains can't be served without
# either provisioning a mapping per slug at runtime or this LB.
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

resource "google_compute_global_address" "api_lb_ip" {
  name    = "${var.base_prefix}-api-lb-ip"
  project = var.project_id
}

resource "google_compute_managed_ssl_certificate" "api_cert" {
  name    = "${var.base_prefix}-api-cert"
  project = var.project_id

  managed {
    domains = [
      var.api_apex,
      "*.${var.api_apex}",
    ]
  }
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
  name             = "${var.base_prefix}-api-https-proxy"
  project          = var.project_id
  url_map          = google_compute_url_map.api.id
  ssl_certificates = [google_compute_managed_ssl_certificate.api_cert.id]
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
  value = google_compute_managed_ssl_certificate.api_cert.id
}
