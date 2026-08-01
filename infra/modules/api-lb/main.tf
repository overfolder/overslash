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
# The URL map whitelists the API's own hostnames (`<apex>` and `*.<apex>`,
# plus `extra_hosts`): only those reach the Cloud Run backend. Everything
# else — raw LB-IP scans, random vhosts — gets a 301 to the marketing site
# at the edge, keeping scanner noise out of the service's request metrics.
# Slug dispatch still happens in `subdomain_middleware` inside the API; the
# LB does no per-path routing.

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

variable "backend_timeout_seconds" {
  type        = number
  default     = 120
  description = "Backend response timeout. Must exceed EVENTS_STREAM_MAX_CONNECTION_SECS (default 30) — the SSE stream holds a response open that long on purpose."
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

variable "extra_hosts" {
  type        = list(string)
  default     = []
  description = "Additional hostnames routed to the API backend, beyond `api_apex` and `*.api_apex`. Extension point for per-org custom domains — pair each entry with a cert map entry against `cert_map_id`."
}

variable "unmatched_redirect_host" {
  type        = string
  default     = "www.overslash.com"
  description = "Host that requests with a non-whitelisted Host header are 301'd to (path and query stripped)."
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

  # Inject the client's ISO 3166-1 alpha-2 country code so the API can return
  # EUR vs USD pricing without a separate GeoIP DB. GCLB overwrites any
  # client-supplied header of the same name, so this cannot be spoofed.
  custom_request_headers = ["X-Client-Geo-Country:{client_region}"]

  # `google_compute_backend_service` defaults this to 30s — exactly the SSE
  # stream's own ceiling, so the two would race and the load balancer could cut
  # a response mid-frame instead of us closing it cleanly. Serverless NEG
  # backends are documented as deferring to Cloud Run's timeout rather than
  # this field, but leaving a 30s value sitting here that *might* apply is not
  # a bet worth taking on a streaming endpoint.
  timeout_sec = var.backend_timeout_seconds

  backend {
    group = google_compute_region_network_endpoint_group.api_neg.id
  }

  log_config {
    enable      = true
    sample_rate = 1.0
  }
}

resource "google_compute_url_map" "api" {
  name    = "${var.base_prefix}-api-urlmap"
  project = var.project_id

  # Host whitelist: only the API's own hostnames reach Cloud Run. Requests
  # for anything else (the raw LB IP, arbitrary vhosts probed by scanners)
  # are redirected at the edge and never count against the service's
  # request_count metrics. Per-slug dispatch stays in subdomain_middleware.
  host_rule {
    hosts        = concat([var.api_apex, "*.${var.api_apex}"], var.extra_hosts)
    path_matcher = "api"
  }

  path_matcher {
    name            = "api"
    default_service = google_compute_backend_service.api_backend.id
  }

  # path_redirect + strip_query so scanner payloads are not echoed back in
  # the Location header.
  default_url_redirect {
    host_redirect          = var.unmatched_redirect_host
    path_redirect          = "/"
    strip_query            = true
    https_redirect         = true
    redirect_response_code = "MOVED_PERMANENTLY_DEFAULT"
  }
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
