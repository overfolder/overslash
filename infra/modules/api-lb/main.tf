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
#
# TLS and edge filtering (CASA 4.1.1): the HTTPS proxy carries an explicit
# `google_compute_ssl_policy` (TLS 1.2 minimum, RESTRICTED ciphers) instead
# of GCP's permissive default, and the backend service carries a Cloud Armor
# policy. The Cloud Armor baseline only allows by default; its OWASP rules
# ship in preview (logged, never enforced) until the logs show they don't
# trip on legitimate agent payloads. See docs/runbooks/lb-hardening.md.

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

variable "ssl_min_tls_version" {
  type        = string
  default     = "TLS_1_2"
  description = "Minimum TLS version the HTTPS proxy negotiates."

  validation {
    condition     = contains(["TLS_1_2", "TLS_1_3"], var.ssl_min_tls_version)
    error_message = "ssl_min_tls_version must be TLS_1_2 or TLS_1_3 (CASA 4.1.1)."
  }
}

variable "ssl_profile" {
  type        = string
  default     = "RESTRICTED"
  description = "SSL policy profile. RESTRICTED drops the CBC/SHA-1 suites MODERN still offers at TLS 1.2; every client that speaks TLS 1.2 with ECDHE-GCM or ChaCha20 is unaffected."

  validation {
    condition     = contains(["MODERN", "RESTRICTED"], var.ssl_profile)
    error_message = "ssl_profile must be MODERN or RESTRICTED (COMPATIBLE allows weak ciphers)."
  }
}

variable "cloud_armor_waf_rules" {
  type = list(string)
  default = [
    "sqli-v33-stable",
    "xss-v33-stable",
    "lfi-v33-stable",
    "rfi-v33-stable",
    "rce-v33-stable",
    "scannerdetection-v33-stable",
    "protocolattack-v33-stable",
    "sessionfixation-v33-stable",
  ]
  description = "Cloud Armor preconfigured WAF rule sets, one deny(403) rule each at priority 1000, 1001, ... Order is significant: reordering renumbers the rules."
}

variable "cloud_armor_waf_sensitivity" {
  type        = number
  default     = 1
  description = "Sensitivity level passed to every preconfigured WAF rule (1 = fewest false positives)."

  validation {
    condition     = var.cloud_armor_waf_sensitivity >= 1 && var.cloud_armor_waf_sensitivity <= 4
    error_message = "cloud_armor_waf_sensitivity must be between 1 and 4."
  }
}

variable "cloud_armor_waf_preview" {
  type        = bool
  default     = true
  description = "Run the WAF rules in preview: matches are logged on the LB request log (`jsonPayload.previewSecurityPolicy`) but traffic is never blocked. Flip to false only after tuning against those logs."
}

variable "enable_ipv6" {
  type        = bool
  default     = false
  description = "Also serve the LB on a global IPv6 address: one more `google_compute_global_address` and a 443 + 80 forwarding-rule pair on the existing proxies, so v6 gets the same cert map, SSL policy and Cloud Armor policy. Publish `lb_ipv6` as AAAA for `<apex>` and `*.<apex>`."
}

resource "google_compute_global_address" "api_lb_ip" {
  name    = "${var.base_prefix}-api-lb-ip"
  project = var.project_id
}

resource "google_compute_global_address" "api_lb_ipv6" {
  count = var.enable_ipv6 ? 1 : 0

  name       = "${var.base_prefix}-api-lb-ipv6"
  project    = var.project_id
  ip_version = "IPV6"
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

# Pins what the proxy negotiates so "TLS 1.2+, strong ciphers" is declared
# config rather than whatever GCP's default profile happens to allow.
resource "google_compute_ssl_policy" "api" {
  name            = "${var.base_prefix}-api-ssl-policy"
  project         = var.project_id
  description     = "API LB: ${var.ssl_min_tls_version}+, ${var.ssl_profile} ciphers (CASA 4.1.1)."
  min_tls_version = var.ssl_min_tls_version
  profile         = var.ssl_profile
}

# Baseline Cloud Armor policy. The default rule allows; the OWASP rule sets
# deny with 403 but run in preview (var.cloud_armor_waf_preview), so on day
# one this policy blocks nothing. Agent action bodies routinely carry SQL,
# shell snippets and HTML that a CRS rule would read as an attack, which is
# why enforcement waits for evidence from the preview logs. Requests the URL
# map redirects at the edge never reach the backend, so they are not
# evaluated here.
resource "google_compute_security_policy" "api" {
  name        = "${var.base_prefix}-api-armor"
  project     = var.project_id
  description = "API LB baseline: default allow, OWASP CRS rules ${var.cloud_armor_waf_preview ? "in preview" : "enforced"}."
  type        = "CLOUD_ARMOR"

  advanced_options_config {
    # Lets the WAF parse JSON bodies field by field instead of matching the
    # raw body, which cuts false positives on a JSON API.
    json_parsing = "STANDARD"
    log_level    = "NORMAL"
  }

  dynamic "rule" {
    for_each = var.cloud_armor_waf_rules
    content {
      action      = "deny(403)"
      priority    = 1000 + rule.key
      preview     = var.cloud_armor_waf_preview
      description = "Preconfigured WAF: ${rule.value}"

      match {
        expr {
          expression = "evaluatePreconfiguredWaf('${rule.value}', {'sensitivity': ${var.cloud_armor_waf_sensitivity}})"
        }
      }
    }
  }

  rule {
    action      = "allow"
    priority    = 2147483647
    description = "Default allow."

    match {
      versioned_expr = "SRC_IPS_V1"
      config {
        src_ip_ranges = ["*"]
      }
    }
  }
}

resource "google_compute_backend_service" "api_backend" {
  name                  = "${var.base_prefix}-api-backend"
  project               = var.project_id
  protocol              = "HTTPS"
  load_balancing_scheme = "EXTERNAL_MANAGED"
  security_policy       = google_compute_security_policy.api.id

  # Inject the client's ISO 3166-1 alpha-2 country code so the API can return
  # EUR vs USD pricing without a separate GeoIP DB, and the address the LB saw
  # so the API needn't guess where in X-Forwarded-For Google's own hops landed
  # (OVERSLASH_TRUSTED_CLIENT_IP_HEADER, set from infra/main.tf). GCLB
  # overwrites any client-supplied header of the same name, so neither can be
  # spoofed — as long as the service's ingress is LB-only.
  custom_request_headers = [
    "X-Client-Geo-Country:{client_region}",
    "X-Overslash-Edge-Client-Ip:{client_ip_address}",
  ]

  # No timeout_sec: serverless-NEG backends reject it. The SSE ceiling lives in
  # modules/cloud-run's request_timeout_seconds.

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
  ssl_policy      = google_compute_ssl_policy.api.id
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

# IPv6 front door. A forwarding rule binds one address, so v6 needs its own
# pair — but both target the proxies above, so the cert map, SSL policy and
# Cloud Armor policy (on the backend service) apply to v6 unchanged. Turning
# this on is purely additive: nothing on the IPv4 path is touched.
resource "google_compute_global_forwarding_rule" "api_https_v6" {
  count = var.enable_ipv6 ? 1 : 0

  name                  = "${var.base_prefix}-api-https-fr-v6"
  project               = var.project_id
  load_balancing_scheme = "EXTERNAL_MANAGED"
  ip_address            = google_compute_global_address.api_lb_ipv6[0].address
  ip_protocol           = "TCP"
  port_range            = "443"
  target                = google_compute_target_https_proxy.api.id
}

resource "google_compute_global_forwarding_rule" "api_http_v6" {
  count = var.enable_ipv6 ? 1 : 0

  name                  = "${var.base_prefix}-api-http-fr-v6"
  project               = var.project_id
  load_balancing_scheme = "EXTERNAL_MANAGED"
  ip_address            = google_compute_global_address.api_lb_ipv6[0].address
  ip_protocol           = "TCP"
  port_range            = "80"
  target                = google_compute_target_http_proxy.api_http.id
}

output "lb_ip" {
  value       = google_compute_global_address.api_lb_ip.address
  description = "Anycast IP for `<apex>` and `*.<apex>` A records."
}

output "lb_ipv6" {
  value       = var.enable_ipv6 ? google_compute_global_address.api_lb_ipv6[0].address : ""
  description = "Anycast IPv6 address for `<apex>` and `*.<apex>` AAAA records. Empty unless `enable_ipv6`."
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

output "ssl_policy_name" {
  value = google_compute_ssl_policy.api.name
}

output "security_policy_name" {
  value = google_compute_security_policy.api.name
}

output "acme_challenge_data" {
  value = google_certificate_manager_dns_authorization.api.dns_resource_record[0].data
}
