//! Public billing config (`GET /v1/billing/config`) and the unauthenticated
//! geo/currency probe (`GET /v1/billing/geo`).

use super::*;

/// EU member state ISO 3166-1 alpha-2 codes for EUR/USD detection.
const EU_COUNTRIES: &[&str] = &[
    "AT", "BE", "BG", "CY", "CZ", "DE", "DK", "EE", "ES", "FI", "FR", "GR", "HR", "HU", "IE", "IT",
    "LT", "LU", "LV", "MT", "NL", "PL", "PT", "RO", "SE", "SI", "SK",
];

// ---------------------------------------------------------------------------
// Public config — exposed to the dashboard so it can render the right CTA
// ("Add org" goes to `/billing/new-team` when billing is on).
// ---------------------------------------------------------------------------

#[derive(Serialize)]
pub(super) struct BillingConfigResponse {
    cloud_billing: bool,
}

/// GET /v1/billing/config — unauthenticated; the only field is the public
/// flag. Always returns true here (route is only mounted when billing is on).
pub(super) async fn get_billing_config() -> Json<BillingConfigResponse> {
    Json(BillingConfigResponse {
        cloud_billing: true,
    })
}

// ---------------------------------------------------------------------------
// Geo
// ---------------------------------------------------------------------------

#[derive(Serialize)]
pub(super) struct GeoResponse {
    currency: &'static str,
    base_price: u32,
}

/// GET /v1/billing/geo — unauthenticated; returns EUR or USD pricing.
///
/// Country resolution priority:
///   1. `CF-IPCountry` — set by Cloudflare when the API is fronted by CF.
///   2. `X-Client-Geo-Country` — injected by the GCLB backend service via
///      `custom_request_headers = ["X-Client-Geo-Country:{client_region}"]`.
///   3. `X-Country-Code` — manual override (kept for direct-API consumers).
///   4. Default: USD.
pub(super) async fn get_geo(headers: HeaderMap) -> Json<GeoResponse> {
    let country = headers
        .get("CF-IPCountry")
        .or_else(|| headers.get("X-Client-Geo-Country"))
        .or_else(|| headers.get("X-Country-Code"))
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    if EU_COUNTRIES.contains(&country) {
        Json(GeoResponse {
            currency: "eur",
            base_price: 15,
        })
    } else {
        Json(GeoResponse {
            currency: "usd",
            base_price: 20,
        })
    }
}
