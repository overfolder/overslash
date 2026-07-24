//! Raw Stripe REST API wrappers shared by the checkout and webhook
//! routes (reqwest + form encoding — no new dependencies).

use super::*;

// ---------------------------------------------------------------------------
// Stripe API helpers (uses reqwest + form encoding — no new dependencies)
// ---------------------------------------------------------------------------

pub(super) async fn stripe_create_customer(
    client: &reqwest::Client,
    secret_key: &str,
    email: Option<&str>,
    name: Option<&str>,
    user_id: Uuid,
    api_base: &str,
) -> Result<String> {
    let mut params = vec![("metadata[user_id]", user_id.to_string())];
    if let Some(e) = email {
        params.push(("email", e.to_string()));
    }
    if let Some(n) = name {
        params.push(("name", n.to_string()));
    }

    let resp = client
        .post(format!("{api_base}/customers"))
        .basic_auth(secret_key, Option::<&str>::None)
        .form(&params)
        .send()
        .await
        .map_err(|e| AppError::Internal(format!("stripe customer create: {e}")))?;

    if !resp.status().is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(AppError::Internal(format!("stripe customer error: {body}")));
    }

    let json: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| AppError::Internal(format!("stripe customer parse: {e}")))?;
    json["id"]
        .as_str()
        .map(|s| s.to_string())
        .ok_or_else(|| AppError::Internal("stripe customer: no id".into()))
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn stripe_create_checkout_session(
    client: &reqwest::Client,
    secret_key: &str,
    customer_id: &str,
    price_id: &str,
    seats: u32,
    success_url: &str,
    cancel_url: &str,
    api_base: &str,
    trial_period_days: Option<u32>,
) -> Result<(String, String)> {
    let seats_str = seats.to_string();
    // `customer_update[address]=auto` is required when `automatic_tax` is on
    // and the Customer has no saved address — Stripe needs an address to
    // compute tax, and `auto` tells it to copy the billing address collected
    // in Checkout onto the Customer. Without it Stripe rejects the request
    // with `customer_tax_location_invalid`.
    let mut params: Vec<(&str, &str)> = vec![
        ("mode", "subscription"),
        ("customer", customer_id),
        ("line_items[0][price]", price_id),
        ("line_items[0][quantity]", &seats_str),
        ("automatic_tax[enabled]", "true"),
        ("customer_update[address]", "auto"),
        ("customer_update[name]", "auto"),
        ("billing_address_collection", "required"),
        ("success_url", success_url),
        ("cancel_url", cancel_url),
    ];
    // Free trial: card collected now, first charge deferred by N days. Stripe
    // reports the subscription as status='trialing' with current_period_end at
    // the trial end, which the dashboard renders as a trial banner.
    let trial_days_str;
    if let Some(days) = trial_period_days {
        trial_days_str = days.to_string();
        params.push(("subscription_data[trial_period_days]", &trial_days_str));
    }

    let resp = client
        .post(format!("{api_base}/checkout/sessions"))
        .basic_auth(secret_key, Option::<&str>::None)
        .form(&params)
        .send()
        .await
        .map_err(|e| AppError::Internal(format!("stripe checkout create: {e}")))?;

    if !resp.status().is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(AppError::Internal(format!("stripe checkout error: {body}")));
    }

    let json: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| AppError::Internal(format!("stripe checkout parse: {e}")))?;
    let id = json["id"]
        .as_str()
        .ok_or_else(|| AppError::Internal("stripe checkout: no id".into()))?
        .to_string();
    let url = json["url"]
        .as_str()
        .ok_or_else(|| AppError::Internal("stripe checkout: no url".into()))?
        .to_string();
    Ok((id, url))
}

/// Resolve a Stripe lookup key to a literal price ID. Called at startup when
/// `cloud_billing` is enabled so a misconfigured deploy (typo in lookup key,
/// price not yet created in Stripe Dashboard, etc.) fails fast instead of at
/// first checkout. Returns the single matching active price's ID.
pub async fn resolve_stripe_price_by_lookup_key(
    client: &reqwest::Client,
    secret_key: &str,
    lookup_key: &str,
    api_base: &str,
) -> Result<String> {
    // Stripe wants `lookup_keys[]=<key>` as a repeated query param. URL-encode
    // the lookup key (it can contain characters like `_` which are safe, but
    // be defensive in case future operators pick something with reserved
    // characters).
    let encoded = urlencoding::encode(lookup_key);
    let url = format!("{api_base}/prices?lookup_keys[]={encoded}&active=true&limit=1");
    let resp = client
        .get(url)
        .basic_auth(secret_key, Option::<&str>::None)
        .send()
        .await
        .map_err(|e| AppError::Internal(format!("stripe price lookup: {e}")))?;
    if !resp.status().is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(AppError::Internal(format!("stripe price lookup: {body}")));
    }
    let json: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| AppError::Internal(format!("stripe price parse: {e}")))?;
    let id = json["data"][0]["id"].as_str().ok_or_else(|| {
        AppError::Internal(format!(
            "no active Stripe price for lookup_key={lookup_key}"
        ))
    })?;
    Ok(id.to_string())
}

/// Delete a Stripe Customer — used to compensate when the local
/// `set_stripe_customer` insert fails after the customer has been created.
/// Without this, retrying the checkout would create a second orphan customer
/// in Stripe.
pub(super) async fn stripe_delete_customer(
    client: &reqwest::Client,
    secret_key: &str,
    customer_id: &str,
    api_base: &str,
) -> Result<()> {
    let resp = client
        .delete(format!("{api_base}/customers/{customer_id}"))
        .basic_auth(secret_key, Option::<&str>::None)
        .send()
        .await
        .map_err(|e| AppError::Internal(format!("stripe delete customer: {e}")))?;
    if !resp.status().is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(AppError::Internal(format!(
            "stripe delete customer error: {body}"
        )));
    }
    Ok(())
}

/// Expire a Stripe Checkout Session — used to compensate when the local
/// pending_checkouts insert fails after the session has been created. After
/// expiry the user's payment URL stops working, preventing a charge with no
/// matching local record.
pub(super) async fn stripe_expire_checkout_session(
    client: &reqwest::Client,
    secret_key: &str,
    session_id: &str,
    api_base: &str,
) -> Result<()> {
    let resp = client
        .post(format!("{api_base}/checkout/sessions/{session_id}/expire"))
        .basic_auth(secret_key, Option::<&str>::None)
        .send()
        .await
        .map_err(|e| AppError::Internal(format!("stripe expire session: {e}")))?;
    if !resp.status().is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(AppError::Internal(format!(
            "stripe expire session error: {body}"
        )));
    }
    Ok(())
}

pub(super) async fn stripe_create_portal_session(
    client: &reqwest::Client,
    secret_key: &str,
    customer_id: &str,
    return_url: &str,
    api_base: &str,
) -> Result<String> {
    let params = [("customer", customer_id), ("return_url", return_url)];

    let resp = client
        .post(format!("{api_base}/billing_portal/sessions"))
        .basic_auth(secret_key, Option::<&str>::None)
        .form(&params)
        .send()
        .await
        .map_err(|e| AppError::Internal(format!("stripe portal create: {e}")))?;

    if !resp.status().is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(AppError::Internal(format!("stripe portal error: {body}")));
    }

    let json: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| AppError::Internal(format!("stripe portal parse: {e}")))?;
    json["url"]
        .as_str()
        .map(|s| s.to_string())
        .ok_or_else(|| AppError::Internal("stripe portal: no url".into()))
}

pub(super) async fn fetch_stripe_subscription(
    client: &reqwest::Client,
    secret_key: &str,
    subscription_id: &str,
    api_base: &str,
) -> Result<serde_json::Value> {
    let resp = client
        .get(format!("{api_base}/subscriptions/{subscription_id}"))
        .basic_auth(secret_key, Option::<&str>::None)
        .send()
        .await
        .map_err(|e| AppError::Internal(format!("stripe fetch subscription: {e}")))?;
    if !resp.status().is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(AppError::Internal(format!(
            "stripe subscription {subscription_id} error: {body}"
        )));
    }
    resp.json()
        .await
        .map_err(|e| AppError::Internal(format!("stripe subscription parse: {e}")))
}
