//! Serve the built-in service icons at `/icons/{file}`.
//!
//! Baked into the binary like `/SKILL.md`, so cloud and self-hosted
//! deployments both reach them with no static-asset plumbing, no Docker `COPY`
//! and no dependency on the dashboard build.
//!
//! Mounted in `global_routes`, outside auth and outside rate limiting. That is
//! required rather than incidental: an `<img>` sends no `Authorization` header,
//! and cross-origin (`app.` → `api.`) it sends no cookie either.

use std::collections::HashMap;
use std::sync::LazyLock;

use sha2::{Digest, Sha256};

use axum::{
    Router,
    extract::Path,
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::get,
};

use crate::AppState;

include!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../assets/service-icons/icons.rs"
));

/// A day. Deliberately not `immutable`: the URL carries no content hash, so
/// `immutable` would pin a stale logo for as long as the browser felt like
/// after a redeploy. The ETag makes the revalidation a 304 anyway.
const CACHE_CONTROL: &str = "public, max-age=86400";

/// An SVG is an *active document* — inline script inside one executes on this
/// origin if somebody navigates straight to it. We author these files, so this
/// is a supply-chain guard rather than a live hole, and it costs one header.
/// (`<img src>` never runs SVG script, so it only matters for direct
/// navigation.)
const ICON_CSP: &str = "default-src 'none'; style-src 'unsafe-inline'; sandbox";

struct Icon {
    bytes: &'static [u8],
    etag: String,
}

static ICONS: LazyLock<HashMap<&'static str, Icon>> = LazyLock::new(|| {
    BUILTIN_ICONS
        .iter()
        .map(|(name, bytes)| {
            let digest = hex::encode(Sha256::digest(bytes));
            (
                *name,
                Icon {
                    bytes,
                    etag: format!("\"{}\"", &digest[..32]),
                },
            )
        })
        .collect()
});

pub fn router() -> Router<AppState> {
    Router::new().route("/icons/{file}", get(serve_icon))
}

async fn serve_icon(Path(file): Path<String>, headers: HeaderMap) -> Response {
    // Traversal is already structurally impossible — one path segment, and the
    // bytes come from a compiled table rather than the filesystem — but naming
    // the accepted shape keeps the surface obviously closed.
    let Some(name) = file.strip_suffix(".svg").filter(|n| is_icon_name(n)) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let Some(icon) = ICONS.get(name) else {
        return StatusCode::NOT_FOUND.into_response();
    };

    let base = [
        (header::CONTENT_TYPE, "image/svg+xml; charset=utf-8"),
        (header::CACHE_CONTROL, CACHE_CONTROL),
        (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
        (header::CONTENT_SECURITY_POLICY, ICON_CSP),
    ];

    if headers
        .get(header::IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.split(',').any(|tag| tag.trim() == icon.etag))
    {
        return (
            StatusCode::NOT_MODIFIED,
            base,
            [(header::ETAG, icon.etag.clone())],
        )
            .into_response();
    }

    (base, [(header::ETAG, icon.etag.clone())], icon.bytes).into_response()
}

fn is_icon_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.chars()
            .next()
            .is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        && s.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-')
}

#[cfg(test)]
mod tests {
    use super::*;
    use overslash_core::service_icon::BUILTIN_ICON_SLUGS;

    fn assets_dir() -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("assets/service-icons")
    }

    /// The generated table and the files on disk are produced together by
    /// `make service-icons`; a hand-edit to either one has to fail loudly.
    #[test]
    fn embedded_table_matches_the_asset_directory() {
        let mut on_disk: Vec<String> = std::fs::read_dir(assets_dir())
            .unwrap()
            .filter_map(|e| {
                let name = e.unwrap().file_name().to_string_lossy().into_owned();
                name.strip_suffix(".svg").map(str::to_string)
            })
            .collect();
        on_disk.sort();

        let mut embedded: Vec<String> = BUILTIN_ICONS.iter().map(|(n, _)| n.to_string()).collect();
        embedded.sort();

        assert_eq!(
            embedded, on_disk,
            "assets/service-icons is out of sync with icons.rs — run `make service-icons`"
        );
    }

    /// Core decides which templates get an implicit icon; this crate holds the
    /// bytes. If the two lists drift, a template resolves to a URL that 404s.
    #[test]
    fn embedded_table_matches_the_core_slug_list() {
        let mut embedded: Vec<&str> = BUILTIN_ICONS.iter().map(|(n, _)| *n).collect();
        embedded.sort_unstable();
        let mut slugs = BUILTIN_ICON_SLUGS.to_vec();
        slugs.sort_unstable();
        assert_eq!(embedded, slugs);
    }

    #[test]
    fn every_embedded_icon_is_inert_and_small() {
        for (name, bytes) in BUILTIN_ICONS {
            let svg = std::str::from_utf8(bytes).expect("{name} is not utf-8");
            assert!(bytes.len() < 32 * 1024, "{name} is over 32 KiB");
            assert!(svg.contains("viewBox=\""), "{name} has no viewBox");
            assert!(!svg.contains("<script"), "{name} contains a script");
            assert!(
                !svg.to_ascii_lowercase().contains("javascript:"),
                "{name} contains a javascript: URL"
            );
            assert!(!svg.contains("<image"), "{name} embeds a raster image");
            assert!(
                !svg.contains("href=\"http"),
                "{name} references a remote URL"
            );
        }
    }

    #[test]
    fn icon_names_are_constrained() {
        assert!(is_icon_name("github"));
        assert!(is_icon_name("google_calendar"));
        assert!(!is_icon_name("GitHub"));
        assert!(!is_icon_name("../secrets"));
        assert!(!is_icon_name("-leading"));
        assert!(!is_icon_name(""));
    }

    #[tokio::test]
    async fn serves_a_shipped_icon_with_caching_headers() {
        let resp = serve_icon(Path("github.svg".into()), HeaderMap::new()).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let h = resp.headers();
        assert_eq!(h[header::CONTENT_TYPE], "image/svg+xml; charset=utf-8");
        assert_eq!(h[header::CACHE_CONTROL], CACHE_CONTROL);
        assert_eq!(h[header::X_CONTENT_TYPE_OPTIONS], "nosniff");
        assert!(h.contains_key(header::ETAG));
    }

    #[tokio::test]
    async fn a_matching_etag_is_a_304() {
        let first = serve_icon(Path("github.svg".into()), HeaderMap::new()).await;
        let etag = first.headers()[header::ETAG].clone();

        let mut headers = HeaderMap::new();
        headers.insert(header::IF_NONE_MATCH, etag);
        let second = serve_icon(Path("github.svg".into()), headers).await;
        assert_eq!(second.status(), StatusCode::NOT_MODIFIED);
    }

    #[tokio::test]
    async fn unknown_and_malformed_names_are_404() {
        for name in [
            "nope.svg",
            "GitHub.SVG",
            "github",
            "github.png",
            "../../etc/passwd",
        ] {
            let resp = serve_icon(Path(name.into()), HeaderMap::new()).await;
            assert_eq!(resp.status(), StatusCode::NOT_FOUND, "{name}");
        }
    }

    /// The cloud dashboard is served from `app.` while this route lives on
    /// `api.`, and `config.public_url` — which `resolve_icon_url` builds on —
    /// is the *app* origin there, so every `icon_url` lands on the dashboard
    /// host. That host only serves what `vercel.json` explicitly proxies, so
    /// without a rewrite every icon 404s to `text/html` and silently degrades
    /// to a letter tile. It shipped exactly that way once.
    ///
    /// The invariant: wherever `/health` is proxied, `/icons` must be too —
    /// same host condition, same destination origin.
    #[test]
    fn every_health_rewrite_has_a_matching_icons_rewrite() {
        let path =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../dashboard/vercel.json");
        let cfg: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).expect("read vercel.json"))
                .expect("vercel.json is valid JSON");
        let rewrites = cfg["rewrites"].as_array().expect("rewrites array");

        // Key a block by its host condition (None = the catch-all block).
        let host_of = |r: &serde_json::Value| r["has"][0]["value"].as_str().map(str::to_string);
        let origin_of = |r: &serde_json::Value| {
            r["destination"]
                .as_str()
                .unwrap_or_default()
                .split("/health")
                .next()
                .unwrap_or_default()
                .to_string()
        };

        let health: Vec<_> = rewrites
            .iter()
            .filter(|r| r["source"] == "/health")
            .collect();
        assert!(
            !health.is_empty(),
            "no /health rewrites found — did the file move?"
        );

        for h in health {
            let host = host_of(h);
            let origin = origin_of(h);
            let found = rewrites.iter().any(|r| {
                r["source"] == "/icons/:path*"
                    && host_of(r) == host
                    && r["destination"]
                        .as_str()
                        .is_some_and(|d| d == format!("{origin}/icons/:path*"))
            });
            assert!(
                found,
                "vercel.json proxies /health for host {host:?} to {origin} but not /icons/:path* — \
                 icons will 404 to the SPA on that origin"
            );
        }
    }
}
