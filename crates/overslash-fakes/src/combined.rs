//! Combined fake used by backend integration tests.
//!
//! Returns a single bound socket that serves the OAuth/OIDC + GitHub user
//! endpoints alongside the generic openapi (echo + webhook capture) handlers,
//! matching the surface the previous in-process `tests/common/mod.rs::start_mock()`
//! used to expose. New code should prefer the per-fake modules and start each
//! fake on its own port.

use axum::Router;
use std::net::SocketAddr;

use crate::{bind, openapi, serve};

pub struct CombinedHandle {
    pub addr: SocketAddr,
    pub url: String,
    pub openapi_state: openapi::SharedState,
    handle: crate::Handle,
}

impl CombinedHandle {
    pub fn shutdown(self) {
        self.handle.shutdown();
    }
}

/// Start the combined fake on `127.0.0.1:0` (OS-assigned). Equivalent to the
/// legacy `start_mock()` helper.
pub async fn start_in_process() -> CombinedHandle {
    let (listener, addr, url) = bind("127.0.0.1:0").await.expect("bind combined fake");
    let openapi_state = std::sync::Arc::new(tokio::sync::Mutex::new(openapi::State_::default()));
    let app = Router::new()
        .merge(crate::oauth::router())
        .merge(openapi::router(openapi_state.clone()));
    let handle = serve(listener, addr, url.clone(), app);
    CombinedHandle {
        addr,
        url,
        openapi_state,
        handle,
    }
}
