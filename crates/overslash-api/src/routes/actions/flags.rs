//! Flag-combination validation for `/v1/actions/call`.
//!
//! Every rejection here follows the rule the deferred-delivery guards
//! established: when two flags give contradictory instructions, refusing is the
//! only safe answer, because silently honouring one of them is how a caller
//! ends up holding something it had explicitly ruled out.
//!
//! Split into two passes because they need different things. [`validate_request`]
//! reads only the request and so can run before any resolution, keeping the
//! cheapest structurally-impossible answer first. [`validate_resolved`] needs
//! the action template, so it runs immediately after
//! `resolve_action_metadata` — still above argument coercion, for the same
//! reason the argument gate sits above the permission walk.

use crate::error::AppError;

use super::dto::{CallRequest, Delivery, ExecutionMode, ResolvedModeC};

/// Whether this call defers its body, and whether it runs off the request path.
pub(super) struct RequestFlags {
    pub(super) deliver_url: bool,
    pub(super) is_async: bool,
}

/// Request-only combinations, checked before any resolution.
pub(super) fn validate_request(req: &CallRequest) -> Result<RequestFlags, AppError> {
    let deliver_url = req.deliver.is_some_and(Delivery::is_url);
    let is_async = req.execution.is_some_and(ExecutionMode::is_async);
    let prefer_stream = req.prefer_stream.unwrap_or(false);

    // A filter narrows the body this response carries; streaming means there is
    // no buffered body to narrow. Letting both through would pipe a multi-MB
    // stream into a caller that asked for a small slice.
    if prefer_stream && req.filter.is_some() {
        return Err(AppError::BadRequest(
            "filter cannot be combined with prefer_stream".into(),
        ));
    }
    // With `deliver: "url"` the body never passes through the gateway at call
    // time, so a filter has nothing to read.
    if deliver_url && req.filter.is_some() {
        return Err(AppError::BadRequest(
            "filter cannot be combined with deliver: \"url\"".into(),
        ));
    }
    if deliver_url && prefer_stream {
        return Err(AppError::BadRequest(
            "prefer_stream cannot be combined with deliver: \"url\" — \
             prefer_stream streams the bytes inline on this response, \
             deliver: \"url\" defers them to a second request"
                .into(),
        ));
    }

    if is_async {
        if prefer_stream {
            return Err(AppError::BadRequest(
                "prefer_stream cannot be combined with execution: \"async\" — \
                 prefer_stream streams the bytes on this response, and an async \
                 call has no response to stream onto"
                    .into(),
            ));
        }
        if deliver_url {
            return Err(AppError::BadRequest(
                "deliver: \"url\" cannot be combined with execution: \"async\" — \
                 the download token would start expiring before the call runs; \
                 poll GET /v1/executions/{id} and read the body from the \
                 execution instead"
                    .into(),
            ));
        }
        if req.return_url.is_some() {
            return Err(AppError::BadRequest(
                "return_url cannot be combined with execution: \"async\" — \
                 return_url redirects the caller after a reactive auth flow, \
                 and an async call has no caller waiting to be redirected"
                    .into(),
            ));
        }
    }

    Ok(RequestFlags {
        deliver_url,
        is_async,
    })
}

/// Combinations that only become visible once the action template resolves.
///
/// Called from both `/call` and `/validate`, so the dry-run can never
/// green-light a shape the real call refuses.
pub(super) fn validate_resolved(
    req: &CallRequest,
    resolved: Option<&ResolvedModeC>,
) -> Result<(), AppError> {
    // The action key comes from the request rather than the resolved struct:
    // `ResolvedModeC` carries the service definition and the instance binding,
    // not the key that selected the action.
    let action_key = req.action.as_deref().unwrap_or_default();
    if !req.execution.is_some_and(ExecutionMode::is_async) {
        return Ok(());
    }
    let Some(resolved) = resolved else {
        return Ok(());
    };

    if resolved.svc.runtime == overslash_core::types::service::Runtime::Platform {
        return Err(AppError::BadRequest(format!(
            "service '{}' has runtime=platform; execution: \"async\" is not supported — \
             platform actions run in-process and return immediately, so there is \
             nothing to defer",
            resolved.svc.key
        )));
    }

    // Binary is refused rather than quietly corrupted: the buffered path runs
    // response bodies through `String::from_utf8_lossy` before they reach the
    // row, so an async binary result would be mangled on the way in. The real
    // fix is object storage for results, which is a follow-up.
    if let Some(action) = resolved.svc.actions.get(action_key)
        && action.response_type.as_deref() == Some("binary")
    {
        return Err(AppError::BadRequest(format!(
            "action '{}' on service '{}' returns binary; execution: \"async\" is not \
             supported — the bytes would be buffered into the execution row and \
             corrupted. Call it synchronously with deliver: \"url\".",
            action_key, resolved.svc.key
        )));
    }

    Ok(())
}
