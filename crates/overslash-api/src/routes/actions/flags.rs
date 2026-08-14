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
use crate::services::wait_mode;

use super::dto::{CallRequest, Delivery, ExecutionMode, ResolvedModeC};

/// Whether this call defers its body, and how it runs relative to the request
/// path.
pub(super) struct RequestFlags {
    pub(super) deliver_url: bool,
    /// What the *caller* asked for, and only that — `None` means the request
    /// named no mode.
    ///
    /// It stayed an `Option` when the action template became rung 2 of the
    /// cascade: "absent" and "explicitly sync" now decide different things.
    /// Every refusal below fires on a caller-named mode, while an absent one
    /// leaves room for [`wait_mode::resolve`](crate::services::wait_mode::resolve)
    /// to supply a template's and, where a flag here would have refused it,
    /// silently demote it instead.
    pub(super) mode: Option<ExecutionMode>,
    /// Everything that makes a deferred mode impossible, in the form the
    /// cascade wants. Assembled here so the demotion rule and the refusal rule
    /// read the same facts and cannot drift.
    pub(super) blockers: wait_mode::Blockers,
}

/// Request-only combinations, checked before any resolution.
pub(super) fn validate_request(req: &CallRequest) -> Result<RequestFlags, AppError> {
    let deliver_url = req.deliver.is_some_and(Delivery::is_url);
    let mode = req.execution;
    let prefer_stream = req.prefer_stream.unwrap_or(false);
    let blockers = wait_mode::Blockers {
        prefer_stream,
        deliver_url,
        return_url: req.return_url.is_some(),
        // The two template-shaped blockers are unknown until the action
        // resolves; `validate_resolved` fills them in.
        ..Default::default()
    };

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

    // Keyed on `is_deferred`, not on the variant: a hybrid call may leave this
    // connection, and a flag that is incoherent once it does is incoherent
    // whether or not the race happens to be won. Refusing on the possibility
    // is what keeps "hybrid answers `called` or `accepted`" true — a mode that
    // silently dropped `prefer_stream` on handoff would be a third behaviour.
    if let Some(mode) = mode.filter(|m| m.is_deferred()) {
        let m = mode.label();
        if prefer_stream {
            return Err(AppError::BadRequest(format!(
                "prefer_stream cannot be combined with execution: \"{m}\" — \
                 prefer_stream streams the bytes on this response, and a call \
                 that may leave this connection has no response to stream onto"
            )));
        }
        if deliver_url {
            return Err(AppError::BadRequest(format!(
                "deliver: \"url\" cannot be combined with execution: \"{m}\" — \
                 the download token would start expiring before the call runs; \
                 poll GET /v1/executions/{{id}} and read the body from the \
                 execution instead"
            )));
        }
        if req.return_url.is_some() {
            return Err(AppError::BadRequest(format!(
                "return_url cannot be combined with execution: \"{m}\" — \
                 return_url redirects the caller after a reactive auth flow, \
                 and a call that may leave this connection has no caller \
                 waiting to be redirected"
            )));
        }
    }

    if req.handoff_after_ms == Some(0) {
        return Err(AppError::BadRequest(
            "handoff_after_ms must be greater than 0 — a zero handoff is \
             execution: \"async\" with extra bookkeeping; ask for that instead"
                .into(),
        ));
    }

    Ok(RequestFlags {
        deliver_url,
        mode,
        blockers,
    })
}

/// The one refusal that cannot be decided until the cascade has run.
///
/// Naming `handoff_after_ms` without the mode it belongs to is a 400 rather
/// than a silently ignored field: `deny_unknown_fields` means a caller who set
/// it believes it is doing something. What changed when the action template
/// became a rung is *which* mode counts — a caller that sends only
/// `handoff_after_ms` against an action declaring `wait-mode: hybrid` is asking
/// a coherent question, and answering it with a 400 would make the knob
/// unusable on exactly the actions it was built for.
pub(super) fn validate_effective(
    req: &CallRequest,
    effective: ExecutionMode,
) -> Result<(), AppError> {
    if req.handoff_after_ms.is_some() && !effective.is_hybrid() {
        return Err(AppError::BadRequest(format!(
            "handoff_after_ms is only valid with execution: \"hybrid\" — it is \
             how long that mode holds the connection before answering 202, and \
             this call resolved to \"{}\", which has no handoff to schedule",
            effective.label()
        )));
    }
    Ok(())
}

/// Combinations that only become visible once the action template resolves.
///
/// Two jobs in one pass, because both read the same two template facts.
/// It **refuses** when the caller named a deferred mode, and it **reports**
/// those facts as [`wait_mode::Blockers`] either way, so a template's own
/// `wait-mode` can be demoted against exactly the conditions that would have
/// refused a caller's. Deriving the two separately is how they would drift.
///
/// Only `/call` calls this today. The comment that used to claim `/validate`
/// did was aspirational — the dry-run can still green-light a deferred shape
/// the real call refuses, which is recorded in TECH_DEBT rather than fixed
/// here, since closing it adds 400s to an endpoint whose whole job is to
/// answer without side effects.
pub(super) fn validate_resolved(
    req: &CallRequest,
    resolved: Option<&ResolvedModeC>,
) -> Result<wait_mode::Blockers, AppError> {
    // The action key comes from the request rather than the resolved struct:
    // `ResolvedModeC` carries the service definition and the instance binding,
    // not the key that selected the action.
    let action_key = req.action.as_deref().unwrap_or_default();
    let Some(resolved) = resolved else {
        return Ok(wait_mode::Blockers::default());
    };

    let platform_runtime =
        resolved.svc.runtime == overslash_core::types::service::Runtime::Platform;
    let binary_response = resolved
        .svc
        .actions
        .get(action_key)
        .is_some_and(|a| a.response_type.as_deref() == Some("binary"));
    let blockers = wait_mode::Blockers {
        platform_runtime,
        binary_response,
        ..Default::default()
    };

    let Some(m) = req
        .execution
        .filter(|e| e.is_deferred())
        .map(ExecutionMode::label)
    else {
        return Ok(blockers);
    };

    if platform_runtime {
        return Err(AppError::BadRequest(format!(
            "service '{}' has runtime=platform; execution: \"{m}\" is not supported — \
             platform actions run in-process and return immediately, so there is \
             nothing to defer",
            resolved.svc.key
        )));
    }

    // Binary is refused rather than quietly corrupted: the buffered path runs
    // response bodies through `String::from_utf8_lossy` before they reach the
    // row, so an async binary result would be mangled on the way in. The real
    // fix is object storage for results, which is a follow-up.
    if binary_response {
        return Err(AppError::BadRequest(format!(
            "action '{}' on service '{}' returns binary; execution: \"{m}\" is not \
             supported — the bytes would be buffered into the execution row and \
             corrupted. Call it synchronously with deliver: \"url\".",
            action_key, resolved.svc.key
        )));
    }

    Ok(blockers)
}
