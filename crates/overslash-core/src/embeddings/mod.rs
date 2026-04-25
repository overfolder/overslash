//! Embedding backend for semantic search (SPEC §10).
//!
//! The `Embedder` trait is the seam between the API layer and whichever text
//! → vector backend is configured. Three implementations ship:
//!
//! - [`DisabledEmbedder`] — no-op, used when `OVERSLASH_EMBEDDINGS=off` or
//!   when the boot-time pgvector preflight fails. Returns empty vectors; the
//!   scorer blends them as zero-weight so search falls back to keyword +
//!   fuzzy.
//! - [`StubEmbedder`] — deterministic hash-based embedding, used in unit and
//!   integration tests so CI doesn't need to download model weights from
//!   HuggingFace.
//! - [`FastembedEmbedder`] — the real backend (behind the `embeddings` Cargo
//!   feature). Wraps `fastembed::TextEmbedding` with
//!   `BAAI/bge-small-en-v1.5` (384-dim).
//!
//! All three produce 384-dimensional vectors so they interop with the same
//! pgvector column and HNSW index.

/// Dimension of every vector this module produces. Kept constant across
/// implementations so the pgvector column type (`VECTOR(384)`) is valid
/// regardless of which backend the binary was built with.
pub const EMBEDDING_DIM: usize = 384;

/// Produces 384-dim float vectors for a batch of input texts.
///
/// Implementations are expected to be `Send + Sync` so they can live behind
/// an `Arc` inside the application state and be shared across request
/// handlers.
pub trait Embedder: Send + Sync {
    /// Embed a batch of texts. On success returns either:
    ///   - a `Vec<Vec<f32>>` of the same length as `texts`, each inner vec
    ///     of length `EMBEDDING_DIM` (the enabled case), or
    ///   - an empty outer `Vec` when the backend is disabled (signals "no
    ///     embeddings available — fall back to keyword + fuzzy").
    ///
    /// Callers must check `is_enabled()` (or the outer `Vec`'s length)
    /// before zipping with `texts`. Always-zipping consumers will
    /// out-of-bounds against the disabled backend — that's by design to
    /// force a fallback branch rather than silently emitting zero vectors.
    ///
    /// Callers should batch (e.g., 32 at a time) during backfill — the
    /// underlying ONNX model amortizes per-batch setup cost.
    fn embed(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>, EmbedError>;

    /// Whether this backend actually produces meaningful vectors. Used by
    /// the endpoint to decide whether to blend the embedding score at all
    /// (a [`DisabledEmbedder`] returns `false` and collapses the score to
    /// pure keyword + fuzzy).
    fn is_enabled(&self) -> bool {
        true
    }
}

#[derive(Debug, thiserror::Error)]
pub enum EmbedError {
    #[error("embedding backend failed: {0}")]
    Backend(String),
}

/// No-op backend used when embeddings are disabled (env kill-switch or
/// missing pgvector). Returns empty vectors and reports `is_enabled=false`
/// so the scorer skips it cleanly.
pub struct DisabledEmbedder;

impl Embedder for DisabledEmbedder {
    fn embed(&self, _texts: &[&str]) -> Result<Vec<Vec<f32>>, EmbedError> {
        // An empty outer vec signals "no embeddings available"; callers
        // treat this the same as "skipped".
        Ok(Vec::new())
    }

    fn is_enabled(&self) -> bool {
        false
    }
}

/// Deterministic hash-based embedder for tests. Produces a stable 384-dim
/// vector per input string so integration tests can exercise the full
/// pgvector path without downloading model weights. Cosine similarity
/// between two stub vectors reflects word overlap only — good enough to
/// prove the wiring works end-to-end.
pub struct StubEmbedder;

impl StubEmbedder {
    /// Embed a single text deterministically. Used by both the trait impl
    /// and by tests that want to precompute the expected query vector.
    pub fn embed_one(text: &str) -> Vec<f32> {
        let mut vec = vec![0f32; EMBEDDING_DIM];
        for token in text
            .to_lowercase()
            .split(|c: char| !c.is_alphanumeric())
            .filter(|t| !t.is_empty())
        {
            let h = fnv1a(token.as_bytes());
            // Spread across two slots so different tokens add energy to
            // different basis vectors; cosine similarity then reflects
            // token overlap in a stable way.
            let i = (h as usize) % EMBEDDING_DIM;
            let j = ((h.rotate_left(13)) as usize) % EMBEDDING_DIM;
            vec[i] += 1.0;
            vec[j] += 0.5;
        }
        normalize(&mut vec);
        vec
    }
}

impl Embedder for StubEmbedder {
    fn embed(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>, EmbedError> {
        Ok(texts.iter().map(|t| Self::embed_one(t)).collect())
    }
}

fn fnv1a(bytes: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for b in bytes {
        hash ^= *b as u64;
        hash = hash.wrapping_mul(0x100_0000_01b3);
    }
    hash
}

fn normalize(v: &mut [f32]) {
    let norm: f32 = v.iter().map(|x| x * x).sum::<f32>().sqrt();
    if norm > 0.0 {
        for x in v.iter_mut() {
            *x /= norm;
        }
    }
}

/// Real fastembed-backed implementation. Loads
/// `BAAI/bge-small-en-v1.5` (384-dim) from the local cache; on first boot
/// downloads ~130 MB of ONNX weights from HuggingFace. Subsequent boots
/// reuse the cache.
#[cfg(feature = "embeddings")]
pub struct FastembedEmbedder {
    // fastembed 5.x changed `embed` to take `&mut self`, but the trait — and
    // every caller via `Arc<dyn Embedder>` — holds a shared reference. Wrap
    // the model so the lock lives entirely inside this impl. ONNX inference
    // is the bottleneck and is already serialized internally, so the mutex
    // adds no meaningful contention.
    inner: std::sync::Mutex<fastembed::TextEmbedding>,
}

#[cfg(feature = "embeddings")]
impl FastembedEmbedder {
    /// Initialize with the default small English model. `cache_dir` controls
    /// where ONNX weights are downloaded/read; pass `None` to use the
    /// crate's default (a platform-appropriate cache path).
    pub fn new(cache_dir: Option<std::path::PathBuf>) -> Result<Self, EmbedError> {
        let mut opts = fastembed::InitOptions::new(fastembed::EmbeddingModel::BGESmallENV15);
        if let Some(dir) = cache_dir {
            opts = opts.with_cache_dir(dir);
        }
        let inner = fastembed::TextEmbedding::try_new(opts)
            .map_err(|e| EmbedError::Backend(format!("fastembed init failed: {e}")))?;
        Ok(Self {
            inner: std::sync::Mutex::new(inner),
        })
    }
}

#[cfg(feature = "embeddings")]
impl Embedder for FastembedEmbedder {
    fn embed(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>, EmbedError> {
        if texts.is_empty() {
            return Ok(Vec::new());
        }
        let owned: Vec<String> = texts.iter().map(|s| (*s).to_string()).collect();
        let mut guard = self
            .inner
            .lock()
            .map_err(|e| EmbedError::Backend(format!("fastembed mutex poisoned: {e}")))?;
        guard
            .embed(owned, None)
            .map_err(|e| EmbedError::Backend(format!("fastembed embed failed: {e}")))
    }
}

/// Compose the text a template action should be indexed under. Centralized
/// here (not in the repo or endpoint) so the backfill task, the write-path
/// hook, and the query-time embedder all produce the same string for the
/// same action — staleness detection compares raw source text.
pub fn action_source_text(
    service_display_name: &str,
    service_description: Option<&str>,
    action_key: &str,
    action_description: &str,
) -> String {
    let svc_desc = service_description.unwrap_or("");
    format!("{service_display_name} — {action_key}: {action_description} ({svc_desc})")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stub_embed_dim_matches() {
        let e = StubEmbedder;
        let v = e.embed(&["hello world"]).unwrap();
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].len(), EMBEDDING_DIM);
    }

    #[test]
    fn stub_is_deterministic() {
        let a = StubEmbedder::embed_one("send an email");
        let b = StubEmbedder::embed_one("send an email");
        assert_eq!(a, b);
    }

    #[test]
    fn stub_similar_texts_cluster() {
        // Cosine similarity of overlapping-word inputs should exceed that
        // of disjoint inputs. Proves the stub gives a meaningful signal.
        let email1 = StubEmbedder::embed_one("send an email");
        let email2 = StubEmbedder::embed_one("send email message");
        let unrelated = StubEmbedder::embed_one("charge a credit card");
        let s_same = cosine(&email1, &email2);
        let s_diff = cosine(&email1, &unrelated);
        assert!(
            s_same > s_diff,
            "overlap should be more similar: same={s_same} diff={s_diff}"
        );
    }

    #[test]
    fn disabled_returns_empty_and_reports_disabled() {
        let e = DisabledEmbedder;
        assert!(!e.is_enabled());
        assert!(e.embed(&["anything"]).unwrap().is_empty());
    }

    #[test]
    fn action_source_text_is_stable() {
        let a = action_source_text("Gmail", Some("Mail"), "send_message", "Send an email");
        let b = action_source_text("Gmail", Some("Mail"), "send_message", "Send an email");
        assert_eq!(a, b);
    }

    fn cosine(a: &[f32], b: &[f32]) -> f32 {
        let dot: f32 = a.iter().zip(b.iter()).map(|(x, y)| x * y).sum();
        let na: f32 = a.iter().map(|x| x * x).sum::<f32>().sqrt();
        let nb: f32 = b.iter().map(|x| x * x).sum::<f32>().sqrt();
        if na == 0.0 || nb == 0.0 {
            0.0
        } else {
            dot / (na * nb)
        }
    }
}
