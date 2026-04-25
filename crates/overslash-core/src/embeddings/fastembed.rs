//! Real fastembed-backed [`Embedder`] implementation.
//!
//! Loaded only behind the `embeddings` Cargo feature. Excluded from CI
//! coverage because exercising it requires downloading ~130 MB of ONNX
//! weights from HuggingFace; tests use [`super::StubEmbedder`] instead.

use super::{EmbedError, Embedder};

/// Real fastembed-backed implementation. Loads
/// `BAAI/bge-small-en-v1.5` (384-dim) from the local cache; on first boot
/// downloads ~130 MB of ONNX weights from HuggingFace. Subsequent boots
/// reuse the cache.
pub struct FastembedEmbedder {
    // fastembed 5.x changed `embed` to take `&mut self`, but the trait — and
    // every caller via `Arc<dyn Embedder>` — holds a shared reference. Wrap
    // the model so the lock lives entirely inside this impl. ONNX inference
    // is the bottleneck and is already serialized internally, so the mutex
    // adds no meaningful contention.
    inner: std::sync::Mutex<fastembed::TextEmbedding>,
}

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
