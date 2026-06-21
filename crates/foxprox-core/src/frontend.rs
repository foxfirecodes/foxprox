//! Frontend abstraction shared by TUN, proxy, DNS, and future TAP adapters.
//!
//! A frontend converts implementation-specific input into normalized
//! `NetworkEvent` values. The trait intentionally avoids async/runtime and raw
//! packet types so platform adapters can choose their own I/O model.

use crate::event::{Frontend, NetworkEvent, SandboxId};
use std::fmt;

/// Metadata that identifies a frontend instance.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct FrontendContext {
    /// Sandbox/session identifier.
    pub sandbox_id: SandboxId,
    /// Frontend kind.
    pub frontend: Frontend,
    /// Human-readable frontend instance label.
    pub label: String,
}

impl FrontendContext {
    /// Creates frontend metadata.
    pub fn new(sandbox_id: SandboxId, frontend: Frontend, label: impl Into<String>) -> Self {
        Self {
            sandbox_id,
            frontend,
            label: label.into(),
        }
    }
}

/// Error produced while normalizing frontend input.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FrontendError {
    /// Error category.
    pub kind: FrontendErrorKind,
    /// Human-readable detail for logs/audit.
    pub detail: String,
}

impl FrontendError {
    /// Creates a frontend error.
    pub fn new(kind: FrontendErrorKind, detail: impl Into<String>) -> Self {
        Self {
            kind,
            detail: detail.into(),
        }
    }
}

impl fmt::Display for FrontendError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}: {}", self.kind, self.detail)
    }
}

impl std::error::Error for FrontendError {}

/// Frontend error category.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum FrontendErrorKind {
    /// Input was malformed.
    MalformedInput,
    /// Input protocol is unsupported.
    UnsupportedProtocol,
    /// Input path failed closed.
    FailedClosed,
    /// Frontend I/O failed.
    Io,
    /// Frontend resource limit was reached.
    ResourceLimit,
}

/// Platform/frontend adapter boundary.
pub trait NetworkFrontend {
    /// Concrete input type accepted by this frontend.
    type Input;

    /// Returns metadata for this frontend instance.
    fn context(&self) -> &FrontendContext;

    /// Converts implementation-specific input into zero or more normalized events.
    ///
    /// Normalized events carry their own sandbox/frontend identity where the
    /// event shape requires it, so implementations should populate those fields
    /// from `context()` rather than duplicating identity in a wrapper.
    fn normalize(&mut self, input: Self::Input) -> Result<Vec<NetworkEvent>, FrontendError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frontend_context_preserves_identity() {
        let sandbox_id = SandboxId::new("alpha").unwrap();
        let context = FrontendContext::new(sandbox_id.clone(), Frontend::Tun, "tun-proof");
        assert_eq!(context.sandbox_id, sandbox_id);
        assert_eq!(context.frontend, Frontend::Tun);
        assert_eq!(context.label, "tun-proof");
    }

    #[test]
    fn frontend_error_is_displayable() {
        let error = FrontendError::new(FrontendErrorKind::MalformedInput, "short packet");
        assert!(error.to_string().contains("short packet"));
    }
}
