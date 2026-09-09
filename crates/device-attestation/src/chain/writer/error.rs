// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

#[derive(Debug, thiserror::Error)]
pub enum WriterError {
    /// A second writer took the lease, so this one must stop writing at once.
    #[error("lost the writer lease {0}")]
    LeaseLost(&'static str),

    /// The outbox database.
    #[error(transparent)]
    Db(#[from] sqlx::Error),

    /// Anything the chain did, or that happened while talking to it.
    #[error(transparent)]
    Chain(#[from] anyhow::Error),
}

impl WriterError {
    pub fn is_lease_lost(&self) -> bool {
        matches!(self, WriterError::LeaseLost(_))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_chain_error_renders_without_a_prefix() {
        let reason = "Invalid transaction: Inability to pay some fees";
        let wrapped = WriterError::Chain(anyhow::anyhow!(reason));
        assert_eq!(wrapped.to_string(), reason);
        assert!(!wrapped.is_lease_lost());
    }

    #[test]
    fn a_lost_lease_names_what_it_interrupted() {
        let error = WriterError::LeaseLost("while assigning");
        assert_eq!(error.to_string(), "lost the writer lease while assigning");
        assert!(error.is_lease_lost());
    }
}
