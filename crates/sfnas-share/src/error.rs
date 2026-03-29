#![deny(unsafe_code)]

use thiserror::Error;

/// All errors that can occur in share management operations.
#[derive(Debug, Error)]
pub enum ShareError {
    /// Samba configuration file could not be read or parsed.
    #[error("samba configuration error: {0}")]
    Config(String),

    /// A share with the given name was not found.
    #[error("share '{0}' not found")]
    NotFound(String),

    /// A share with the given name already exists.
    #[error("share '{0}' already exists")]
    AlreadyExists(String),

    /// A service management operation failed (start, stop, restart, reload).
    #[error("service error: {0}")]
    Service(String),

    /// A NAS user was not found.
    #[error("user '{0}' not found")]
    UserNotFound(String),

    /// A NAS user already exists.
    #[error("user '{0}' already exists")]
    UserAlreadyExists(String),

    /// A username is invalid (bad characters, reserved name, etc.).
    #[error("invalid username: {0}")]
    InvalidUsername(String),

    /// A share name is invalid (bad characters, too long, etc.).
    #[error("invalid share name: {0}")]
    InvalidShareName(String),

    /// A path validation failed (traversal, non-absolute, etc.).
    #[error("invalid path: {0}")]
    InvalidPath(String),

    /// A command execution failed.
    #[error("command failed: {0}")]
    Command(String),

    /// An rsync configuration error.
    #[error("rsync configuration error: {0}")]
    Rsync(String),

    /// Underlying I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}
