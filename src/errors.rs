use thiserror::Error;

#[derive(Error, Debug)]
#[allow(dead_code)]
pub enum RyptonError {
    #[error("Vault not initialized. Run 'rypton init' first.")]
    VaultNotInitialized,

    #[error("Master password verification failed. Wrong password or corrupted vault.")]
    AuthenticationFailed,

    #[error("Vault item not found: {0}")]
    ItemNotFound(String),

    #[error("File not found: {0}")]
    FileNotFound(String),

    #[error("Path is not a file: {0}")]
    NotAFile(String),

    #[error("Path is not a directory: {0}")]
    NotADirectory(String),

    #[error("Encryption failed: {0}")]
    EncryptionError(String),

    #[error("Decryption failed: {0}")]
    DecryptionError(String),

    #[error("Key derivation failed: {0}")]
    KeyDerivationError(String),

    #[error("Integrity check failed for item: {0}")]
    IntegrityError(String),

    #[error("Password too weak. Use at least 12 characters with mixed case, digits, and symbols.")]
    WeakPassword,

    #[error("Vault already initialized at {0}")]
    VaultAlreadyExists(String),

    #[error("Insufficient privileges. This operation requires root (sudo).")]
    InsufficientPrivileges,

    #[error("System file tamper detected: {0}")]
    TamperDetected(String),

    #[error("Immutable flag operation failed: {0}")]
    ImmutableFlagError(String),

    #[error("Baseline not found. Run 'rypton system baseline' first.")]
    BaselineNotFound,

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}
