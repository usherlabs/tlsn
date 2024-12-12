use cipher::CipherError;
use hmac_sha256::PrfError;
use key_exchange::KeyExchangeError;
use mpz_memory_core::DecodeError;

use crate::leader::state::StateError;
use std::{error::Error, fmt::Display};

/// MPC-TLS protocol error.
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub struct MpcTlsError(#[from] ErrorRepr);

#[derive(Debug, thiserror::Error)]
enum ErrorRepr {
    /// An unexpected state was encountered
    State(Box<dyn Error + Send + Sync + 'static>),
    /// IO related error
    Io(Box<dyn Error + Send + Sync + 'static>),
    /// An error occurred during key exchange
    KeyExchange(Box<dyn Error + Send + Sync + 'static>),
    /// An error occurred during PRF
    Prf(Box<dyn Error + Send + Sync + 'static>),
    /// A stream cipher error
    Cipher(Box<dyn Error + Send + Sync + 'static>),
    /// An error occurred during encryption
    Encrypt(Box<dyn Error + Send + Sync + 'static>),
    /// An error occurred during decryption
    Decrypt(Box<dyn Error + Send + Sync + 'static>),
    /// An error occurred during tag computation
    Tag(Box<dyn Error + Send + Sync + 'static>),
    /// An error related to configuration.
    Config(Box<dyn Error + Send + Sync + 'static>),
    /// Peer misbehaved somehow, perhaps maliciously.
    PeerMisbehaved(Box<dyn Error + Send + Sync + 'static>),
    /// Virtual machine error
    Vm(Box<dyn Error + Send + Sync + 'static>),
    /// Decoding error
    Decode(Box<dyn Error + Send + Sync + 'static>),
    /// Actor error
    Actor(Box<dyn Error + Send + Sync + 'static>),
    /// Other error
    Other(Box<dyn Error + Send + Sync + 'static>),
}

impl Display for ErrorRepr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ErrorRepr::State(error) => write!(f, "{error}"),
            ErrorRepr::Io(error) => write!(f, "{error}"),
            ErrorRepr::KeyExchange(error) => write!(f, "{error}"),
            ErrorRepr::Prf(error) => write!(f, "{error}"),
            ErrorRepr::Cipher(error) => write!(f, "{error}"),
            ErrorRepr::Encrypt(error) => write!(f, "{error}"),
            ErrorRepr::Decrypt(error) => write!(f, "{error}"),
            ErrorRepr::Tag(error) => write!(f, "{error}"),
            ErrorRepr::Config(error) => write!(f, "{error}"),
            ErrorRepr::PeerMisbehaved(error) => write!(f, "{error}"),
            ErrorRepr::Vm(error) => write!(f, "{error}"),
            ErrorRepr::Decode(error) => write!(f, "{error}"),
            ErrorRepr::Actor(error) => write!(f, "{error}"),
            ErrorRepr::Other(error) => write!(f, "{error}"),
        }
    }
}

impl MpcTlsError {
    pub(crate) fn state<E>(err: E) -> MpcTlsError
    where
        E: Into<Box<dyn Error + Send + Sync + 'static>>,
    {
        Self(ErrorRepr::State(err.into()))
    }

    pub(crate) fn io<E>(err: E) -> MpcTlsError
    where
        E: Into<Box<dyn Error + Send + Sync + 'static>>,
    {
        Self(ErrorRepr::Io(err.into()))
    }

    pub(crate) fn key_exchange<E>(err: E) -> MpcTlsError
    where
        E: Into<Box<dyn Error + Send + Sync + 'static>>,
    {
        Self(ErrorRepr::KeyExchange(err.into()))
    }

    pub(crate) fn prf<E>(err: E) -> MpcTlsError
    where
        E: Into<Box<dyn Error + Send + Sync + 'static>>,
    {
        Self(ErrorRepr::Prf(err.into()))
    }

    pub(crate) fn cipher<E>(err: E) -> MpcTlsError
    where
        E: Into<Box<dyn Error + Send + Sync + 'static>>,
    {
        Self(ErrorRepr::Cipher(err.into()))
    }

    pub(crate) fn encrypt<E>(err: E) -> MpcTlsError
    where
        E: Into<Box<dyn Error + Send + Sync + 'static>>,
    {
        Self(ErrorRepr::Encrypt(err.into()))
    }

    pub(crate) fn decrypt<E>(err: E) -> MpcTlsError
    where
        E: Into<Box<dyn Error + Send + Sync + 'static>>,
    {
        Self(ErrorRepr::Decrypt(err.into()))
    }

    pub(crate) fn tag<E>(err: E) -> MpcTlsError
    where
        E: Into<Box<dyn Error + Send + Sync + 'static>>,
    {
        Self(ErrorRepr::Tag(err.into()))
    }

    pub(crate) fn config<E>(err: E) -> MpcTlsError
    where
        E: Into<Box<dyn Error + Send + Sync + 'static>>,
    {
        Self(ErrorRepr::Config(err.into()))
    }

    pub(crate) fn peer<E>(err: E) -> MpcTlsError
    where
        E: Into<Box<dyn Error + Send + Sync + 'static>>,
    {
        Self(ErrorRepr::PeerMisbehaved(err.into()))
    }

    pub(crate) fn vm<E>(err: E) -> MpcTlsError
    where
        E: Into<Box<dyn Error + Send + Sync + 'static>>,
    {
        Self(ErrorRepr::Vm(err.into()))
    }

    pub(crate) fn decode<E>(err: E) -> MpcTlsError
    where
        E: Into<Box<dyn Error + Send + Sync + 'static>>,
    {
        Self(ErrorRepr::Decode(err.into()))
    }

    pub(crate) fn actor<E>(err: E) -> MpcTlsError
    where
        E: Into<Box<dyn Error + Send + Sync + 'static>>,
    {
        Self(ErrorRepr::Actor(err.into()))
    }

    pub(crate) fn other<E>(err: E) -> MpcTlsError
    where
        E: Into<Box<dyn Error + Send + Sync + 'static>>,
    {
        Self(ErrorRepr::Other(err.into()))
    }
}

impl From<StateError> for MpcTlsError {
    fn from(value: StateError) -> Self {
        MpcTlsError::state(value)
    }
}

impl From<KeyExchangeError> for MpcTlsError {
    fn from(value: KeyExchangeError) -> Self {
        MpcTlsError::key_exchange(value)
    }
}

impl From<DecodeError> for MpcTlsError {
    fn from(value: DecodeError) -> Self {
        MpcTlsError::decode(value)
    }
}

impl From<PrfError> for MpcTlsError {
    fn from(value: PrfError) -> Self {
        MpcTlsError::prf(value)
    }
}

impl From<CipherError> for MpcTlsError {
    fn from(value: CipherError) -> Self {
        MpcTlsError::cipher(value)
    }
}

impl From<crate::record_layer::aead::ghash::UniversalHashError> for MpcTlsError {
    fn from(value: crate::record_layer::aead::ghash::UniversalHashError) -> Self {
        MpcTlsError::tag(value)
    }
}

impl From<std::io::Error> for MpcTlsError {
    fn from(value: std::io::Error) -> Self {
        MpcTlsError::io(value)
    }
}

impl From<ludi::Error> for MpcTlsError {
    fn from(value: ludi::Error) -> Self {
        MpcTlsError::actor(value)
    }
}
