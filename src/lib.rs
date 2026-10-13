#![allow(clippy::too_many_arguments, clippy::type_complexity)]

uniffi::setup_scaffolding!();

pub mod crypto;
pub mod delivery_issue;
pub mod device;
pub mod envelope;
pub mod ffi;
#[doc(hidden)] // G6 upgrade-fixture emission — a dev utility, not SDK API
pub mod fixtures;
pub mod keys;
pub mod limits;
pub mod manifest;
pub mod member;
pub mod message;
pub mod operation_log;
pub mod relay;
pub mod relay_address;
pub mod revocation;
pub mod session;
pub mod store;
pub mod version;

pub use keys::{NoisePublicKey, SigningPublicKey};
pub use limits::PROTOCOL_SIZE_LIMIT;
pub use operation_log::LogEntry;
pub use version::{END_TO_END_VERSION, TRANSPORT_VERSION};
