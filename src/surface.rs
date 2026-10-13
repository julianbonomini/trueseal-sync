//! The canonical public surface, enumerated FROM THE CODE (SYNC-21, docs
//! ADR-0003).
//!
//! This module is the single in-code source for the Shared Facts
//! (`docs/shared-facts.json`) and the G12 parity surface
//! (`docs/api-surface.json`). Both files are written by
//! `cargo run --bin gen-shared-facts` from the functions here — never by
//! hand. Three drift gates keep them honest:
//!
//! 1. Every `*_name`/`*_code`/`*_kind` function below is an EXHAUSTIVE
//!    match, so adding a variant to a public enum fails compilation until
//!    it is named here.
//! 2. `ffi::tests::the_ffi_surface_matches_api_surface_json` and
//!    `ffi::tests::shared_facts_json_matches_the_code` fail if the
//!    checked-in files disagree with this module.
//! 3. CI runs `gen-shared-facts --check`, which fails if the files were
//!    not regenerated after a change.
//!
//! The module is `#[doc(hidden)]`: it exists for the generator, the tests
//! and future SDK codegen (SDK-3/G12), not for app developers.

use crate::ffi::{
    AdmissionDropReason, ConnectionState, DeliveryIssue, GroupStatus, JoinRequest,
    SendFailedReason, StatusReason, TrueSealError, TrueSealEvent, UnreadableReason,
};

// ── Errors (ADR-0028: 14 canonical cases, as amended by ADR-0032 and SYNC-15) ─

/// One instance of every error variant. Field values are dummies — only the
/// variant identity matters for naming.
pub fn every_error() -> Vec<TrueSealError> {
    vec![
        TrueSealError::InvalidRelayAddress { msg: String::new() },
        TrueSealError::InvalidNamespace { msg: String::new() },
        TrueSealError::Storage { msg: String::new() },
        TrueSealError::Closed,
        TrueSealError::NotMember {
            status: GroupStatus::NotJoined,
        },
        TrueSealError::AlreadyInGroup,
        TrueSealError::InvalidPairingToken,
        TrueSealError::PairingClosed,
        TrueSealError::GroupFull { max: 32 },
        TrueSealError::MemberNotFound,
        TrueSealError::PayloadTooLarge { max: 61440 },
        TrueSealError::MessageHandlerAlreadySet,
        TrueSealError::StoreTooNew {
            found: 2,
            supported: 1,
        },
        TrueSealError::ManifestVersionExhausted,
    ]
}

/// One canonical code per error variant — an exhaustive match, so the
/// compiler fails here when a 15th case appears.
pub fn error_code(e: &TrueSealError) -> &'static str {
    match e {
        TrueSealError::InvalidRelayAddress { .. } => "invalidRelayAddress",
        TrueSealError::InvalidNamespace { .. } => "invalidNamespace",
        TrueSealError::Storage { .. } => "storage",
        TrueSealError::Closed => "closed",
        TrueSealError::NotMember { .. } => "notMember",
        TrueSealError::AlreadyInGroup => "alreadyInGroup",
        TrueSealError::InvalidPairingToken => "invalidPairingToken",
        TrueSealError::PairingClosed => "pairingClosed",
        TrueSealError::GroupFull { .. } => "groupFull",
        TrueSealError::MemberNotFound => "memberNotFound",
        TrueSealError::PayloadTooLarge { .. } => "payloadTooLarge",
        TrueSealError::MessageHandlerAlreadySet => "messageHandlerAlreadySet",
        TrueSealError::StoreTooNew { .. } => "storeTooNew",
        TrueSealError::ManifestVersionExhausted => "manifestVersionExhausted",
    }
}

/// The canonical error codes, in declaration order.
pub fn errors() -> Vec<&'static str> {
    every_error().iter().map(error_code).collect()
}

// ── Events (ADR-0028) ─────────────────────────────────────────────────────────

pub fn every_event() -> Vec<TrueSealEvent> {
    vec![
        TrueSealEvent::StatusChanged {
            status: GroupStatus::Member,
            reason: StatusReason::Joined,
        },
        TrueSealEvent::MembersChanged { members: vec![] },
        TrueSealEvent::JoinRequest {
            request: JoinRequest {
                id: String::new(),
                name: String::new(),
            },
        },
        TrueSealEvent::ConnectionChanged {
            connection: ConnectionState::Connected,
        },
        TrueSealEvent::AdmissionDropped {
            name: String::new(),
            reason: AdmissionDropReason::GroupFull,
        },
    ]
}

pub fn event_kind(e: &TrueSealEvent) -> &'static str {
    match e {
        TrueSealEvent::StatusChanged { .. } => "statusChanged",
        TrueSealEvent::MembersChanged { .. } => "membersChanged",
        TrueSealEvent::JoinRequest { .. } => "joinRequest",
        TrueSealEvent::ConnectionChanged { .. } => "connectionChanged",
        TrueSealEvent::AdmissionDropped { .. } => "admissionDropped",
    }
}

pub fn events() -> Vec<&'static str> {
    every_event().iter().map(event_kind).collect()
}

// ── Group statuses and status reasons (ADR-0028, ADR-0029, ADR-0032) ─────────

pub fn every_status() -> Vec<GroupStatus> {
    vec![
        GroupStatus::NotJoined,
        GroupStatus::PendingJoin,
        GroupStatus::Member,
        GroupStatus::Leaving,
        GroupStatus::Destroying,
    ]
}

pub fn status_name(s: &GroupStatus) -> &'static str {
    match s {
        GroupStatus::NotJoined => "notJoined",
        GroupStatus::PendingJoin => "pendingJoin",
        GroupStatus::Member => "member",
        GroupStatus::Leaving => "leaving",
        GroupStatus::Destroying => "destroying",
    }
}

pub fn statuses() -> Vec<&'static str> {
    every_status().iter().map(status_name).collect()
}

pub fn every_status_reason() -> Vec<StatusReason> {
    vec![
        StatusReason::Created,
        StatusReason::Joined,
        StatusReason::Left,
        StatusReason::Removed,
        StatusReason::Destroyed,
        StatusReason::StoreReset,
    ]
}

pub fn status_reason_name(r: &StatusReason) -> &'static str {
    match r {
        StatusReason::Created => "created",
        StatusReason::Joined => "joined",
        StatusReason::Left => "left",
        StatusReason::Removed => "removed",
        StatusReason::Destroyed => "destroyed",
        StatusReason::StoreReset => "storeReset",
    }
}

pub fn status_reasons() -> Vec<&'static str> {
    every_status_reason()
        .iter()
        .map(status_reason_name)
        .collect()
}

// ── Connection states (ADR-0028) ──────────────────────────────────────────────

pub fn every_connection_state() -> Vec<ConnectionState> {
    vec![
        ConnectionState::Connecting,
        ConnectionState::Connected,
        ConnectionState::Disconnected,
        ConnectionState::RelayVersionUnsupported { min: 1, max: 1 },
    ]
}

pub fn connection_state_name(c: &ConnectionState) -> &'static str {
    match c {
        ConnectionState::Connecting => "connecting",
        ConnectionState::Connected => "connected",
        ConnectionState::Disconnected => "disconnected",
        ConnectionState::RelayVersionUnsupported { .. } => "relayVersionUnsupported",
    }
}

pub fn connection_states() -> Vec<&'static str> {
    every_connection_state()
        .iter()
        .map(connection_state_name)
        .collect()
}

// ── Delivery issues and their reason enums (ADR-0026, ADR-0034) ───────────────

pub fn every_issue() -> Vec<DeliveryIssue> {
    vec![
        DeliveryIssue::Unreadable {
            reason: UnreadableReason::Malformed,
        },
        DeliveryIssue::Unauthorized,
        DeliveryIssue::HeldForUpgrade { version: 2 },
        DeliveryIssue::HandlerGaveUp {
            message_id: String::new(),
            error: String::new(),
        },
        DeliveryIssue::SendFailed {
            message_id: String::new(),
            reason: SendFailedReason::Expired,
        },
    ]
}

pub fn issue_kind(i: &DeliveryIssue) -> &'static str {
    match i {
        DeliveryIssue::Unreadable { .. } => "unreadable",
        DeliveryIssue::Unauthorized => "unauthorized",
        DeliveryIssue::HeldForUpgrade { .. } => "heldForUpgrade",
        DeliveryIssue::HandlerGaveUp { .. } => "handlerGaveUp",
        DeliveryIssue::SendFailed { .. } => "sendFailed",
    }
}

pub fn delivery_issues() -> Vec<&'static str> {
    every_issue().iter().map(issue_kind).collect()
}

pub fn every_unreadable_reason() -> Vec<UnreadableReason> {
    vec![
        UnreadableReason::Malformed,
        UnreadableReason::SenderOutdated,
        UnreadableReason::Expired,
        UnreadableReason::DroppedWhileHeld,
    ]
}

pub fn unreadable_reason_name(r: &UnreadableReason) -> &'static str {
    match r {
        UnreadableReason::Malformed => "malformed",
        UnreadableReason::SenderOutdated => "senderOutdated",
        UnreadableReason::Expired => "expired",
        UnreadableReason::DroppedWhileHeld => "droppedWhileHeld",
    }
}

pub fn unreadable_reasons() -> Vec<&'static str> {
    every_unreadable_reason()
        .iter()
        .map(unreadable_reason_name)
        .collect()
}

pub fn every_send_failed_reason() -> Vec<SendFailedReason> {
    vec![
        SendFailedReason::TooLarge,
        SendFailedReason::Malformed,
        SendFailedReason::Expired,
    ]
}

pub fn send_failed_reason_name(r: &SendFailedReason) -> &'static str {
    match r {
        SendFailedReason::TooLarge => "tooLarge",
        SendFailedReason::Malformed => "malformed",
        SendFailedReason::Expired => "expired",
    }
}

pub fn send_failed_reasons() -> Vec<&'static str> {
    every_send_failed_reason()
        .iter()
        .map(send_failed_reason_name)
        .collect()
}

pub fn admission_drop_reason_name(r: &AdmissionDropReason) -> &'static str {
    match r {
        AdmissionDropReason::GroupFull => "groupFull",
    }
}

pub fn admission_drop_reasons() -> Vec<&'static str> {
    vec![admission_drop_reason_name(&AdmissionDropReason::GroupFull)]
}

// ── Limits (ADR-0025, ADR-0027, ADR-0022) ─────────────────────────────────────

/// The Protocol Size Limit in bytes (61,440, ADR-0025). `maxPayloadBytes`.
pub fn max_payload_bytes() -> u32 {
    crate::limits::PROTOCOL_SIZE_LIMIT as u32
}

/// The Maximum Group Size (32, ADR-0027). `maxGroupSize`.
pub fn max_group_size() -> u32 {
    crate::session::MAX_GROUP_SIZE as u32
}

/// Cap on newer-End-to-End-Version Blobs held unacked per Device
/// (100, ADR-0022).
pub fn max_held_blobs() -> u32 {
    crate::version::MAX_HELD_BLOBS as u32
}

// ── Versions (ADR-0022, ADR-0032) ─────────────────────────────────────────────

/// The one Transport Version this build speaks (ADR-0022).
pub fn transport_version() -> u32 {
    crate::version::TRANSPORT_VERSION
}

/// The one End-to-End Version this build speaks (ADR-0022).
pub fn end_to_end_version() -> u32 {
    crate::version::END_TO_END_VERSION
}

/// The Store Version this build writes (ADR-0032).
pub fn store_version() -> u32 {
    crate::version::STORE_VERSION
}

/// The migration floor: the oldest Store Version this build migrates
/// (ADR-0032).
pub fn store_migration_floor() -> u32 {
    crate::version::STORE_MIGRATION_FLOOR
}

/// The core package version of the generating build (`sdkVersion` in
/// `TrueSeal.info`). Package versions imply nothing about wire
/// compatibility (ADR-0022) — the protocol versions above are the
/// compatibility facts.
pub fn sdk_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

// ── Relay Address format (ADR-0028; grammar pinned with the relay, SYNC-15) ───

/// The Relay Address format string, as documented in ADR-0028 and parsed
/// byte-identically by `crate::relay_address` and the Go relay
/// (trueseal-relay PR #50).
pub fn relay_address_format() -> &'static str {
    "trueseal://<relay public key hex>@host[:receivePort][?push=pushPort]"
}

/// The Relay Address scheme.
pub fn relay_address_scheme() -> &'static str {
    crate::relay_address::SCHEME
}

/// Default Receive Session port (7700).
pub fn relay_address_default_receive_port() -> u16 {
    crate::relay_address::DEFAULT_RECEIVE_PORT
}

/// Default Push Session port (7701).
pub fn relay_address_default_push_port() -> u16 {
    crate::relay_address::DEFAULT_PUSH_PORT
}
