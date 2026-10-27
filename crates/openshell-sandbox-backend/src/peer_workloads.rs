// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Driver/runtime contract for peer workload containers.
//!
//! A Kubernetes sandbox may run additional regular containers ("peers") next
//! to the canonical `agent` container. The peers share the Pod network
//! namespace (and therefore `localhost`) and any driver-declared volumes, the
//! sandbox policy, and the sandbox lifecycle. They do not form additional
//! isolation boundaries: the supervisor still sees exactly one boundary, served
//! by the primary `openshell-sandbox` runtime in the `agent` container.
//!
//! Each peer container runs `openshell-sandbox peer` as its entrypoint. That
//! subordinate runtime owns the peer's launcher, seccomp broker, Landlock and
//! binary-identity resolution inside the peer's own PID namespace and root
//! filesystem. It talks only to the primary, over a private Unix socket in a
//! Memory `emptyDir` shared by the two containers, and forwards every mediated
//! network operation to the primary, which feeds it into the single mediation
//! source the supervisor already consumes. This is backend-internal helper
//! coordination as permitted by RFC 0012; nothing here is supervisor-visible.
//!
//! Layout for the peer at `index` (all paths are fixed so neither side can be
//! steered by workload-controlled data):
//!
//! | Volume | Medium | Mounted in | Path |
//! |---|---|---|---|
//! | [`peer_control_volume_name`] | Memory `emptyDir` | agent | [`peer_control_dir_in_primary`] |
//! | | | peer | [`PEER_CONTROL_DIR`] |
//! | [`peer_boot_volume_name`] | Memory `emptyDir` | bootstrap init | [`peer_boot_dir_in_init`] |
//! | | | peer | [`PEER_BOOT_DIR`] |
//!
//! The driver writes a random one-use token for each peer into the generation
//! bootstrap Secret as [`peer_token_secret_key`] and records its SHA-256 in
//! [`PeerWorkloadConfig::token_sha256`]. The trusted init container stages the
//! token to [`PEER_TOKEN_FILE`] inside [`peer_boot_dir_in_init`]; the peer
//! container never mounts the Secret. The peer consumes (reads, then unlinks)
//! the token and presents it to the primary, which accepts exactly one
//! connection per peer socket and unlinks the socket after accepting.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

/// Maximum number of peer workload containers in one sandbox.
pub const MAX_PEER_WORKLOADS: usize = 16;

/// Maximum peer container name length. Kubernetes container names are DNS-1123
/// labels (63 characters); the cap leaves room for driver-owned suffixes.
pub const MAX_PEER_NAME_LEN: usize = 40;

/// Container names a peer may not use.
pub const RESERVED_PEER_NAMES: &[&str] = &["agent", "supervisor", "openshell-sandbox-bootstrap"];

/// Name prefix reserved for driver-owned containers and volumes.
pub const RESERVED_PEER_NAME_PREFIX: &str = "openshell";

/// `openshell-sandbox` subcommand that runs the subordinate peer runtime.
pub const PEER_SUBCOMMAND: &str = "peer";

/// Peer-side mount of its private control directory.
pub const PEER_CONTROL_DIR: &str = "/.openshell/peer-control";

/// Peer-side mount of its one-use boot directory.
pub const PEER_BOOT_DIR: &str = "/.openshell/peer-boot";

/// Socket file the primary listens on inside each peer control directory.
pub const PEER_SOCKET_FILE: &str = "peer.sock";

/// Token file the init container stages inside each peer boot directory.
pub const PEER_TOKEN_FILE: &str = "token";

/// Byte length of a peer token before hex encoding.
pub const PEER_TOKEN_BYTES: usize = 32;

/// Bound on how long the primary waits for every peer to connect and qualify
/// before it refuses to serve the boundary.
pub const PEER_CONNECT_TIMEOUT_SECS: u64 = 300;

/// Primary-side mount of the control directory shared with peer `index`.
#[must_use]
pub fn peer_control_dir_in_primary(index: usize) -> String {
    format!("/.openshell/peers/{index}")
}

/// Init-container mount of the boot directory of peer `index`.
#[must_use]
pub fn peer_boot_dir_in_init(index: usize) -> String {
    format!("/.openshell/peer-boot/{index}")
}

/// Name of the Memory `emptyDir` shared by the agent and peer `index`.
#[must_use]
pub fn peer_control_volume_name(index: usize) -> String {
    format!("openshell-peer-{index}-control")
}

/// Name of the Memory `emptyDir` shared by the init container and peer `index`.
#[must_use]
pub fn peer_boot_volume_name(index: usize) -> String {
    format!("openshell-peer-{index}-boot")
}

/// Key of peer `index`'s one-use token in the generation bootstrap Secret.
#[must_use]
pub fn peer_token_secret_key(index: usize) -> String {
    format!("peer-{index}.token")
}

/// Sandbox-local DNS relay address served by peer `index`'s runtime.
///
/// The primary runtime owns `127.0.0.53:53`. Every runtime in the shared
/// network namespace needs its own relay address, so peers use
/// `127.0.<index + 1>.53:53` and redirect their workloads' queries to the
/// well-known resolver address onto it.
#[must_use]
pub fn peer_dns_relay_address(index: usize) -> SocketAddr {
    let octet = u8::try_from(index + 1).expect("peer index is bounded by MAX_PEER_WORKLOADS");
    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, octet, 53), 53))
}

/// One peer workload container, as recorded in the protected boundary config.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerWorkloadConfig {
    /// Position in `BoundaryConfig::peers`; selects the fixed volume and path
    /// layout above. Must equal the entry's position.
    pub index: usize,
    /// Kubernetes container name, used in diagnostics and audit events.
    pub name: String,
    /// Exact argv the peer runtime launches once the boundary starts its agent.
    pub command: Vec<String>,
    /// Non-secret environment for the peer workload, applied on top of the
    /// boundary's child environment.
    #[serde(default)]
    pub environment: BTreeMap<String, String>,
    /// Lowercase hex SHA-256 of the peer's one-use bootstrap token.
    pub token_sha256: String,
}

impl fmt::Debug for PeerWorkloadConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PeerWorkloadConfig")
            .field("index", &self.index)
            .field("name", &self.name)
            .field("command", &self.command)
            .field(
                "environment_keys",
                &self.environment.keys().collect::<Vec<_>>(),
            )
            .finish_non_exhaustive()
    }
}

/// Validate a peer container name.
///
/// # Errors
///
/// Returns a description of the first violated rule.
pub fn validate_peer_name(name: &str) -> Result<(), String> {
    if name.is_empty() || name.len() > MAX_PEER_NAME_LEN {
        return Err(format!(
            "peer workload name must be 1-{MAX_PEER_NAME_LEN} characters, got {name:?}"
        ));
    }
    let valid_label = name
        .bytes()
        .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        && name
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        && name
            .as_bytes()
            .last()
            .is_some_and(u8::is_ascii_alphanumeric);
    if !valid_label {
        return Err(format!(
            "peer workload name {name:?} must be a DNS-1123 label"
        ));
    }
    if RESERVED_PEER_NAMES.contains(&name) || name.starts_with(RESERVED_PEER_NAME_PREFIX) {
        return Err(format!("peer workload name {name:?} is reserved"));
    }
    Ok(())
}

/// Validate the peer list of a boundary config.
///
/// # Errors
///
/// Returns a description of the first violated rule.
pub fn validate_peer_workloads(peers: &[PeerWorkloadConfig]) -> Result<(), String> {
    if peers.len() > MAX_PEER_WORKLOADS {
        return Err(format!(
            "at most {MAX_PEER_WORKLOADS} peer workloads are supported, got {}",
            peers.len()
        ));
    }
    let mut names = std::collections::BTreeSet::new();
    for (position, peer) in peers.iter().enumerate() {
        if peer.index != position {
            return Err(format!(
                "peer workload {:?} has index {} at position {position}",
                peer.name, peer.index
            ));
        }
        validate_peer_name(&peer.name)?;
        if !names.insert(peer.name.as_str()) {
            return Err(format!("duplicate peer workload name {:?}", peer.name));
        }
        if peer.command.is_empty() || peer.command.iter().any(String::is_empty) {
            return Err(format!(
                "peer workload {:?} requires a non-empty command without empty arguments",
                peer.name
            ));
        }
        if let Some(key) = peer
            .environment
            .keys()
            .find(|key| key.is_empty() || key.contains('=') || key.starts_with("OPENSHELL_"))
        {
            return Err(format!(
                "peer workload {:?} environment key {key:?} is empty, contains '=', or uses the reserved OPENSHELL_ prefix",
                peer.name
            ));
        }
        let digest_ok = peer.token_sha256.len() == 64
            && peer
                .token_sha256
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
        if !digest_ok {
            return Err(format!(
                "peer workload {:?} token digest must be 64 lowercase hex characters",
                peer.name
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(index: usize, name: &str) -> PeerWorkloadConfig {
        PeerWorkloadConfig {
            index,
            name: name.to_string(),
            command: vec!["/bin/reviewer".to_string()],
            environment: BTreeMap::from([(
                "MESH_PEER".to_string(),
                "tcp://127.0.0.1:7480".to_string(),
            )]),
            token_sha256: "a".repeat(64),
        }
    }

    #[test]
    fn accepts_ordered_unique_peers() {
        validate_peer_workloads(&[peer(0, "reviewer"), peer(1, "coder-2")]).unwrap();
    }

    #[test]
    fn rejects_reserved_duplicate_and_misindexed_peers() {
        for (peers, needle) in [
            (vec![peer(0, "agent")], "reserved"),
            (vec![peer(0, "openshell-helper")], "reserved"),
            (vec![peer(0, "reviewer"), peer(1, "reviewer")], "duplicate"),
            (vec![peer(1, "reviewer")], "index"),
            (vec![peer(0, "Reviewer")], "DNS-1123"),
            (
                vec![peer(0, &"a".repeat(MAX_PEER_NAME_LEN + 1))],
                "characters",
            ),
        ] {
            let error = validate_peer_workloads(&peers).unwrap_err();
            assert!(error.contains(needle), "{error} should mention {needle}");
        }
    }

    #[test]
    fn rejects_bad_command_environment_and_digest() {
        let mut empty_command = peer(0, "reviewer");
        empty_command.command.clear();
        let mut reserved_env = peer(0, "reviewer");
        reserved_env
            .environment
            .insert("OPENSHELL_ENDPOINT".to_string(), "x".to_string());
        let mut bad_digest = peer(0, "reviewer");
        bad_digest.token_sha256 = "A".repeat(64);
        for config in [empty_command, reserved_env, bad_digest] {
            validate_peer_workloads(&[config]).unwrap_err();
        }
        let too_many = (0..=MAX_PEER_WORKLOADS)
            .map(|index| peer(index, &format!("peer-{index}")))
            .collect::<Vec<_>>();
        assert!(
            validate_peer_workloads(&too_many)
                .unwrap_err()
                .contains("at most")
        );
    }

    #[test]
    fn layout_is_index_derived_and_relays_do_not_collide() {
        assert_eq!(peer_control_volume_name(3), "openshell-peer-3-control");
        assert_eq!(peer_boot_volume_name(3), "openshell-peer-3-boot");
        assert_eq!(peer_token_secret_key(3), "peer-3.token");
        assert_eq!(peer_control_dir_in_primary(3), "/.openshell/peers/3");
        assert_eq!(peer_boot_dir_in_init(3), "/.openshell/peer-boot/3");
        let relays = (0..MAX_PEER_WORKLOADS)
            .map(peer_dns_relay_address)
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(relays.len(), MAX_PEER_WORKLOADS);
        assert!(!relays.contains(&"127.0.0.53:53".parse().unwrap()));
    }
}
