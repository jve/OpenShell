// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Private control protocol between the primary runtime and its peer runtimes.
//!
//! Each peer workload container runs a subordinate `openshell-sandbox peer`
//! runtime that talks only to the primary runtime in the `agent` container,
//! over one Unix stream socket in a Memory `emptyDir` the two containers share
//! (see [`openshell_sandbox_backend::peer_workloads`]). Nothing here is visible
//! to the supervisor: the primary folds peer state into the single boundary it
//! serves.
//!
//! Frames are a 4-byte big-endian length followed by one JSON message. A
//! message that carries a descriptor (a relayed TCP stream) sends that
//! descriptor with `SCM_RIGHTS` attached to the first byte of its frame.
//! Descriptors therefore arrive no later than their frame and in frame order,
//! so the receiver pairs each descriptor-carrying frame with the oldest
//! received, unclaimed descriptor.
//!
//! Exchange, in order:
//!
//! 1. peer → [`PeerToPrimary::Hello`]: one-use token and the peer's own
//!    runtime qualification. The primary checks `SO_PEERCRED`, the token
//!    digest, and replies [`PrimaryToPeer::Welcome`].
//! 2. peer → [`PeerToPrimary::Ready`] once its network broker runs.
//! 3. primary → [`PrimaryToPeer::Start`] when the boundary starts its agent;
//!    peer → [`PeerToPrimary::Started`] or [`PeerToPrimary::StartFailed`].
//! 4. Mediation: [`PeerToPrimary::TcpOpen`] / [`PrimaryToPeer::TcpDecision`] /
//!    [`PeerToPrimary::TcpRelay`] for external TCP opens, and
//!    [`PeerToPrimary::DnsAdmit`] / [`PrimaryToPeer::DnsAdmitResult`] to
//!    register a workload DNS socket with the primary's resolver relay.
//!    Provider rotation: [`PrimaryToPeer::UpdateProviderEnvironment`] /
//!    [`PeerToPrimary::ProviderEnvironmentUpdated`].
//! 5. Lifecycle: [`PrimaryToPeer::Freeze`], [`PrimaryToPeer::Thaw`],
//!    [`PrimaryToPeer::Terminate`]; peer → [`PeerToPrimary::WorkloadExited`]
//!    when its workload tree is gone and [`PeerToPrimary::Failed`] before it
//!    gives up. Either side closing the socket ends the whole group.

use std::collections::{BTreeSet, HashMap, VecDeque};
use std::fmt;
use std::io::{self, IoSlice, IoSliceMut, Write as _};
use std::net::SocketAddr;
use std::os::fd::{AsRawFd as _, BorrowedFd, FromRawFd as _, OwnedFd, RawFd};
use std::os::unix::net::UnixStream;
use std::sync::Mutex;

use nix::sys::socket::{ControlMessage, ControlMessageOwned, MsgFlags, recvmsg, sendmsg};
use openshell_isolation_interface::contract::{
    DnsTransport, NetworkSocketMetadata, TcpOpenDecision,
};
use openshell_sandbox_backend::boundary_protocol::{
    BinaryIdentityWire, ExitStatusWire, MAX_CONTROL_FRAME_BYTES, SandboxPolicyWire, SeccompEvidence,
};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

/// Largest accepted frame. `Start` carries one complete `start_agent`
/// request (itself bounded by the control frame limit) re-encoded as JSON.
pub const MAX_PEER_FRAME_BYTES: usize = 4 * MAX_CONTROL_FRAME_BYTES;

/// Received descriptors waiting for their frame. Each relayed stream frame
/// claims one; a sender that attaches more than this without frames is
/// violating the protocol.
const MAX_PENDING_DESCRIPTORS: usize = 16;

/// Descriptors accepted by one `recvmsg`.
const DESCRIPTORS_PER_READ: usize = 4;

const READ_CHUNK_BYTES: usize = 64 * 1024;

/// Runtime qualification measured by a peer runtime in its own container.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "qualification preserves independently exercised security results"
)]
pub struct PeerQualification {
    pub(crate) seccomp: SeccompEvidence,
    pub(crate) landlock_abi: u32,
    pub(crate) landlock_allow_deny: bool,
    pub(crate) udp_dns_round_trip: bool,
    pub(crate) tcp_dns_round_trip: bool,
    pub(crate) tcp_allow_round_trip: bool,
    pub(crate) tcp_deny_round_trip: bool,
    pub(crate) socket_loopback_confinement: bool,
}

impl From<crate::RuntimeQualification> for PeerQualification {
    fn from(qualification: crate::RuntimeQualification) -> Self {
        Self {
            seccomp: qualification.seccomp,
            landlock_abi: qualification.landlock_abi,
            landlock_allow_deny: qualification.landlock_allow_deny,
            udp_dns_round_trip: qualification.udp_dns_round_trip,
            tcp_dns_round_trip: qualification.tcp_dns_round_trip,
            tcp_allow_round_trip: qualification.tcp_allow_round_trip,
            tcp_deny_round_trip: qualification.tcp_deny_round_trip,
            socket_loopback_confinement: qualification.socket_loopback_confinement,
        }
    }
}

impl From<PeerQualification> for crate::RuntimeQualification {
    fn from(qualification: PeerQualification) -> Self {
        Self {
            seccomp: qualification.seccomp,
            landlock_abi: qualification.landlock_abi,
            landlock_allow_deny: qualification.landlock_allow_deny,
            udp_dns_round_trip: qualification.udp_dns_round_trip,
            tcp_dns_round_trip: qualification.tcp_dns_round_trip,
            tcp_allow_round_trip: qualification.tcp_allow_round_trip,
            tcp_deny_round_trip: qualification.tcp_deny_round_trip,
            socket_loopback_confinement: qualification.socket_loopback_confinement,
        }
    }
}

/// Fold every runtime's qualification into the one the boundary reports:
/// each mechanism is proven only if every runtime proved it, and the
/// Landlock ABI is the lowest any runtime enforces.
pub fn aggregate_qualification(
    primary: crate::RuntimeQualification,
    peers: impl IntoIterator<Item = PeerQualification>,
) -> crate::RuntimeQualification {
    peers.into_iter().fold(primary, |aggregate, peer| {
        let seccomp = SeccompEvidence {
            new_listener: aggregate.seccomp.new_listener && peer.seccomp.new_listener,
            notification_round_trip: aggregate.seccomp.notification_round_trip
                && peer.seccomp.notification_round_trip,
            id_validation: aggregate.seccomp.id_validation && peer.seccomp.id_validation,
            addfd_send: aggregate.seccomp.addfd_send && peer.seccomp.addfd_send,
            retained_socket_operation: aggregate.seccomp.retained_socket_operation
                && peer.seccomp.retained_socket_operation,
            proc_fd_identity: aggregate.seccomp.proc_fd_identity && peer.seccomp.proc_fd_identity,
            task_memory_read: aggregate.seccomp.task_memory_read && peer.seccomp.task_memory_read,
        };
        crate::RuntimeQualification {
            seccomp,
            landlock_abi: aggregate.landlock_abi.min(peer.landlock_abi),
            landlock_allow_deny: aggregate.landlock_allow_deny && peer.landlock_allow_deny,
            udp_dns_round_trip: aggregate.udp_dns_round_trip && peer.udp_dns_round_trip,
            tcp_dns_round_trip: aggregate.tcp_dns_round_trip && peer.tcp_dns_round_trip,
            tcp_allow_round_trip: aggregate.tcp_allow_round_trip && peer.tcp_allow_round_trip,
            tcp_deny_round_trip: aggregate.tcp_deny_round_trip && peer.tcp_deny_round_trip,
            socket_loopback_confinement: aggregate.socket_loopback_confinement
                && peer.socket_loopback_confinement,
        }
    })
}

/// Everything a peer runtime needs to launch its workload when the boundary
/// starts its agent. Shared inputs are exactly those applied to the agent.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerStart {
    /// Exact argv of the peer workload.
    pub(crate) command: Vec<String>,
    /// Boundary child environment with the peer's own environment applied on
    /// top.
    pub(crate) environment: HashMap<String, String>,
    /// Policy attached to the boundary.
    pub(crate) policy: SandboxPolicyWire,
    /// Whether the boundary admitted a GPU resource claim.
    pub(crate) gpu_requested: bool,
    /// Resolved workload UID and GID applied to every workload process.
    pub(crate) workload_uid: u32,
    pub(crate) workload_gid: u32,
    pub(crate) ca_cert: Option<String>,
    pub(crate) ca_bundle: Option<String>,
    pub(crate) provider_env_revision: u64,
    pub(crate) provider_env: HashMap<String, String>,
    pub(crate) provider_files: HashMap<String, String>,
}

impl fmt::Debug for PeerStart {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PeerStart")
            .field("command", &self.command)
            .field(
                "environment_keys",
                &self.environment.keys().collect::<BTreeSet<_>>(),
            )
            .field("gpu_requested", &self.gpu_requested)
            .field("workload_uid", &self.workload_uid)
            .field("workload_gid", &self.workload_gid)
            .field("provider_env_revision", &self.provider_env_revision)
            .field("provider_file_count", &self.provider_files.len())
            .finish_non_exhaustive()
    }
}

/// Messages a peer runtime sends to the primary.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum PeerToPrimary {
    /// First frame: the one-use bootstrap token and the peer's qualification.
    Hello {
        token: String,
        qualification: PeerQualification,
    },
    /// The peer's network broker is running.
    Ready,
    /// The peer workload is running.
    Started,
    /// The peer workload could not be launched.
    StartFailed { message: String },
    /// An external TCP open blocked in the peer workload's `connect(2)`.
    TcpOpen {
        id: u64,
        destination: SocketAddr,
        identity: BinaryIdentityWire,
        socket: NetworkSocketMetadata,
        notification_to_queue_us: u64,
        queue_wait_us: u64,
    },
    /// The relayed stream for an allowed open; carries one descriptor.
    TcpRelay { id: u64 },
    /// An allowed open whose relay could not be established.
    TcpRelayFailed { id: u64, message: String },
    /// Register a workload DNS socket's loopback source with the primary's
    /// resolver relay before the socket reaches it.
    DnsAdmit {
        id: u64,
        transport: DnsTransport,
        source: SocketAddr,
    },
    /// Drop admissions whose workload sockets have closed.
    DnsRevoke {
        transport: DnsTransport,
        sources: Vec<SocketAddr>,
    },
    /// Outcome of one provider environment update; `error` is set when the
    /// peer did not apply it.
    ProviderEnvironmentUpdated { id: u64, error: Option<String> },
    /// The peer workload tree has exited.
    WorkloadExited { status: ExitStatusWire },
    /// The peer runtime cannot keep its workload under the boundary and is
    /// exiting.
    Failed { message: String },
}

impl PeerToPrimary {
    fn kind(&self) -> &'static str {
        match self {
            Self::Hello { .. } => "hello",
            Self::Ready => "ready",
            Self::Started => "started",
            Self::StartFailed { .. } => "start_failed",
            Self::TcpOpen { .. } => "tcp_open",
            Self::TcpRelay { .. } => "tcp_relay",
            Self::TcpRelayFailed { .. } => "tcp_relay_failed",
            Self::DnsAdmit { .. } => "dns_admit",
            Self::DnsRevoke { .. } => "dns_revoke",
            Self::ProviderEnvironmentUpdated { .. } => "provider_environment_updated",
            Self::WorkloadExited { .. } => "workload_exited",
            Self::Failed { .. } => "failed",
        }
    }
}

/// Messages the primary sends to a peer runtime.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum PrimaryToPeer {
    /// The peer is authenticated. Workloads must never reach the supervisor
    /// control port, so the peer's broker refuses it like the primary's.
    Welcome { protected_control_port: Option<u16> },
    /// Launch the peer workload.
    Start(Box<PeerStart>),
    /// Supervisor decision for one forwarded TCP open.
    TcpDecision { id: u64, decision: TcpOpenDecision },
    /// Outcome of one DNS admission; `errno` is set when it was refused.
    DnsAdmitResult { id: u64, errno: Option<i32> },
    /// Install a rotated provider snapshot, exactly as the agent's.
    UpdateProviderEnvironment {
        id: u64,
        revision: u64,
        provider_env: HashMap<String, String>,
        provider_files: HashMap<String, String>,
    },
    /// Stop the peer workload while supervisor control recovers.
    Freeze,
    /// Resume the peer workload after authenticated recovery.
    Thaw,
    /// Terminate the peer workload tree. `enforcement_lost` selects the
    /// fail-closed path used after supervisor recovery expires.
    Terminate { enforcement_lost: bool },
}

impl PrimaryToPeer {
    fn kind(&self) -> &'static str {
        match self {
            Self::Welcome { .. } => "welcome",
            Self::Start(_) => "start",
            Self::TcpDecision { .. } => "tcp_decision",
            Self::DnsAdmitResult { .. } => "dns_admit_result",
            Self::UpdateProviderEnvironment { .. } => "update_provider_environment",
            Self::Freeze => "freeze",
            Self::Thaw => "thaw",
            Self::Terminate { .. } => "terminate",
        }
    }
}

// Messages carry tokens and provider material; diagnostics name the kind only.
impl fmt::Debug for PeerToPrimary {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.kind())
    }
}

impl fmt::Debug for PrimaryToPeer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.kind())
    }
}

/// A message type of the peer protocol.
pub trait PeerMessage: Serialize + DeserializeOwned {
    /// Whether this frame is paired with one `SCM_RIGHTS` descriptor.
    fn carries_descriptor(&self) -> bool;
}

impl PeerMessage for PeerToPrimary {
    fn carries_descriptor(&self) -> bool {
        matches!(self, Self::TcpRelay { .. })
    }
}

impl PeerMessage for PrimaryToPeer {
    fn carries_descriptor(&self) -> bool {
        false
    }
}

/// One received frame and the descriptor it carried, if any.
pub struct Received<T> {
    pub(crate) message: T,
    pub(crate) descriptor: Option<OwnedFd>,
}

fn protocol_error(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

fn encode<T: PeerMessage>(message: &T) -> io::Result<Vec<u8>> {
    let payload = serde_json::to_vec(message)
        .map_err(|error| protocol_error(format!("encode peer frame: {error}")))?;
    if payload.len() > MAX_PEER_FRAME_BYTES {
        return Err(protocol_error(format!(
            "peer frame of {} bytes exceeds {MAX_PEER_FRAME_BYTES}",
            payload.len()
        )));
    }
    let length = u32::try_from(payload.len()).expect("frame limit fits u32");
    let mut frame = Vec::with_capacity(4 + payload.len());
    frame.extend_from_slice(&length.to_be_bytes());
    frame.extend_from_slice(&payload);
    Ok(frame)
}

/// Serialized writer half. Every frame is written atomically with respect to
/// other senders on the same channel.
pub struct PeerSender {
    stream: Mutex<UnixStream>,
}

impl PeerSender {
    pub(crate) fn new(stream: UnixStream) -> Self {
        Self {
            stream: Mutex::new(stream),
        }
    }

    pub(crate) fn send<T: PeerMessage>(&self, message: &T) -> io::Result<()> {
        if message.carries_descriptor() {
            return Err(protocol_error(format!(
                "{} frame requires a descriptor",
                std::any::type_name::<T>()
            )));
        }
        let frame = encode(message)?;
        let mut stream = self
            .stream
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        stream.write_all(&frame)?;
        stream.flush()
    }

    pub(crate) fn send_with_descriptor<T: PeerMessage>(
        &self,
        message: &T,
        descriptor: BorrowedFd<'_>,
    ) -> io::Result<()> {
        if !message.carries_descriptor() {
            return Err(protocol_error("frame does not carry a descriptor"));
        }
        let frame = encode(message)?;
        let stream = self
            .stream
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let descriptors = [descriptor.as_raw_fd()];
        let control = [ControlMessage::ScmRights(&descriptors)];
        let sent = loop {
            match sendmsg::<()>(
                stream.as_raw_fd(),
                &[IoSlice::new(&frame)],
                &control,
                MsgFlags::MSG_NOSIGNAL,
                None,
            ) {
                Ok(sent) => break sent,
                Err(nix::errno::Errno::EINTR) => {}
                Err(error) => return Err(io::Error::from(error)),
            }
        };
        if sent == 0 {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "peer channel accepted no bytes",
            ));
        }
        // The descriptor travels with the first byte; the remainder of a
        // partially sent frame is ordinary stream data.
        let mut rest = &frame[sent..];
        let mut stream = &*stream;
        while !rest.is_empty() {
            match stream.write(rest) {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "peer channel closed during a frame",
                    ));
                }
                Ok(written) => rest = &rest[written..],
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }

    /// Stop both directions; a blocked receiver observes end of stream.
    pub(crate) fn shutdown(&self) {
        let stream = self
            .stream
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let _ = stream.shutdown(std::net::Shutdown::Both);
    }
}

/// Reader half that reassembles frames and pairs descriptors with them.
pub struct PeerReceiver {
    stream: UnixStream,
    buffer: Vec<u8>,
    descriptors: VecDeque<OwnedFd>,
}

impl PeerReceiver {
    pub(crate) fn new(stream: UnixStream) -> Self {
        Self {
            stream,
            buffer: Vec::new(),
            descriptors: VecDeque::new(),
        }
    }

    pub(crate) fn set_read_timeout(&self, timeout: Option<std::time::Duration>) -> io::Result<()> {
        self.stream.set_read_timeout(timeout)
    }

    /// Receive the next frame. `Ok(None)` is a clean end of stream between
    /// frames.
    pub(crate) fn recv<T: PeerMessage>(&mut self) -> io::Result<Option<Received<T>>> {
        loop {
            if let Some(payload) = self.take_frame()? {
                let message: T = serde_json::from_slice(&payload)
                    .map_err(|error| protocol_error(format!("decode peer frame: {error}")))?;
                let descriptor = if message.carries_descriptor() {
                    Some(self.descriptors.pop_front().ok_or_else(|| {
                        protocol_error(
                            "descriptor-carrying peer frame arrived without a descriptor",
                        )
                    })?)
                } else {
                    None
                };
                return Ok(Some(Received {
                    message,
                    descriptor,
                }));
            }
            if self.fill()? == 0 {
                if self.buffer.is_empty() {
                    return Ok(None);
                }
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "peer channel closed inside a frame",
                ));
            }
        }
    }

    fn take_frame(&mut self) -> io::Result<Option<Vec<u8>>> {
        let Some(header) = self.buffer.get(..4) else {
            return Ok(None);
        };
        let length = usize::try_from(u32::from_be_bytes(
            header.try_into().expect("header slice has four bytes"),
        ))
        .expect("u32 fits usize");
        if length > MAX_PEER_FRAME_BYTES {
            return Err(protocol_error(format!(
                "peer frame of {length} bytes exceeds {MAX_PEER_FRAME_BYTES}"
            )));
        }
        if self.buffer.len() < 4 + length {
            return Ok(None);
        }
        let payload = self.buffer[4..4 + length].to_vec();
        self.buffer.drain(..4 + length);
        Ok(Some(payload))
    }

    #[allow(unsafe_code)]
    fn fill(&mut self) -> io::Result<usize> {
        let mut chunk = vec![0_u8; READ_CHUNK_BYTES];
        let mut control = nix::cmsg_space!([RawFd; DESCRIPTORS_PER_READ]);
        let (length, received, truncated) = loop {
            let mut iov = [IoSliceMut::new(&mut chunk)];
            match recvmsg::<()>(
                self.stream.as_raw_fd(),
                &mut iov,
                Some(&mut control),
                MsgFlags::MSG_CMSG_CLOEXEC,
            ) {
                Ok(message) => {
                    let mut received = Vec::new();
                    for control_message in message.cmsgs().map_err(io::Error::from)? {
                        if let ControlMessageOwned::ScmRights(descriptors) = control_message {
                            received.extend(descriptors.into_iter().map(|descriptor| {
                                // SAFETY: SCM_RIGHTS installed each descriptor
                                // in this process; this is its only owner.
                                unsafe { OwnedFd::from_raw_fd(descriptor) }
                            }));
                        }
                    }
                    break (
                        message.bytes,
                        received,
                        message.flags.contains(MsgFlags::MSG_CTRUNC),
                    );
                }
                Err(nix::errno::Errno::EINTR) => {}
                Err(nix::errno::Errno::EAGAIN) => {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "timed out waiting for a peer frame",
                    ));
                }
                Err(error) => return Err(io::Error::from(error)),
            }
        };
        if truncated {
            return Err(protocol_error("peer channel descriptor list was truncated"));
        }
        self.descriptors.extend(received);
        if self.descriptors.len() > MAX_PENDING_DESCRIPTORS {
            return Err(protocol_error(
                "peer sent descriptors without descriptor-carrying frames",
            ));
        }
        if self.buffer.len() + length > 4 + MAX_PEER_FRAME_BYTES + READ_CHUNK_BYTES {
            return Err(protocol_error("peer frame buffer exceeds its bound"));
        }
        self.buffer.extend_from_slice(&chunk[..length]);
        Ok(length)
    }
}

/// Split one connected peer channel into its sender and receiver halves.
pub fn split(stream: UnixStream) -> io::Result<(PeerSender, PeerReceiver)> {
    let reader = stream.try_clone()?;
    Ok((PeerSender::new(stream), PeerReceiver::new(reader)))
}

/// Lowercase hex SHA-256 of a peer token, as recorded in the boundary config.
pub fn token_digest(token: &str) -> io::Result<String> {
    let digest = openshell_crypto::sha256(token.as_bytes())
        .map_err(|error| io::Error::other(format!("hash peer token: {error}")))?;
    Ok(hex::encode(digest))
}

/// Compare a presented token with its recorded digest without revealing,
/// through timing, how much of the digest matched.
pub fn token_matches(token: &str, expected_sha256: &str) -> io::Result<bool> {
    let presented = token_digest(token)?;
    let (presented, expected) = (presented.as_bytes(), expected_sha256.as_bytes());
    let mut difference = presented.len() ^ expected.len();
    for index in 0..presented.len().max(expected.len()) {
        let left = presented.get(index).copied().unwrap_or_default();
        let right = expected.get(index).copied().unwrap_or_default();
        difference |= usize::from(left ^ right);
    }
    Ok(difference == 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read as _;
    use std::os::fd::AsFd as _;

    fn qualification(landlock_abi: u32) -> PeerQualification {
        PeerQualification {
            seccomp: SeccompEvidence {
                new_listener: true,
                notification_round_trip: true,
                id_validation: true,
                addfd_send: true,
                retained_socket_operation: true,
                proc_fd_identity: true,
                task_memory_read: true,
            },
            landlock_abi,
            landlock_allow_deny: true,
            udp_dns_round_trip: true,
            tcp_dns_round_trip: true,
            tcp_allow_round_trip: true,
            tcp_deny_round_trip: true,
            socket_loopback_confinement: true,
        }
    }

    #[test]
    fn frames_round_trip_in_order() {
        let (left, right) = UnixStream::pair().unwrap();
        let (sender, _) = split(left).unwrap();
        let (_, mut receiver) = split(right).unwrap();
        let messages = vec![
            PeerToPrimary::Hello {
                token: "a".repeat(64),
                qualification: qualification(5),
            },
            PeerToPrimary::Ready,
            PeerToPrimary::DnsAdmit {
                id: 7,
                transport: DnsTransport::Udp,
                source: "127.0.0.1:40000".parse().unwrap(),
            },
            PeerToPrimary::WorkloadExited {
                status: ExitStatusWire::Exited(3),
            },
        ];
        for message in &messages {
            sender.send(message).unwrap();
        }
        drop(sender);
        for expected in &messages {
            let frame = receiver.recv::<PeerToPrimary>().unwrap().unwrap();
            assert!(frame.message == *expected, "{:?}", frame.message);
            assert!(frame.descriptor.is_none());
        }
        assert!(receiver.recv::<PeerToPrimary>().unwrap().is_none());
    }

    #[test]
    fn relayed_descriptors_pair_with_their_frames() {
        let (left, right) = UnixStream::pair().unwrap();
        let (sender, _) = split(left).unwrap();
        let (_, mut receiver) = split(right).unwrap();
        let (first_local, mut first_remote) = UnixStream::pair().unwrap();
        let (second_local, mut second_remote) = UnixStream::pair().unwrap();

        sender
            .send_with_descriptor(&PeerToPrimary::TcpRelay { id: 1 }, first_local.as_fd())
            .unwrap();
        sender.send(&PeerToPrimary::Ready).unwrap();
        sender
            .send_with_descriptor(&PeerToPrimary::TcpRelay { id: 2 }, second_local.as_fd())
            .unwrap();
        drop((first_local, second_local));

        for (id, remote) in [(1, &mut first_remote), (2, &mut second_remote)] {
            let frame = receiver.recv::<PeerToPrimary>().unwrap().unwrap();
            assert!(frame.message == PeerToPrimary::TcpRelay { id });
            let mut stream = UnixStream::from(frame.descriptor.unwrap());
            stream.write_all(&[u8::try_from(id).unwrap()]).unwrap();
            drop(stream);
            let mut byte = [0_u8; 1];
            remote.read_exact(&mut byte).unwrap();
            assert_eq!(u64::from(byte[0]), id);
            if id == 1 {
                let ready = receiver.recv::<PeerToPrimary>().unwrap().unwrap();
                assert!(ready.message == PeerToPrimary::Ready);
                assert!(ready.descriptor.is_none());
            }
        }
    }

    #[test]
    fn descriptor_rules_are_enforced_on_both_sides() {
        let (left, right) = UnixStream::pair().unwrap();
        let (sender, _) = split(left).unwrap();
        let (_, mut receiver) = split(right).unwrap();
        assert!(sender.send(&PeerToPrimary::TcpRelay { id: 1 }).is_err());
        let (spare, _) = UnixStream::pair().unwrap();
        assert!(
            sender
                .send_with_descriptor(&PeerToPrimary::Ready, spare.as_fd())
                .is_err()
        );
        // A descriptor-carrying frame forged without SCM_RIGHTS is refused.
        let frame = encode(&PeerToPrimary::TcpRelay { id: 9 }).unwrap();
        sender.stream.lock().unwrap().write_all(&frame).unwrap();
        let error = receiver.recv::<PeerToPrimary>().err().unwrap();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn oversized_and_truncated_frames_are_rejected() {
        let (mut left, right) = UnixStream::pair().unwrap();
        let mut receiver = PeerReceiver::new(right);
        let declared = u32::try_from(MAX_PEER_FRAME_BYTES + 1).unwrap();
        left.write_all(&declared.to_be_bytes()).unwrap();
        assert_eq!(
            receiver.recv::<PeerToPrimary>().err().unwrap().kind(),
            io::ErrorKind::InvalidData
        );

        let (mut left, right) = UnixStream::pair().unwrap();
        let mut receiver = PeerReceiver::new(right);
        let frame = encode(&PeerToPrimary::Ready).unwrap();
        left.write_all(&frame[..frame.len() - 1]).unwrap();
        drop(left);
        assert_eq!(
            receiver.recv::<PeerToPrimary>().err().unwrap().kind(),
            io::ErrorKind::UnexpectedEof
        );
    }

    #[test]
    fn unknown_fields_and_messages_are_rejected() {
        for payload in [
            br#"{"type":"start_failed","message":"x","extra":1}"#.as_slice(),
            br#"{"type":"become_primary"}"#.as_slice(),
        ] {
            let (mut left, right) = UnixStream::pair().unwrap();
            let mut receiver = PeerReceiver::new(right);
            left.write_all(&u32::try_from(payload.len()).unwrap().to_be_bytes())
                .unwrap();
            left.write_all(payload).unwrap();
            assert_eq!(
                receiver.recv::<PeerToPrimary>().err().unwrap().kind(),
                io::ErrorKind::InvalidData
            );
        }
    }

    #[test]
    fn receive_timeout_is_reported() {
        let (_left, right) = UnixStream::pair().unwrap();
        let mut receiver = PeerReceiver::new(right);
        receiver
            .set_read_timeout(Some(std::time::Duration::from_millis(20)))
            .unwrap();
        assert_eq!(
            receiver.recv::<PrimaryToPeer>().err().unwrap().kind(),
            io::ErrorKind::TimedOut
        );
    }

    #[test]
    fn token_digest_matches_the_driver_encoding() {
        let token = "0f".repeat(32);
        let digest = token_digest(&token).unwrap();
        assert_eq!(digest.len(), 64);
        assert!(token_matches(&token, &digest).unwrap());
        assert!(!token_matches(&"0e".repeat(32), &digest).unwrap());
        assert!(!token_matches(&token, &digest[..63]).unwrap());
        assert!(!token_matches(&token, "").unwrap());
    }

    #[test]
    fn qualification_is_the_conjunction_with_the_lowest_landlock_abi() {
        let primary = crate::RuntimeQualification::from(qualification(6));
        let mut weaker = qualification(4);
        weaker.seccomp.addfd_send = false;
        let aggregate = aggregate_qualification(primary, [qualification(5), weaker]);
        assert_eq!(aggregate.landlock_abi, 4);
        assert!(!aggregate.seccomp.addfd_send);
        assert!(aggregate.seccomp.notification_round_trip);
        assert!(aggregate.tcp_allow_round_trip);

        let unchanged = aggregate_qualification(primary, []);
        assert_eq!(PeerQualification::from(unchanged), qualification(6));
    }
}
