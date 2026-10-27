// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! The primary runtime's side of peer workload containers.
//!
//! Before the primary serves its boundary it listens on each peer's private
//! socket, accepts exactly one connection per peer, removes the socket, and
//! authenticates the caller by `SO_PEERCRED` and its one-use token. Every peer
//! must join and report its qualification within
//! [`PEER_CONNECT_TIMEOUT_SECS`]; otherwise the boundary is never served.
//!
//! Afterwards the hub only adapts: forwarded TCP opens and DNS admissions
//! enter the primary's own network broker, so mediation, the supervisor and
//! the Sandbox Protocol see one boundary. Each forwarded identity is stamped
//! with the peer's name as its execution environment, decided by which socket
//! it arrived on, never by what the peer claims.
//!
//! The peers share the agent's lifecycle. They start, freeze, thaw and
//! terminate with it, and a peer that fails or whose workload exits ends the
//! whole group through the handler the boundary registers.

use std::collections::HashMap;
use std::io;
use std::net::TcpStream;
use std::os::fd::OwnedFd;
use std::os::unix::fs::PermissionsExt as _;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use openshell_isolation_interface::contract::{
    ResolvedWorkloadIdentity, TcpOpenDecision, TcpOpenDenial,
};
use openshell_sandbox_backend::boundary_protocol::ExitStatusWire;
use openshell_sandbox_backend::peer_workloads::{
    PEER_CONNECT_TIMEOUT_SECS, PEER_SOCKET_FILE, PeerWorkloadConfig, peer_control_dir_in_primary,
};
use tokio::sync::oneshot;

use crate::network_broker::{NETWORK_DECISION_TIMEOUT, NetworkBroker};
use crate::peer_protocol::{
    self, PeerQualification, PeerReceiver, PeerSender, PeerStart, PeerToPrimary, PrimaryToPeer,
};

/// Bound on all peers acknowledging `Start`.
pub const PEER_START_TIMEOUT: Duration = Duration::from_mins(1);

/// Bound on every peer reporting its terminated workload: its own graceful
/// and forced termination windows plus scheduling slack.
pub const PEER_TERMINATION_TIMEOUT: Duration = Duration::from_secs(
    crate::boundary_server::ENFORCEMENT_LOSS_TERMINATION_GRACE.as_secs()
        + crate::boundary_server::FORCE_KILL_REAP_TIMEOUT.as_secs()
        + 5,
);

const ACCEPT_POLL_INTERVAL: Duration = Duration::from_millis(10);

/// Group-ending callback registered by the boundary.
pub type GroupFailureHandler = Arc<dyn Fn(String) + Send + Sync>;

/// Credentials the kernel recorded for a connected peer socket.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PeerCredentials {
    pub pid: i32,
    pub uid: u32,
    pub gid: u32,
}

fn peer_credentials(stream: &UnixStream) -> io::Result<PeerCredentials> {
    let credentials =
        nix::sys::socket::getsockopt(stream, nix::sys::socket::sockopt::PeerCredentials)
            .map_err(io::Error::from)?;
    Ok(PeerCredentials {
        pid: credentials.pid(),
        uid: credentials.uid(),
        gid: credentials.gid(),
    })
}

/// A peer runtime runs as the boundary's workload identity in its own
/// container, so its PID namespace is not the primary's: the kernel reports
/// PID 0. A visible PID is a process of the agent container, typically one
/// of its workloads; workloads share the identity, which is why the token is
/// also required.
pub fn require_peer_credentials(
    credentials: PeerCredentials,
    identity: &ResolvedWorkloadIdentity,
) -> Result<(), String> {
    if credentials.uid != identity.uid || credentials.gid != identity.gid {
        return Err(format!(
            "connection runs as {}:{}, not the workload identity {}:{}",
            credentials.uid, credentials.gid, identity.uid, identity.gid
        ));
    }
    if credentials.pid != 0 {
        return Err(format!(
            "connection comes from process {} inside the primary runtime's own container",
            credentials.pid
        ));
    }
    Ok(())
}

/// What the barrier needs, with every environment-specific input explicit.
pub struct HubSetup<'a> {
    pub peers: &'a [PeerWorkloadConfig],
    /// Directory holding peer `index`'s control socket.
    pub control_dir: &'a dyn Fn(usize) -> PathBuf,
    pub verify_credentials: &'a dyn Fn(PeerCredentials) -> Result<(), String>,
    pub protected_control_port: Option<u16>,
    pub timeout: Duration,
    /// Abandon the barrier, for example on SIGTERM.
    pub should_abort: &'a dyn Fn() -> bool,
}

impl<'a> HubSetup<'a> {
    /// The production layout and checks for `peers`.
    pub fn production(
        peers: &'a [PeerWorkloadConfig],
        verify_credentials: &'a dyn Fn(PeerCredentials) -> Result<(), String>,
        protected_control_port: Option<u16>,
        should_abort: &'a dyn Fn() -> bool,
    ) -> Self {
        Self {
            peers,
            control_dir: &production_control_dir,
            verify_credentials,
            protected_control_port,
            timeout: Duration::from_secs(PEER_CONNECT_TIMEOUT_SECS),
            should_abort,
        }
    }
}

fn production_control_dir(index: usize) -> PathBuf {
    PathBuf::from(peer_control_dir_in_primary(index))
}

#[derive(Default)]
struct LinkState {
    start: Option<Result<(), String>>,
    exited: Option<ExitStatusWire>,
    closed: bool,
}

/// Relayed-stream waiters of one link; `None` once the link has closed, so
/// no waiter can be parked on a peer that will never answer.
type RelayWaiters = Option<HashMap<u64, oneshot::Sender<io::Result<TcpStream>>>>;

struct PeerLink {
    config: PeerWorkloadConfig,
    sender: PeerSender,
    qualification: PeerQualification,
    state: Mutex<LinkState>,
    changed: Condvar,
    relays: Mutex<RelayWaiters>,
}

impl PeerLink {
    fn name(&self) -> &str {
        &self.config.name
    }

    fn update(&self, change: impl FnOnce(&mut LinkState)) {
        change(&mut lock(&self.state));
        self.changed.notify_all();
    }

    /// Wait until `done` holds or `deadline` passes; returns whether it held.
    fn wait_until(&self, deadline: Instant, done: impl Fn(&LinkState) -> bool) -> bool {
        let mut state = lock(&self.state);
        loop {
            if done(&state) {
                return true;
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return false;
            }
            state = self
                .changed
                .wait_timeout(state, remaining)
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .0;
        }
    }

    fn send(&self, message: &PrimaryToPeer) {
        if let Err(error) = self.sender.send(message) {
            tracing::warn!(peer = self.name(), %error, "could not reach peer runtime");
        }
    }
}

/// Every authenticated peer runtime of this boundary.
pub struct PeerHub {
    links: Vec<Arc<PeerLink>>,
    broker: NetworkBroker,
    failure: Mutex<Option<String>>,
    handler: Mutex<Option<GroupFailureHandler>>,
    /// The boundary is ending the group; peer exits are expected.
    terminating: AtomicBool,
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

impl PeerHub {
    /// Run the peer barrier: every peer connects, authenticates, qualifies and
    /// starts its broker, or the boundary is never served.
    pub fn establish(setup: &HubSetup<'_>, broker: NetworkBroker) -> Result<Arc<Self>, String> {
        let mut listeners = Vec::with_capacity(setup.peers.len());
        for peer in setup.peers {
            let path = (setup.control_dir)(peer.index).join(PEER_SOCKET_FILE);
            match bind_peer_socket(&path) {
                Ok(listener) => listeners.push(Some((listener, path))),
                Err(error) => {
                    remove_sockets(&listeners);
                    return Err(format!(
                        "listen for peer workload {} at {}: {error}",
                        peer.name,
                        path.display()
                    ));
                }
            }
        }
        let result = accept_peers(setup, &mut listeners);
        remove_sockets(&listeners);
        let channels = result?;
        let mut links = Vec::with_capacity(channels.len());
        let mut receivers = Vec::with_capacity(channels.len());
        for (peer, (sender, receiver, qualification)) in setup.peers.iter().zip(channels) {
            links.push(Arc::new(PeerLink {
                config: peer.clone(),
                sender,
                qualification,
                state: Mutex::new(LinkState::default()),
                changed: Condvar::new(),
                relays: Mutex::new(Some(HashMap::new())),
            }));
            receivers.push(receiver);
        }
        let hub = Arc::new(Self {
            links,
            broker,
            failure: Mutex::new(None),
            handler: Mutex::new(None),
            terminating: AtomicBool::new(false),
        });
        for (link, mut receiver) in hub.links.clone().into_iter().zip(receivers) {
            let hub = hub.clone();
            std::thread::Builder::new()
                .name(format!("openshell-peer-{}", link.config.index))
                .spawn(move || hub.serve_link(&link, &mut receiver))
                .map_err(|error| format!("start peer channel reader: {error}"))?;
        }
        tracing::info!(
            peers = hub.links.len(),
            "Peer workload runtimes joined the boundary"
        );
        Ok(hub)
    }

    /// Register the boundary's group-ending handler. A failure that happened
    /// before registration is delivered immediately.
    pub fn set_failure_handler(&self, handler: GroupFailureHandler) {
        let pending = lock(&self.failure).clone();
        *lock(&self.handler) = Some(handler.clone());
        if let Some(reason) = pending {
            handler(reason);
        }
    }

    pub fn failure(&self) -> Option<String> {
        lock(&self.failure).clone()
    }

    /// Qualifications every peer measured in its own container.
    pub fn qualifications(&self) -> Vec<PeerQualification> {
        self.links.iter().map(|link| link.qualification).collect()
    }

    /// Every peer runtime is still connected and nothing has failed.
    pub fn confirm_healthy(&self) -> Result<(), String> {
        if let Some(reason) = self.failure() {
            return Err(format!("peer workload group failed: {reason}"));
        }
        if let Some(link) = self.links.iter().find(|link| lock(&link.state).closed) {
            return Err(format!("peer workload {} is not connected", link.name()));
        }
        Ok(())
    }

    /// Start every peer workload and wait for all acknowledgements. Any
    /// failure terminates the peers that did start.
    pub fn start(
        &self,
        start_for: impl Fn(&PeerWorkloadConfig) -> PeerStart,
        timeout: Duration,
    ) -> Result<(), String> {
        self.confirm_healthy()?;
        for link in &self.links {
            if let Err(error) = link
                .sender
                .send(&PrimaryToPeer::Start(Box::new(start_for(&link.config))))
            {
                self.request_termination(false);
                return Err(format!("start peer workload {}: {error}", link.name()));
            }
        }
        let deadline = Instant::now() + timeout;
        for link in &self.links {
            let answered = link.wait_until(deadline, |state| state.start.is_some() || state.closed);
            let outcome = lock(&link.state).start.clone();
            let failure = match (answered, outcome) {
                (true, Some(Ok(()))) => continue,
                (true, Some(Err(message))) => message,
                (true, None) => "peer runtime closed its channel".to_string(),
                (false, _) => format!("no answer within {}s", timeout.as_secs()),
            };
            self.request_termination(false);
            return Err(format!(
                "peer workload {} did not start: {failure}",
                link.name()
            ));
        }
        Ok(())
    }

    pub fn freeze(&self) {
        for link in self.open_links() {
            link.send(&PrimaryToPeer::Freeze);
        }
    }

    pub fn thaw(&self) {
        for link in self.open_links() {
            link.send(&PrimaryToPeer::Thaw);
        }
    }

    /// Ask every peer to terminate its workload without waiting.
    pub fn request_termination(&self, enforcement_lost: bool) {
        self.terminating.store(true, Ordering::Release);
        for link in self.open_links() {
            link.send(&PrimaryToPeer::Terminate { enforcement_lost });
        }
    }

    /// Terminate every peer workload and wait until each reported its exit
    /// or its runtime is gone.
    pub fn terminate(&self, enforcement_lost: bool, timeout: Duration) -> Result<(), String> {
        self.request_termination(enforcement_lost);
        let deadline = Instant::now() + timeout;
        let remaining = self
            .links
            .iter()
            .filter(|link| {
                !link.wait_until(deadline, |state| state.exited.is_some() || state.closed)
            })
            .map(|link| link.name().to_string())
            .collect::<Vec<_>>();
        if remaining.is_empty() {
            return Ok(());
        }
        Err(format!(
            "peer workloads {remaining:?} did not terminate within {}s",
            timeout.as_secs()
        ))
    }

    fn open_links(&self) -> impl Iterator<Item = &Arc<PeerLink>> {
        self.links.iter().filter(|link| !lock(&link.state).closed)
    }

    fn fail_group(&self, reason: String) {
        {
            let mut failure = lock(&self.failure);
            if failure.is_some() {
                return;
            }
            *failure = Some(reason.clone());
        }
        tracing::error!(reason = %reason, "Peer workload group failed; ending the sandbox");
        openshell_ocsf::ocsf_emit!(
            openshell_ocsf::DetectionFindingBuilder::new(openshell_ocsf::ctx::ctx())
                .activity(openshell_ocsf::ActivityId::Open)
                .severity(openshell_ocsf::SeverityId::High)
                .confidence(openshell_ocsf::ConfidenceId::High)
                .is_alert(true)
                .finding_info(openshell_ocsf::FindingInfo::new(
                    "sandbox-peer-workload-failed",
                    "Sandbox Peer Workload Failed",
                ))
                .message(format!("Peer workload group ended: {reason}"))
                .build()
        );
        let handler = lock(&self.handler).clone();
        if let Some(handler) = handler {
            handler(reason);
        }
    }

    fn serve_link(&self, link: &Arc<PeerLink>, receiver: &mut PeerReceiver) {
        let ended = loop {
            let frame = match receiver.recv::<PeerToPrimary>() {
                Ok(Some(frame)) => frame,
                Ok(None) => break None,
                Err(error) => break Some(error.to_string()),
            };
            if let Some(violation) = self.handle(link, frame.message, frame.descriptor) {
                break Some(violation);
            }
        };
        link.sender.shutdown();
        lock(&link.relays).take();
        self.broker.forget_peer_dns(link.config.index);
        link.update(|state| state.closed = true);
        // A peer runtime exits once the boundary asked it to terminate,
        // whether or not its workload had started.
        if self.terminating.load(Ordering::Acquire) {
            return;
        }
        let detail = ended.map_or_else(String::new, |error| format!(": {error}"));
        self.fail_group(format!(
            "peer runtime {} closed its channel{detail}",
            link.name()
        ));
    }

    /// Handle one peer message; returns a protocol violation that ends the
    /// link.
    fn handle(
        &self,
        link: &Arc<PeerLink>,
        message: PeerToPrimary,
        descriptor: Option<OwnedFd>,
    ) -> Option<String> {
        match message {
            PeerToPrimary::Started => link.update(|state| state.start = Some(Ok(()))),
            PeerToPrimary::StartFailed { message } => {
                link.update(|state| state.start = Some(Err(message)));
            }
            PeerToPrimary::TcpOpen {
                id,
                destination,
                identity,
                socket,
                notification_to_queue_us,
                queue_wait_us,
            } => {
                // The environment comes from the authenticated socket the
                // open arrived on, never from the peer's own claim.
                let identity = identity.into_result().map(|mut identity| {
                    identity.execution_environment = Some(link.config.name.clone());
                    identity
                });
                Self::forward_tcp_open(
                    link,
                    id,
                    self.broker.inject_tcp_open(
                        destination,
                        identity,
                        socket,
                        Duration::from_micros(notification_to_queue_us),
                        Duration::from_micros(queue_wait_us),
                    ),
                );
            }
            PeerToPrimary::TcpRelay { id } => {
                let waiter = lock(&link.relays)
                    .as_mut()
                    .and_then(|relays| relays.remove(&id));
                if let (Some(waiter), Some(descriptor)) = (waiter, descriptor) {
                    let _ = waiter.send(relayed_stream(descriptor));
                }
            }
            PeerToPrimary::TcpRelayFailed { id, message } => {
                let waiter = lock(&link.relays)
                    .as_mut()
                    .and_then(|relays| relays.remove(&id));
                if let Some(waiter) = waiter {
                    let _ = waiter.send(Err(io::Error::other(message)));
                }
            }
            PeerToPrimary::DnsAdmit {
                id,
                transport,
                source,
            } => {
                let errno = self
                    .broker
                    .admit_peer_dns(link.config.index, transport, source)
                    .err()
                    .map(|error| error.raw_os_error().unwrap_or(libc::EIO));
                link.send(&PrimaryToPeer::DnsAdmitResult { id, errno });
            }
            PeerToPrimary::DnsRevoke { transport, sources } => {
                self.broker
                    .revoke_peer_dns(link.config.index, transport, &sources);
            }
            PeerToPrimary::WorkloadExited { status } => {
                link.update(|state| state.exited = Some(status));
                if !self.terminating.load(Ordering::Acquire) {
                    self.fail_group(format!("peer workload {} exited ({status:?})", link.name()));
                }
            }
            PeerToPrimary::Failed { message } => {
                self.fail_group(format!("peer runtime {} failed: {message}", link.name()));
            }
            message @ (PeerToPrimary::Hello { .. } | PeerToPrimary::Ready) => {
                return Some(format!("unexpected {message:?} after the peer joined"));
            }
        }
        None
    }

    fn forward_tcp_open(
        link: &Arc<PeerLink>,
        id: u64,
        forwarded: io::Result<crate::network_broker::ForwardedTcpOpen>,
    ) {
        let forwarded = match forwarded {
            Ok(forwarded) => forwarded,
            Err(error) => {
                link.send(&PrimaryToPeer::TcpDecision {
                    id,
                    decision: TcpOpenDecision::Denied(injection_denial(&error)),
                });
                return;
            }
        };
        let link = link.clone();
        let spawned = std::thread::Builder::new()
            .name("openshell-peer-open".to_string())
            .spawn(move || {
                let decision = forwarded
                    .decision
                    .recv_timeout(NETWORK_DECISION_TIMEOUT)
                    .unwrap_or(TcpOpenDecision::Denied(TcpOpenDenial::MediationUnavailable));
                if decision == TcpOpenDecision::RelayReady {
                    // Park the waiter before the peer can answer; a closed
                    // link drops it, which fails the relay instead of hanging.
                    if let Some(relays) = lock(&link.relays).as_mut() {
                        relays.insert(id, forwarded.relay);
                    }
                }
                link.send(&PrimaryToPeer::TcpDecision { id, decision });
            });
        if let Err(error) = spawned {
            tracing::warn!(%error, "could not wait for a forwarded peer TCP decision");
        }
    }
}

/// Typed denial for an open the primary could not queue.
fn injection_denial(error: &io::Error) -> TcpOpenDenial {
    match error.raw_os_error() {
        Some(libc::EAGAIN) => TcpOpenDenial::ResourceExhausted,
        Some(libc::EACCES) => TcpOpenDenial::InvalidDestination,
        _ => TcpOpenDenial::MediationUnavailable,
    }
}

/// Accept a relayed stream only if it is what the peer's broker produces: a
/// connected loopback TCP stream.
fn relayed_stream(descriptor: OwnedFd) -> io::Result<TcpStream> {
    let socket = socket2::Socket::from(descriptor);
    if socket.r#type()? != socket2::Type::STREAM
        || !matches!(
            socket.domain()?,
            domain if domain == socket2::Domain::IPV4 || domain == socket2::Domain::IPV6
        )
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "peer relay is not a TCP stream",
        ));
    }
    let stream = TcpStream::from(socket);
    if !stream.peer_addr()?.ip().to_canonical().is_loopback()
        || !stream.local_addr()?.ip().to_canonical().is_loopback()
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "peer relay is not a loopback stream",
        ));
    }
    Ok(stream)
}

fn bind_peer_socket(path: &std::path::Path) -> io::Result<UnixListener> {
    // The control directory is a fresh Memory volume; a leftover socket means
    // something else is, or was, serving it.
    if std::fs::symlink_metadata(path).is_ok() {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "peer socket already exists",
        ));
    }
    let listener = UnixListener::bind(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    listener.set_nonblocking(true)?;
    Ok(listener)
}

fn remove_sockets(listeners: &[Option<(UnixListener, PathBuf)>]) {
    for (_, path) in listeners.iter().flatten() {
        let _ = std::fs::remove_file(path);
    }
}

type PeerChannel = (PeerSender, PeerReceiver, PeerQualification);

fn accept_peers(
    setup: &HubSetup<'_>,
    listeners: &mut [Option<(UnixListener, PathBuf)>],
) -> Result<Vec<PeerChannel>, String> {
    let deadline = Instant::now() + setup.timeout;
    let mut channels: Vec<Option<PeerChannel>> = (0..setup.peers.len()).map(|_| None).collect();
    while channels.iter().any(Option::is_none) {
        if (setup.should_abort)() {
            return Err("termination requested before every peer workload joined".to_string());
        }
        if Instant::now() >= deadline {
            let missing = setup
                .peers
                .iter()
                .zip(&channels)
                .filter(|(_, channel)| channel.is_none())
                .map(|(peer, _)| peer.name.as_str())
                .collect::<Vec<_>>();
            return Err(format!(
                "peer workloads {missing:?} did not join within {}s",
                setup.timeout.as_secs()
            ));
        }
        let mut progressed = false;
        for (index, slot) in listeners.iter_mut().enumerate() {
            let accepted = match slot {
                Some((listener, _)) => listener.accept(),
                None => continue,
            };
            let stream = match accepted {
                Ok((stream, _)) => stream,
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                    ) =>
                {
                    continue;
                }
                Err(error) => return Err(format!("accept peer connection: {error}")),
            };
            // Exactly one connection per peer: the socket disappears and the
            // listener closes before the caller is even authenticated.
            if let Some((listener, path)) = slot.take() {
                drop(listener);
                std::fs::remove_file(&path)
                    .map_err(|error| format!("remove peer socket {}: {error}", path.display()))?;
            }
            let peer = &setup.peers[index];
            channels[index] = Some(
                authenticate(stream, peer, setup, deadline)
                    .map_err(|error| format!("peer workload {}: {error}", peer.name))?,
            );
            progressed = true;
        }
        if !progressed {
            std::thread::sleep(ACCEPT_POLL_INTERVAL);
        }
    }
    Ok(channels.into_iter().flatten().collect())
}

fn authenticate(
    stream: UnixStream,
    peer: &PeerWorkloadConfig,
    setup: &HubSetup<'_>,
    deadline: Instant,
) -> Result<PeerChannel, String> {
    stream
        .set_nonblocking(false)
        .map_err(|error| format!("configure peer connection: {error}"))?;
    let credentials =
        peer_credentials(&stream).map_err(|error| format!("read peer credentials: {error}"))?;
    (setup.verify_credentials)(credentials)?;
    let (sender, mut receiver) =
        peer_protocol::split(stream).map_err(|error| format!("split peer channel: {error}"))?;
    let read_bound = || {
        deadline
            .saturating_duration_since(Instant::now())
            .max(Duration::from_millis(1))
    };
    receiver
        .set_read_timeout(Some(read_bound()))
        .map_err(|error| format!("bound peer handshake: {error}"))?;
    let (token, qualification) = match receiver.recv::<PeerToPrimary>() {
        Ok(Some(frame)) => match frame.message {
            PeerToPrimary::Hello {
                token,
                qualification,
            } => (token, qualification),
            other => return Err(format!("expected hello, got {other:?}")),
        },
        Ok(None) => return Err("closed the connection before hello".to_string()),
        Err(error) => return Err(format!("read hello: {error}")),
    };
    if !peer_protocol::token_matches(&token, &peer.token_sha256)
        .map_err(|error| error.to_string())?
    {
        return Err("presented an invalid token".to_string());
    }
    sender
        .send(&PrimaryToPeer::Welcome {
            protected_control_port: setup.protected_control_port,
        })
        .map_err(|error| format!("send welcome: {error}"))?;
    receiver
        .set_read_timeout(Some(read_bound()))
        .map_err(|error| format!("bound peer readiness: {error}"))?;
    match receiver.recv::<PeerToPrimary>() {
        Ok(Some(frame)) if matches!(frame.message, PeerToPrimary::Ready) => {}
        Ok(Some(frame)) => return Err(format!("expected ready, got {:?}", frame.message)),
        Ok(None) => return Err("closed the connection before ready".to_string()),
        Err(error) => return Err(format!("read ready: {error}")),
    }
    receiver
        .set_read_timeout(None)
        .map_err(|error| format!("clear peer channel timeout: {error}"))?;
    Ok((sender, receiver, qualification))
}

#[cfg(test)]
mod tests {
    use super::*;
    use openshell_sandbox_backend::boundary_protocol::SeccompEvidence;
    use std::collections::BTreeMap;
    use std::path::Path;

    fn qualification() -> PeerQualification {
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
            landlock_abi: 5,
            landlock_allow_deny: true,
            udp_dns_round_trip: true,
            tcp_dns_round_trip: true,
            tcp_allow_round_trip: true,
            tcp_deny_round_trip: true,
            socket_loopback_confinement: true,
        }
    }

    fn token(index: usize) -> String {
        format!("{index:02x}").repeat(32)
    }

    fn peers(count: usize) -> Vec<PeerWorkloadConfig> {
        (0..count)
            .map(|index| PeerWorkloadConfig {
                index,
                name: format!("peer-{index}"),
                command: vec!["/bin/peer".to_string()],
                environment: BTreeMap::new(),
                token_sha256: peer_protocol::token_digest(&token(index)).unwrap(),
            })
            .collect()
    }

    fn test_broker() -> NetworkBroker {
        let (_launcher, listener) = crate::linux::workload_launcher::start().unwrap();
        NetworkBroker::start_for_test(listener).unwrap()
    }

    /// Credentials of this test process stand in for a peer container's;
    /// only the PID-namespace rule differs, and it has its own test.
    fn same_process(credentials: PeerCredentials) -> Result<(), String> {
        if credentials.uid == nix::unistd::geteuid().as_raw()
            && credentials.gid == nix::unistd::getegid().as_raw()
        {
            return Ok(());
        }
        Err("unexpected test credentials".to_string())
    }

    struct Barrier {
        root: tempfile::TempDir,
        peers: Vec<PeerWorkloadConfig>,
    }

    impl Barrier {
        fn new(count: usize) -> Self {
            let root = tempfile::tempdir().unwrap();
            for index in 0..count {
                std::fs::create_dir(root.path().join(index.to_string())).unwrap();
            }
            Self {
                root,
                peers: peers(count),
            }
        }

        fn socket(&self, index: usize) -> PathBuf {
            self.root
                .path()
                .join(index.to_string())
                .join(PEER_SOCKET_FILE)
        }

        fn establish(
            &self,
            timeout: Duration,
            verify: &dyn Fn(PeerCredentials) -> Result<(), String>,
        ) -> Result<Arc<PeerHub>, String> {
            let root = self.root.path().to_path_buf();
            let control_dir = move |index: usize| root.join(index.to_string());
            PeerHub::establish(
                &HubSetup {
                    peers: &self.peers,
                    control_dir: &control_dir,
                    verify_credentials: verify,
                    protected_control_port: Some(9443),
                    timeout,
                    should_abort: &|| false,
                },
                test_broker(),
            )
        }
    }

    fn connect(socket: &Path) -> UnixStream {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            match UnixStream::connect(socket) {
                Ok(stream) => return stream,
                Err(_) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(error) => panic!("connect {}: {error}", socket.display()),
            }
        }
    }

    /// A well-behaved peer: hello, welcome, ready. Returns its channel.
    fn join(socket: &Path, token: String) -> (PeerSender, PeerReceiver) {
        let (sender, mut receiver) = peer_protocol::split(connect(socket)).unwrap();
        sender
            .send(&PeerToPrimary::Hello {
                token,
                qualification: qualification(),
            })
            .unwrap();
        let welcome = receiver.recv::<PrimaryToPeer>().unwrap().unwrap();
        assert!(
            welcome.message
                == PrimaryToPeer::Welcome {
                    protected_control_port: Some(9443)
                }
        );
        sender.send(&PeerToPrimary::Ready).unwrap();
        (sender, receiver)
    }

    #[test]
    fn credentials_require_the_workload_identity_outside_the_primary_namespace() {
        let identity = ResolvedWorkloadIdentity {
            uid: 1000,
            gid: 1000,
            supplementary_gids: Vec::new(),
            source: "image".to_string(),
            resource_digest: "sha256:test".to_string(),
        };
        let peer = PeerCredentials {
            pid: 0,
            uid: 1000,
            gid: 1000,
        };
        require_peer_credentials(peer, &identity).unwrap();
        for credentials in [
            PeerCredentials { uid: 1001, ..peer },
            PeerCredentials { gid: 0, ..peer },
            PeerCredentials { pid: 42, ..peer },
        ] {
            assert!(require_peer_credentials(credentials, &identity).is_err());
        }
    }

    #[test]
    fn barrier_admits_every_authenticated_peer_once() {
        let barrier = Barrier::new(2);
        let mut peers = Vec::new();
        for index in 0..2 {
            let socket = barrier.socket(index);
            peers.push(std::thread::spawn(move || join(&socket, token(index))));
        }
        let hub = barrier
            .establish(Duration::from_secs(10), &same_process)
            .unwrap();
        let _channels = peers
            .into_iter()
            .map(|peer| peer.join().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(hub.qualifications(), vec![qualification(); 2]);
        hub.confirm_healthy().unwrap();
        for index in 0..2 {
            // The socket is gone: no second connection is possible.
            assert!(!barrier.socket(index).exists());
            assert!(UnixStream::connect(barrier.socket(index)).is_err());
        }
    }

    #[test]
    fn barrier_rejects_a_bad_token() {
        let barrier = Barrier::new(1);
        let socket = barrier.socket(0);
        let peer = std::thread::spawn(move || {
            let (sender, mut receiver) = peer_protocol::split(connect(&socket)).unwrap();
            sender
                .send(&PeerToPrimary::Hello {
                    token: token(7),
                    qualification: qualification(),
                })
                .unwrap();
            receiver.recv::<PrimaryToPeer>()
        });
        let error = barrier
            .establish(Duration::from_secs(10), &same_process)
            .err()
            .unwrap();
        assert!(error.contains("invalid token"), "{error}");
        // The peer never receives a welcome.
        assert!(!matches!(peer.join().unwrap(), Ok(Some(_))));
    }

    #[test]
    fn barrier_rejects_unexpected_credentials() {
        let barrier = Barrier::new(1);
        let socket = barrier.socket(0);
        let peer = std::thread::spawn(move || connect(&socket));
        let error = barrier
            .establish(Duration::from_secs(10), &|credentials| {
                require_peer_credentials(
                    credentials,
                    &ResolvedWorkloadIdentity {
                        uid: credentials.uid,
                        gid: credentials.gid,
                        supplementary_gids: Vec::new(),
                        source: "image".to_string(),
                        resource_digest: "sha256:test".to_string(),
                    },
                )
            })
            .err()
            .unwrap();
        // This test process is visible in its own PID namespace.
        assert!(error.contains("inside the primary runtime"), "{error}");
        drop(peer.join().unwrap());

        let barrier = Barrier::new(1);
        let socket = barrier.socket(0);
        let peer = std::thread::spawn(move || connect(&socket));
        let error = barrier
            .establish(Duration::from_secs(10), &|_| {
                Err("connection runs as 1:1, not the workload identity".to_string())
            })
            .err()
            .unwrap();
        assert!(error.contains("not the workload identity"), "{error}");
        drop(peer.join().unwrap());
    }

    #[test]
    fn barrier_fails_closed_when_a_peer_never_joins() {
        let barrier = Barrier::new(2);
        let socket = barrier.socket(0);
        let peer = std::thread::spawn(move || join(&socket, token(0)));
        let error = barrier
            .establish(Duration::from_millis(500), &same_process)
            .err()
            .unwrap();
        assert!(error.contains("peer-1"), "{error}");
        assert!(!error.contains("peer-0\""), "{error}");
        drop(peer.join().unwrap());
        assert!(
            !barrier.socket(1).exists(),
            "an abandoned socket is removed"
        );

        // A peer that connects but never finishes its handshake counts too.
        let barrier = Barrier::new(1);
        let socket = barrier.socket(0);
        let peer = std::thread::spawn(move || {
            let stream = connect(&socket);
            std::thread::sleep(Duration::from_millis(800));
            drop(stream);
        });
        assert!(
            barrier
                .establish(Duration::from_millis(300), &same_process)
                .is_err()
        );
        peer.join().unwrap();
    }

    #[test]
    fn barrier_refuses_a_preexisting_socket() {
        let barrier = Barrier::new(1);
        std::fs::write(barrier.socket(0), b"").unwrap();
        let error = barrier
            .establish(Duration::from_millis(100), &same_process)
            .err()
            .unwrap();
        assert!(error.contains("already exists"), "{error}");
    }

    fn joined_hub(count: usize) -> (Barrier, Arc<PeerHub>, Vec<(PeerSender, PeerReceiver)>) {
        let barrier = Barrier::new(count);
        let mut peers = Vec::new();
        for index in 0..count {
            let socket = barrier.socket(index);
            peers.push(std::thread::spawn(move || join(&socket, token(index))));
        }
        let hub = barrier
            .establish(Duration::from_secs(10), &same_process)
            .unwrap();
        let channels = peers
            .into_iter()
            .map(|peer| peer.join().unwrap())
            .collect::<Vec<_>>();
        (barrier, hub, channels)
    }

    fn failures(hub: &PeerHub) -> Arc<Mutex<Vec<String>>> {
        let failures = Arc::new(Mutex::new(Vec::new()));
        let recorded = failures.clone();
        hub.set_failure_handler(Arc::new(move |reason| lock(&recorded).push(reason)));
        failures
    }

    fn wait_for(condition: impl Fn() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while !condition() {
            assert!(Instant::now() < deadline, "condition not reached");
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    fn start_message(peer: &PeerWorkloadConfig) -> PeerStart {
        PeerStart {
            command: peer.command.clone(),
            environment: HashMap::new(),
            policy: openshell_sandbox_backend::boundary_protocol::SandboxPolicyWire::from(
                openshell_core::policy::SandboxPolicy {
                    version: 1,
                    filesystem: openshell_core::policy::FilesystemPolicy::default(),
                    network: openshell_core::policy::NetworkPolicy::default(),
                    landlock: openshell_core::policy::LandlockPolicy::default(),
                    process: openshell_core::policy::ProcessPolicy {
                        run_as_user: None,
                        run_as_group: None,
                    },
                },
            ),
            gpu_requested: false,
            workload_uid: 1000,
            workload_gid: 1000,
            ca_cert: None,
            ca_bundle: None,
            provider_env_revision: 0,
            provider_env: HashMap::new(),
            provider_files: HashMap::new(),
        }
    }

    #[test]
    fn peer_workload_exit_ends_the_group_once() {
        let (_barrier, hub, mut channels) = joined_hub(2);
        let failures = failures(&hub);
        channels[1]
            .0
            .send(&PeerToPrimary::WorkloadExited {
                status: ExitStatusWire::Signaled(libc::SIGKILL),
            })
            .unwrap();
        wait_for(|| !lock(&failures).is_empty());
        assert!(lock(&failures)[0].contains("peer-1"));
        assert!(hub.confirm_healthy().is_err());
        // The peer runtime then exits; that is the same group failure.
        drop(channels.remove(1));
        wait_for(|| lock(&hub.links[1].state).closed);
        assert_eq!(lock(&failures).len(), 1);
    }

    #[test]
    fn peer_runtime_loss_ends_the_group_and_is_reported_late_handlers() {
        let (_barrier, hub, mut channels) = joined_hub(1);
        drop(channels.remove(0));
        wait_for(|| hub.failure().is_some());
        // A handler registered after the failure still sees it.
        let failures = failures(&hub);
        assert_eq!(lock(&failures).len(), 1);
        assert!(lock(&failures)[0].contains("closed its channel"));
    }

    #[test]
    fn requested_termination_is_not_a_group_failure() {
        let (_barrier, hub, channels) = joined_hub(2);
        let failures = failures(&hub);
        let peers = channels
            .into_iter()
            .map(|(sender, mut receiver)| {
                std::thread::spawn(move || {
                    let message = receiver.recv::<PrimaryToPeer>().unwrap().unwrap().message;
                    assert!(
                        message
                            == PrimaryToPeer::Terminate {
                                enforcement_lost: true
                            }
                    );
                    sender
                        .send(&PeerToPrimary::WorkloadExited {
                            status: ExitStatusWire::Exited(0),
                        })
                        .unwrap();
                })
            })
            .collect::<Vec<_>>();
        hub.terminate(true, Duration::from_secs(10)).unwrap();
        for peer in peers {
            peer.join().unwrap();
        }
        wait_for(|| hub.links.iter().all(|link| lock(&link.state).closed));
        assert!(lock(&failures).is_empty());
    }

    #[test]
    fn termination_times_out_on_a_silent_peer() {
        let (_barrier, hub, _channels) = joined_hub(1);
        let error = hub
            .terminate(false, Duration::from_millis(200))
            .unwrap_err();
        assert!(error.contains("peer-0"), "{error}");
    }

    #[test]
    fn start_waits_for_every_peer_and_terminates_on_failure() {
        let (_barrier, hub, channels) = joined_hub(2);
        let peers = channels
            .into_iter()
            .enumerate()
            .map(|(index, (sender, mut receiver))| {
                std::thread::spawn(move || {
                    let PrimaryToPeer::Start(start) =
                        receiver.recv::<PrimaryToPeer>().unwrap().unwrap().message
                    else {
                        panic!("expected start");
                    };
                    assert_eq!(start.command, vec!["/bin/peer".to_string()]);
                    let reply = if index == 0 {
                        PeerToPrimary::Started
                    } else {
                        PeerToPrimary::StartFailed {
                            message: "image has no python".to_string(),
                        }
                    };
                    sender.send(&reply).unwrap();
                    // Every peer, including the started one, is terminated.
                    let message = receiver.recv::<PrimaryToPeer>().unwrap().unwrap().message;
                    assert!(
                        message
                            == PrimaryToPeer::Terminate {
                                enforcement_lost: false
                            }
                    );
                    (sender, receiver)
                })
            })
            .collect::<Vec<_>>();
        let error = hub
            .start(start_message, Duration::from_secs(10))
            .unwrap_err();
        assert!(
            error.contains("peer-1") && error.contains("image has no python"),
            "{error}"
        );
        for peer in peers {
            drop(peer.join().unwrap());
        }
    }

    #[test]
    fn start_fails_when_a_peer_never_answers() {
        let (_barrier, hub, _channels) = joined_hub(1);
        let error = hub
            .start(start_message, Duration::from_millis(200))
            .unwrap_err();
        assert!(error.contains("no answer"), "{error}");
    }

    #[test]
    fn lifecycle_signals_reach_every_peer() {
        let (_barrier, hub, mut channels) = joined_hub(2);
        hub.freeze();
        hub.thaw();
        for (_, receiver) in &mut channels {
            for expected in [PrimaryToPeer::Freeze, PrimaryToPeer::Thaw] {
                assert!(receiver.recv::<PrimaryToPeer>().unwrap().unwrap().message == expected);
            }
        }
    }

    #[test]
    fn dns_admissions_enter_the_primary_relay_under_the_peer_bound() {
        let (_barrier, hub, mut channels) = joined_hub(1);
        let (sender, receiver) = &mut channels[0];
        let mut admit = |id: u64, source: &str| {
            sender
                .send(&PeerToPrimary::DnsAdmit {
                    id,
                    transport: openshell_isolation_interface::contract::DnsTransport::Udp,
                    source: source.parse().unwrap(),
                })
                .unwrap();
            match receiver.recv::<PrimaryToPeer>().unwrap().unwrap().message {
                PrimaryToPeer::DnsAdmitResult {
                    id: answered,
                    errno,
                } => {
                    assert_eq!(answered, id);
                    errno
                }
                other => panic!("unexpected {other:?}"),
            }
        };
        assert_eq!(admit(1, "127.0.0.1:40000"), None);
        assert_eq!(admit(2, "10.0.0.1:40000"), Some(libc::EINVAL));
        assert_eq!(admit(3, "127.0.0.1:0"), Some(libc::EINVAL));
        let mut next = 4;
        for port in 1..crate::network_broker::FORWARDED_DNS_ADMISSIONS_PER_PEER {
            assert_eq!(admit(next, &format!("127.0.0.1:{}", 40_000 + port)), None);
            next += 1;
        }
        assert_eq!(admit(next, "127.0.0.1:50000"), Some(libc::EMFILE));
        drop(hub);
    }

    #[test]
    fn tcp_relay_streams_must_be_connected_loopback_tcp() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let _server = listener.accept().unwrap();
        relayed_stream(OwnedFd::from(client)).unwrap();

        let (unix, _other) = UnixStream::pair().unwrap();
        assert!(relayed_stream(OwnedFd::from(unix)).is_err());
        let udp = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        assert!(relayed_stream(OwnedFd::from(udp)).is_err());
    }

    #[test]
    fn forwarded_open_carries_the_peer_name_and_returns_the_decision() {
        let (_barrier, hub, mut channels) = joined_hub(1);
        let broker = hub.broker.clone();
        let (sender, receiver) = &mut channels[0];
        let mut identity = openshell_isolation_interface::contract::BinaryIdentity {
            executable: openshell_isolation_interface::contract::ExecutableIdentity {
                path: PathBuf::from("/usr/local/bin/python3"),
                digest: Some("c".repeat(64).parse().unwrap()),
            },
            ancestors: Vec::new(),
            cmdline_paths: Vec::new(),
            execution_environment: Some("agent-impersonation".to_string()),
        };
        sender
            .send(&PeerToPrimary::TcpOpen {
                id: 11,
                destination: "203.0.113.9:443".parse().unwrap(),
                identity: Ok(identity.clone()).into(),
                socket: openshell_isolation_interface::contract::NetworkSocketMetadata {
                    socket_cookie: 1,
                    nonblocking: false,
                    process_generation: 2,
                },
                notification_to_queue_us: 5,
                queue_wait_us: 7,
            })
            .unwrap();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let pending = runtime.block_on(broker.accept()).unwrap();
        identity.execution_environment = Some("peer-0".to_string());
        assert_eq!(pending.identity.as_ref().unwrap(), &identity);
        assert_eq!(pending.destination, "203.0.113.9:443".parse().unwrap());
        let completion = std::thread::spawn(move || {
            runtime.block_on(pending.complete(TcpOpenDecision::Denied(TcpOpenDenial::PolicyDenied)))
        });
        match receiver.recv::<PrimaryToPeer>().unwrap().unwrap().message {
            PrimaryToPeer::TcpDecision { id, decision } => {
                assert_eq!(id, 11);
                assert_eq!(
                    decision,
                    TcpOpenDecision::Denied(TcpOpenDenial::PolicyDenied)
                );
            }
            other => panic!("unexpected {other:?}"),
        }
        assert!(completion.join().unwrap().unwrap().is_none());

        // A loopback destination is refused without reaching mediation.
        sender
            .send(&PeerToPrimary::TcpOpen {
                id: 12,
                destination: "127.0.0.1:8080".parse().unwrap(),
                identity: Ok(identity).into(),
                socket: openshell_isolation_interface::contract::NetworkSocketMetadata {
                    socket_cookie: 3,
                    nonblocking: false,
                    process_generation: 4,
                },
                notification_to_queue_us: 0,
                queue_wait_us: 0,
            })
            .unwrap();
        match receiver.recv::<PrimaryToPeer>().unwrap().unwrap().message {
            PrimaryToPeer::TcpDecision { id: 12, decision } => assert_eq!(
                decision,
                TcpOpenDecision::Denied(TcpOpenDenial::InvalidDestination)
            ),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn allowed_open_relays_the_peer_stream_to_mediation() {
        let (_barrier, hub, mut channels) = joined_hub(1);
        let broker = hub.broker.clone();
        let (sender, receiver) = &mut channels[0];
        sender
            .send(&PeerToPrimary::TcpOpen {
                id: 21,
                destination: "203.0.113.9:443".parse().unwrap(),
                identity:
                    openshell_sandbox_backend::boundary_protocol::BinaryIdentityWire::Failed {
                        message: "unresolved".to_string(),
                    },
                socket: openshell_isolation_interface::contract::NetworkSocketMetadata {
                    socket_cookie: 1,
                    nonblocking: false,
                    process_generation: 2,
                },
                notification_to_queue_us: 0,
                queue_wait_us: 0,
            })
            .unwrap();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let pending = runtime.block_on(broker.accept()).unwrap();
        assert!(pending.identity.is_err());
        let completion = std::thread::spawn(move || {
            runtime.block_on(pending.complete(TcpOpenDecision::RelayReady))
        });
        assert!(matches!(
            receiver.recv::<PrimaryToPeer>().unwrap().unwrap().message,
            PrimaryToPeer::TcpDecision {
                id: 21,
                decision: TcpOpenDecision::RelayReady
            }
        ));
        let relay = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let mut workload = TcpStream::connect(relay.local_addr().unwrap()).unwrap();
        let (broker_side, _) = relay.accept().unwrap();
        sender
            .send_with_descriptor(
                &PeerToPrimary::TcpRelay { id: 21 },
                std::os::fd::AsFd::as_fd(&broker_side),
            )
            .unwrap();
        drop(broker_side);
        let mut relayed = completion.join().unwrap().unwrap().unwrap();
        io::Write::write_all(&mut relayed, b"ping").unwrap();
        let mut echoed = [0_u8; 4];
        io::Read::read_exact(&mut workload, &mut echoed).unwrap();
        assert_eq!(&echoed, b"ping");
    }
}
