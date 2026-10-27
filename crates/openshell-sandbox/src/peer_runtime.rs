// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Subordinate runtime of one peer workload container (`openshell-sandbox peer`).
//!
//! The peer runtime is PID 1 of its container. It owns the peer workload's
//! launcher, seccomp broker and Landlock exactly as the primary owns the
//! agent's, inside the peer's own PID namespace and root filesystem, so binary
//! identity is resolved against the peer image. It holds no supervisor
//! credential and serves no endpoint: everything it needs from the boundary
//! arrives from the primary runtime over the private channel described in
//! [`crate::peer_protocol`], and every mediated network operation goes back
//! over it.
//!
//! Losing the primary channel is fatal: the broker refuses further resumes,
//! the workload tree is killed, and the runtime exits non-zero, which ends
//! the container and with it everything left in its PID namespace.

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::os::fd::AsFd as _;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, mpsc};
use std::time::{Duration, Instant};

use openshell_core::provider_credentials::ProviderCredentialState;
use openshell_isolation_interface::contract::{DnsTransport, TcpOpenDecision, TcpOpenDenial};
use openshell_sandbox_backend::boundary_protocol::{BinaryIdentityWire, ExitStatusWire};
use openshell_sandbox_backend::peer_workloads::{
    PEER_BOOT_DIR, PEER_CONNECT_TIMEOUT_SECS, PEER_CONTROL_DIR, PEER_SOCKET_FILE, PEER_TOKEN_BYTES,
    PEER_TOKEN_FILE,
};
use tokio::sync::oneshot;

use crate::boundary_io::BoundaryRuntimeState;
use crate::linux::socket_registry::SocketIdentity;
use crate::network_broker::{
    DnsAdmissionForwarder, FORWARDED_DNS_ADMISSIONS_PER_PEER, NETWORK_DECISION_TIMEOUT,
    NetworkBroker,
};
use crate::peer_protocol::{self, PeerSender, PeerStart, PeerToPrimary, PrimaryToPeer};

/// Backoff between attempts to reach a primary that is not listening yet.
const CONNECT_RETRY_INTERVAL: Duration = Duration::from_millis(100);
/// Bound on one DNS admission round trip; the workload's socket call waits
/// for it.
const DNS_ADMISSION_TIMEOUT: Duration = Duration::from_secs(5);
/// How often the control loop observes a pending termination signal.
const CONTROL_POLL_INTERVAL: Duration = Duration::from_millis(100);
/// How long a reaped workload's exit status may take to be recorded.
const EXIT_STATUS_SETTLE: Duration = Duration::from_millis(500);
const PROCESS_TREE_POLL_INTERVAL: Duration = Duration::from_millis(25);

/// The one-use token consumed from the peer's boot directory. Deliberately
/// not `Debug` or `Clone`.
pub struct PeerToken(String);

/// Read and unlink the token the bootstrap init container staged.
///
/// # Errors
///
/// Fails when the token is missing, malformed, or cannot be removed.
pub fn consume_token(boot_dir: &Path) -> Result<PeerToken, String> {
    let path = boot_dir.join(PEER_TOKEN_FILE);
    let metadata = std::fs::symlink_metadata(&path)
        .map_err(|error| format!("read peer token {}: {error}", path.display()))?;
    let expected = PEER_TOKEN_BYTES * 2;
    if !metadata.is_file() || metadata.len() != u64::try_from(expected).unwrap_or(u64::MAX) {
        return Err(format!(
            "peer token {} must be a regular file of {expected} bytes",
            path.display()
        ));
    }
    let token = std::fs::read_to_string(&path)
        .map_err(|error| format!("read peer token {}: {error}", path.display()))?;
    // Unlink before validating so a rejected token is still consumed.
    std::fs::remove_file(&path)
        .map_err(|error| format!("consume peer token {}: {error}", path.display()))?;
    if token.len() != expected
        || !token
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(format!(
            "peer token must be {expected} lowercase hex characters"
        ));
    }
    Ok(PeerToken(token))
}

/// Consume the token from the fixed peer boot directory.
///
/// # Errors
///
/// See [`consume_token`].
pub fn consume_staged_token() -> Result<PeerToken, String> {
    consume_token(Path::new(PEER_BOOT_DIR))
}

/// Events the control loop acts on, from the primary channel and from the
/// workload.
enum PeerEvent {
    Start(Box<PeerStart>),
    Freeze,
    Thaw,
    Terminate { enforcement_lost: bool },
    ChannelLost(String),
    Exited(Result<ExitStatusWire, String>),
    Fatal(String),
}

/// State shared by the channel reader, the TCP forwarder and the DNS
/// forwarder.
struct PeerChannel {
    sender: PeerSender,
    next_id: AtomicU64,
    opens: Mutex<HashMap<u64, oneshot::Sender<TcpOpenDecision>>>,
    admissions: Mutex<HashMap<u64, mpsc::SyncSender<Option<i32>>>>,
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn duration_micros(duration: Duration) -> u64 {
    u64::try_from(duration.as_micros()).unwrap_or(u64::MAX)
}

/// Run the peer runtime until its workload ends or the boundary ends it.
///
/// # Errors
///
/// Returns an error, and so exits non-zero, when the runtime cannot join the
/// boundary, loses the primary, or its workload exits on its own.
pub fn run(token: PeerToken, qualification: crate::RuntimeQualification) -> Result<(), String> {
    crate::boundary_server::install_boundary_signal_handlers()?;
    crate::boundary_server::make_boundary_nondumpable()?;
    crate::boundary_server::disable_core_dumps()?;
    crate::sandbox::apply_supervisor_startup_hardening()
        .map_err(|error| format!("install peer process prelude: {error}"))?;
    if nix::unistd::getpid().as_raw() != 1 {
        rustix::process::set_child_subreaper(Some(rustix::process::getpid()))
            .map_err(|error| format!("become child subreaper: {error}"))?;
    }
    crate::managed_children::start_orphan_reaper()
        .map_err(|error| format!("start peer orphan reaper: {error}"))?;
    let (launcher, listener) = crate::linux::workload_launcher::start()
        .map_err(|error| format!("start peer workload launcher: {error}"))?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|error| format!("create peer runtime: {error}"))?;

    let deadline = Instant::now() + Duration::from_secs(PEER_CONNECT_TIMEOUT_SECS);
    let socket = Path::new(PEER_CONTROL_DIR).join(PEER_SOCKET_FILE);
    let stream = connect_primary(&socket, deadline)?;
    let (sender, mut receiver) =
        peer_protocol::split(stream).map_err(|error| format!("split peer channel: {error}"))?;
    sender
        .send(&PeerToPrimary::Hello {
            token: token.0,
            qualification: qualification.into(),
        })
        .map_err(|error| format!("send peer hello: {error}"))?;
    receiver
        .set_read_timeout(Some(deadline.saturating_duration_since(Instant::now())))
        .map_err(|error| format!("bound peer welcome wait: {error}"))?;
    let protected_control_port = match receiver.recv::<PrimaryToPeer>() {
        Ok(Some(frame)) => match frame.message {
            PrimaryToPeer::Welcome {
                protected_control_port,
            } => protected_control_port,
            other => return Err(format!("primary answered peer hello with {other:?}")),
        },
        Ok(None) => return Err("primary refused the peer runtime".to_string()),
        Err(error) => return Err(format!("wait for primary welcome: {error}")),
    };
    receiver
        .set_read_timeout(None)
        .map_err(|error| format!("clear peer channel timeout: {error}"))?;

    let channel = Arc::new(PeerChannel {
        sender,
        next_id: AtomicU64::new(1),
        opens: Mutex::new(HashMap::new()),
        admissions: Mutex::new(HashMap::new()),
    });
    let broker = NetworkBroker::start_peer(
        listener,
        protected_control_port,
        Arc::new(PeerDnsForwarder::new(channel.clone())),
    )
    .map_err(|error| format!("start peer network broker: {error}"))?;
    let (events_tx, events_rx) = mpsc::channel();
    {
        let channel = channel.clone();
        let events = events_tx.clone();
        std::thread::Builder::new()
            .name("openshell-peer-channel".to_string())
            .spawn(move || read_primary(&mut receiver, &channel, &events))
            .map_err(|error| format!("start peer channel reader: {error}"))?;
    }
    runtime.spawn(forward_tcp_opens(
        broker.clone(),
        channel.clone(),
        events_tx.clone(),
    ));
    channel
        .sender
        .send(&PeerToPrimary::Ready)
        .map_err(|error| format!("report peer ready: {error}"))?;
    tracing::info!("Peer runtime joined the sandbox boundary");

    let mut control = PeerControl {
        broker,
        launcher,
        runtime,
        channel,
        events: events_tx,
        workload: None,
    };
    control.run(&events_rx)
}

/// Connect to the primary's socket, which appears once the primary runtime
/// reaches its peer barrier.
fn connect_primary(socket: &Path, deadline: Instant) -> Result<UnixStream, String> {
    loop {
        match UnixStream::connect(socket) {
            Ok(stream) => return Ok(stream),
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused
                ) && Instant::now() < deadline =>
            {
                std::thread::sleep(CONNECT_RETRY_INTERVAL);
            }
            Err(error) => {
                return Err(format!(
                    "connect to the primary runtime at {}: {error}",
                    socket.display()
                ));
            }
        }
    }
}

fn read_primary(
    receiver: &mut peer_protocol::PeerReceiver,
    channel: &PeerChannel,
    events: &mpsc::Sender<PeerEvent>,
) {
    let lost = loop {
        let frame = match receiver.recv::<PrimaryToPeer>() {
            Ok(Some(frame)) => frame,
            Ok(None) => break "primary runtime closed the peer channel".to_string(),
            Err(error) => break format!("read peer channel: {error}"),
        };
        let event = match frame.message {
            PrimaryToPeer::Start(start) => PeerEvent::Start(start),
            PrimaryToPeer::Freeze => PeerEvent::Freeze,
            PrimaryToPeer::Thaw => PeerEvent::Thaw,
            PrimaryToPeer::Terminate { enforcement_lost } => {
                PeerEvent::Terminate { enforcement_lost }
            }
            PrimaryToPeer::TcpDecision { id, decision } => {
                // An unknown ID is an open this runtime already abandoned.
                let waiter = lock(&channel.opens).remove(&id);
                if let Some(waiter) = waiter {
                    let _ = waiter.send(decision);
                }
                continue;
            }
            PrimaryToPeer::DnsAdmitResult { id, errno } => {
                let waiter = lock(&channel.admissions).remove(&id);
                if let Some(waiter) = waiter {
                    let _ = waiter.send(errno);
                }
                continue;
            }
            PrimaryToPeer::Welcome { .. } => {
                break "primary repeated its welcome".to_string();
            }
        };
        if events.send(event).is_err() {
            return;
        }
    };
    // Release every waiter at once; their callers fail closed.
    lock(&channel.opens).clear();
    lock(&channel.admissions).clear();
    let _ = events.send(PeerEvent::ChannelLost(lost));
}

/// Forward every external TCP open of the peer workload to the primary and
/// complete it with the supervisor's decision.
async fn forward_tcp_opens(
    broker: NetworkBroker,
    channel: Arc<PeerChannel>,
    events: mpsc::Sender<PeerEvent>,
) {
    loop {
        let pending = match broker.accept().await {
            Ok(pending) => pending,
            Err(error) => {
                let _ = events.send(PeerEvent::Fatal(format!(
                    "peer network broker stopped: {error}"
                )));
                return;
            }
        };
        let id = channel.next_id.fetch_add(1, Ordering::Relaxed);
        let (decision_tx, decision_rx) = oneshot::channel();
        lock(&channel.opens).insert(id, decision_tx);
        let open = PeerToPrimary::TcpOpen {
            id,
            destination: pending.destination,
            identity: BinaryIdentityWire::from(pending.identity.clone()),
            socket: pending.socket,
            notification_to_queue_us: duration_micros(pending.notification_to_queue),
            queue_wait_us: duration_micros(pending.queued_at.elapsed()),
        };
        if let Err(error) = channel.sender.send(&open) {
            lock(&channel.opens).remove(&id);
            tracing::warn!(%error, "could not forward a peer TCP open to the primary");
            let _ = pending
                .complete(TcpOpenDecision::Denied(TcpOpenDenial::MediationUnavailable))
                .await;
            continue;
        }
        let channel = channel.clone();
        tokio::spawn(async move {
            // The broker's own worker answers the workload with ETIMEDOUT at
            // the same bound; completing afterwards then fails harmlessly.
            let decision = if let Ok(Ok(decision)) =
                tokio::time::timeout(NETWORK_DECISION_TIMEOUT, decision_rx).await
            {
                decision
            } else {
                lock(&channel.opens).remove(&id);
                TcpOpenDecision::Denied(TcpOpenDenial::MediationUnavailable)
            };
            match pending.complete(decision).await {
                Ok(Some(stream)) => {
                    if let Err(error) = channel
                        .sender
                        .send_with_descriptor(&PeerToPrimary::TcpRelay { id }, stream.as_fd())
                    {
                        tracing::warn!(%error, "could not hand a peer relay to the primary");
                    }
                }
                Ok(None) => {}
                Err(error) => {
                    if decision == TcpOpenDecision::RelayReady {
                        let _ = channel.sender.send(&PeerToPrimary::TcpRelayFailed {
                            id,
                            message: error.to_string(),
                        });
                    }
                }
            }
        });
    }
}

/// Registers the peer workload's DNS sockets with the primary's relay and
/// reclaims registrations of sockets that have since closed.
struct PeerDnsForwarder {
    channel: Arc<PeerChannel>,
    admitted: Mutex<PeerAdmissions>,
}

#[derive(Default)]
struct PeerAdmissions {
    udp: HashMap<SocketAddr, u64>,
    tcp: HashMap<SocketAddr, u64>,
}

impl PeerAdmissions {
    fn len(&self) -> usize {
        self.udp.len() + self.tcp.len()
    }

    fn map(&mut self, transport: DnsTransport) -> &mut HashMap<SocketAddr, u64> {
        match transport {
            DnsTransport::Udp => &mut self.udp,
            DnsTransport::Tcp => &mut self.tcp,
        }
    }
}

impl PeerDnsForwarder {
    fn new(channel: Arc<PeerChannel>) -> Self {
        Self {
            channel,
            admitted: Mutex::new(PeerAdmissions::default()),
        }
    }

    /// Withdraw admissions whose sockets no peer workload process holds.
    fn reclaim(&self, admitted: &mut PeerAdmissions) -> io::Result<()> {
        let installed =
            crate::linux::proc_fd::installed_socket_inodes_excluding(std::process::id())?;
        for transport in [DnsTransport::Udp, DnsTransport::Tcp] {
            let map = admitted.map(transport);
            let stale = map
                .iter()
                .filter(|(_, inode)| !installed.contains(inode))
                .map(|(source, _)| *source)
                .collect::<Vec<_>>();
            if stale.is_empty() {
                continue;
            }
            for source in &stale {
                map.remove(source);
            }
            self.channel.sender.send(&PeerToPrimary::DnsRevoke {
                transport,
                sources: stale,
            })?;
        }
        Ok(())
    }
}

impl DnsAdmissionForwarder for PeerDnsForwarder {
    fn admit(
        &self,
        transport: DnsTransport,
        source: SocketAddr,
        socket: SocketIdentity,
    ) -> io::Result<()> {
        let mut admitted = lock(&self.admitted);
        if admitted.len() >= FORWARDED_DNS_ADMISSIONS_PER_PEER
            && !admitted.map(transport).contains_key(&source)
        {
            self.reclaim(&mut admitted)?;
            if admitted.len() >= FORWARDED_DNS_ADMISSIONS_PER_PEER {
                return Err(io::Error::from_raw_os_error(libc::EMFILE));
            }
        }
        let id = self.channel.next_id.fetch_add(1, Ordering::Relaxed);
        let (result_tx, result_rx) = mpsc::sync_channel(1);
        lock(&self.channel.admissions).insert(id, result_tx);
        if let Err(error) = self.channel.sender.send(&PeerToPrimary::DnsAdmit {
            id,
            transport,
            source,
        }) {
            lock(&self.channel.admissions).remove(&id);
            return Err(error);
        }
        match result_rx.recv_timeout(DNS_ADMISSION_TIMEOUT) {
            Ok(None) => {
                admitted.map(transport).insert(source, socket.inode);
                Ok(())
            }
            Ok(Some(errno)) => Err(io::Error::from_raw_os_error(errno)),
            Err(mpsc::RecvTimeoutError::Timeout) => {
                lock(&self.channel.admissions).remove(&id);
                Err(io::Error::from_raw_os_error(libc::ETIMEDOUT))
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "primary runtime is gone",
            )),
        }
    }

    fn revoke(&self, transport: DnsTransport, source: SocketAddr) {
        lock(&self.admitted).map(transport).remove(&source);
        let _ = self.channel.sender.send(&PeerToPrimary::DnsRevoke {
            transport,
            sources: vec![source],
        });
    }
}

/// The running peer workload.
struct PeerWorkload {
    state: Arc<BoundaryRuntimeState>,
    exit: Arc<(Mutex<Option<ExitStatusWire>>, Condvar)>,
}

impl PeerWorkload {
    fn wait_for_exit_status(&self, timeout: Duration) -> Option<ExitStatusWire> {
        let (status, changed) = &*self.exit;
        let deadline = Instant::now() + timeout;
        let mut status = lock(status);
        while status.is_none() {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return None;
            }
            status = changed
                .wait_timeout(status, remaining)
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .0;
        }
        *status
    }

    fn wait_for_tree_exit(&self, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        while self.state.has_owned_processes() && Instant::now() < deadline {
            std::thread::sleep(PROCESS_TREE_POLL_INTERVAL);
        }
        !self.state.has_owned_processes()
    }
}

struct PeerControl {
    broker: NetworkBroker,
    launcher: crate::linux::workload_launcher::WorkloadLauncher,
    runtime: tokio::runtime::Runtime,
    channel: Arc<PeerChannel>,
    events: mpsc::Sender<PeerEvent>,
    workload: Option<PeerWorkload>,
}

impl PeerControl {
    fn run(&mut self, events: &mpsc::Receiver<PeerEvent>) -> Result<(), String> {
        loop {
            if crate::boundary_server::boundary_termination_requested() {
                tracing::info!("Peer runtime frame a termination signal");
                self.terminate(false);
                return Ok(());
            }
            let event = match events.recv_timeout(CONTROL_POLL_INTERVAL) {
                Ok(event) => event,
                Err(mpsc::RecvTimeoutError::Timeout) => continue,
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    return self.fail("peer runtime event sources stopped".to_string());
                }
            };
            match event {
                PeerEvent::Start(start) => self.start(*start),
                PeerEvent::Freeze => {
                    // Refuse workload SIGCONT before stopping the tree.
                    self.broker.set_workload_frozen(true);
                    if let Some(workload) = &self.workload {
                        let _ = workload.state.freeze();
                    }
                }
                PeerEvent::Thaw => {
                    if let Some(workload) = &self.workload {
                        let _ = workload.state.resume();
                    }
                    self.broker.set_workload_frozen(false);
                }
                PeerEvent::Terminate { enforcement_lost } => {
                    self.terminate(enforcement_lost);
                    return Ok(());
                }
                PeerEvent::Exited(result) => {
                    let status = result.unwrap_or(ExitStatusWire::Exited(-1));
                    let _ = self
                        .channel
                        .sender
                        .send(&PeerToPrimary::WorkloadExited { status });
                    // The group ends with the peer workload: kill whatever
                    // the workload left behind and stop the container.
                    if let Some(workload) = &self.workload {
                        workload.state.deactivate();
                    }
                    return Err(format!("peer workload exited on its own ({status:?})"));
                }
                PeerEvent::ChannelLost(reason) => {
                    self.broker.set_workload_frozen(true);
                    if let Some(workload) = &self.workload {
                        workload.state.deactivate();
                    }
                    return Err(format!("peer runtime lost the primary runtime: {reason}"));
                }
                PeerEvent::Fatal(message) => return self.fail(message),
            }
        }
    }

    fn fail(&self, message: String) -> Result<(), String> {
        let _ = self.channel.sender.send(&PeerToPrimary::Failed {
            message: message.clone(),
        });
        self.broker.set_workload_frozen(true);
        if let Some(workload) = &self.workload {
            workload.state.deactivate();
        }
        self.channel.sender.shutdown();
        Err(message)
    }

    fn start(&mut self, start: PeerStart) {
        let reply = if self.workload.is_some() {
            PeerToPrimary::StartFailed {
                message: "peer workload is already running".to_string(),
            }
        } else {
            match self.launch(start) {
                Ok(workload) => {
                    self.workload = Some(workload);
                    PeerToPrimary::Started
                }
                Err(message) => PeerToPrimary::StartFailed { message },
            }
        };
        if let Err(error) = self.channel.sender.send(&reply) {
            tracing::warn!(%error, "could not report peer workload start");
        }
    }

    fn launch(&self, start: PeerStart) -> Result<PeerWorkload, String> {
        let PeerStart {
            command,
            environment,
            policy,
            gpu_requested,
            workload_uid,
            workload_gid,
            ca_cert,
            ca_bundle,
            provider_env_revision,
            provider_env,
            provider_files,
        } = start;
        validate_peer_identity(workload_uid, workload_gid)?;
        let Some((program, args)) = command.split_first() else {
            return Err("peer workload command is empty".to_string());
        };
        self.broker
            .confirm_healthy()
            .map_err(|error| format!("peer network broker unavailable: {error}"))?;
        crate::provider_files::ProviderFiles::validate(&provider_files)
            .map_err(|error| format!("invalid provider files: {error}"))?;
        let ca_file_paths = crate::boundary_server::install_ca_material(ca_cert, ca_bundle)?;
        crate::process::install_boundary_user_environment(environment)?;
        let mut policy: openshell_core::policy::SandboxPolicy = policy.into();
        crate::boundary_server::enrich_gpu_filesystem_paths(&mut policy, gpu_requested);
        policy.process.run_as_user = Some(workload_uid.to_string());
        policy.process.run_as_group = Some(workload_gid.to_string());
        self.broker
            .provider_files()
            .replace(provider_files)
            .map_err(|error| format!("install provider files: {error}"))?;

        let state = BoundaryRuntimeState::new_exclusive_pid_namespace();
        let provider_credentials = ProviderCredentialState::from_child_env_snapshot(
            provider_env_revision,
            provider_env.clone(),
        );
        // No workdir: the workload starts in the runtime's working directory,
        // which the container runtime sets to the peer image's WORKDIR (`/`
        // when the image declares none).
        let mut spawned = self
            .runtime
            .block_on(crate::delegated::spawn_workload(
                &self.launcher,
                program,
                args,
                None,
                0,
                false,
                &policy,
                Arc::new(AtomicU32::new(0)),
                provider_credentials,
                provider_env,
                ca_file_paths,
                Some(state.clone()),
            ))
            .map_err(|error| format!("start peer workload: {error:?}"))?;
        let exit = Arc::new((Mutex::new(None), Condvar::new()));
        let reaper_exit = exit.clone();
        let events = self.events.clone();
        self.runtime.spawn(async move {
            let result = spawned
                .wait()
                .await
                .map(crate::boundary_server::process_status)
                .map_err(|error| format!("wait for peer workload: {error}"));
            if let Ok(status) = &result {
                let (slot, changed) = &*reaper_exit;
                *lock(slot) = Some(*status);
                changed.notify_all();
            }
            let _ = events.send(PeerEvent::Exited(result));
        });
        tracing::info!(program, "Peer workload started");
        Ok(PeerWorkload { state, exit })
    }

    /// Terminate the workload tree as the primary does its own, report the
    /// final status, and close the channel.
    fn terminate(&mut self, enforcement_lost: bool) {
        self.broker.set_workload_frozen(true);
        let Some(workload) = self.workload.take() else {
            self.channel.sender.shutdown();
            return;
        };
        // Enforcement-loss termination applies only to a frozen tree; a tree
        // that was never frozen still gets the graceful path.
        let began = enforcement_lost && workload.state.begin_enforcement_loss_termination();
        if !began {
            let _ = workload.state.begin_termination();
        }
        if !workload.wait_for_tree_exit(crate::boundary_server::ENFORCEMENT_LOSS_TERMINATION_GRACE)
        {
            workload.state.force_kill();
            if !workload.wait_for_tree_exit(crate::boundary_server::FORCE_KILL_REAP_TIMEOUT) {
                tracing::error!("peer workload processes remain after forced termination");
            }
        }
        let status = workload
            .wait_for_exit_status(EXIT_STATUS_SETTLE)
            .unwrap_or(ExitStatusWire::Signaled(libc::SIGKILL));
        let _ = self
            .channel
            .sender
            .send(&PeerToPrimary::WorkloadExited { status });
        self.channel.sender.shutdown();
    }
}

/// The peer runtime runs as the boundary's resolved workload identity, like
/// the primary; the primary also checks it through `SO_PEERCRED`.
#[allow(clippy::similar_names)]
fn validate_peer_identity(uid: u32, gid: u32) -> Result<(), String> {
    let uids =
        nix::unistd::getresuid().map_err(|error| format!("measure peer identity: {error}"))?;
    let gids =
        nix::unistd::getresgid().map_err(|error| format!("measure peer identity: {error}"))?;
    if [uids.real, uids.effective, uids.saved]
        .iter()
        .any(|value| value.as_raw() != uid)
        || [gids.real, gids.effective, gids.saved]
            .iter()
            .any(|value| value.as_raw() != gid)
    {
        return Err(format!(
            "peer runtime identity does not match resolved workload {uid}:{gid}"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;

    #[test]
    fn token_is_consumed_even_when_rejected() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join(PEER_TOKEN_FILE);
        std::fs::write(&path, "0f".repeat(32)).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400)).unwrap();
        let token = consume_token(directory.path()).unwrap();
        assert_eq!(token.0, "0f".repeat(32));
        assert!(!path.exists());
        assert!(consume_token(directory.path()).is_err());

        std::fs::write(&path, "0F".repeat(32)).unwrap();
        assert!(consume_token(directory.path()).is_err());
        assert!(!path.exists(), "a malformed token is still consumed");

        std::fs::write(&path, "0f".repeat(31)).unwrap();
        assert!(consume_token(directory.path()).is_err());
    }

    #[test]
    fn primary_connection_waits_for_the_socket_and_then_gives_up() {
        let directory = tempfile::tempdir().unwrap();
        let socket = directory.path().join(PEER_SOCKET_FILE);
        let error =
            connect_primary(&socket, Instant::now() + Duration::from_millis(200)).unwrap_err();
        assert!(error.contains("connect to the primary runtime"), "{error}");

        let listener_path = socket.clone();
        let listener = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(150));
            let listener = std::os::unix::net::UnixListener::bind(&listener_path).unwrap();
            listener.accept().unwrap()
        });
        connect_primary(&socket, Instant::now() + Duration::from_secs(5)).unwrap();
        listener.join().unwrap();
    }

    struct ChannelPair {
        channel: Arc<PeerChannel>,
        events: mpsc::Receiver<PeerEvent>,
        primary_sender: PeerSender,
        primary_receiver: peer_protocol::PeerReceiver,
    }

    /// A peer channel whose reader runs as in production, and the primary's
    /// end of it.
    fn channel_pair() -> ChannelPair {
        let (peer, primary) = UnixStream::pair().unwrap();
        let (sender, mut peer_receiver) = peer_protocol::split(peer).unwrap();
        let (primary_sender, primary_receiver) = peer_protocol::split(primary).unwrap();
        let channel = Arc::new(PeerChannel {
            sender,
            next_id: AtomicU64::new(1),
            opens: Mutex::new(HashMap::new()),
            admissions: Mutex::new(HashMap::new()),
        });
        let (events_tx, events) = mpsc::channel();
        let reader_channel = channel.clone();
        std::thread::spawn(move || read_primary(&mut peer_receiver, &reader_channel, &events_tx));
        ChannelPair {
            channel,
            events,
            primary_sender,
            primary_receiver,
        }
    }

    fn socket(inode: u64) -> SocketIdentity {
        SocketIdentity {
            listener_generation: 1,
            inode,
            cookie: inode,
        }
    }

    #[test]
    fn dns_admission_round_trips_through_the_primary() {
        let ChannelPair {
            channel,
            events,
            primary_sender,
            mut primary_receiver,
        } = channel_pair();
        let primary = std::thread::spawn(move || {
            for errno in [None, Some(libc::EADDRINUSE)] {
                let frame = primary_receiver.recv::<PeerToPrimary>().unwrap().unwrap();
                let PeerToPrimary::DnsAdmit { id, transport, .. } = frame.message else {
                    panic!("expected a DNS admission, got {:?}", frame.message);
                };
                assert_eq!(transport, DnsTransport::Udp);
                primary_sender
                    .send(&PrimaryToPeer::DnsAdmitResult { id, errno })
                    .unwrap();
            }
            (primary_sender, primary_receiver)
        });
        let forwarder = PeerDnsForwarder::new(channel);
        let source: SocketAddr = "127.0.0.1:41000".parse().unwrap();
        forwarder
            .admit(DnsTransport::Udp, source, socket(7))
            .unwrap();
        assert_eq!(lock(&forwarder.admitted).udp.get(&source), Some(&7));
        let error = forwarder
            .admit(
                DnsTransport::Udp,
                "127.0.0.1:41001".parse().unwrap(),
                socket(8),
            )
            .unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::EADDRINUSE));
        assert_eq!(lock(&forwarder.admitted).len(), 1);

        let (primary_sender, mut primary_receiver) = primary.join().unwrap();
        forwarder.revoke(DnsTransport::Udp, source);
        let frame = primary_receiver.recv::<PeerToPrimary>().unwrap().unwrap();
        assert!(
            frame.message
                == PeerToPrimary::DnsRevoke {
                    transport: DnsTransport::Udp,
                    sources: vec![source],
                }
        );

        // Losing the primary is reported once and fails later admissions.
        drop((primary_sender, primary_receiver));
        match events.recv_timeout(Duration::from_secs(5)) {
            Ok(PeerEvent::ChannelLost(_)) => {}
            _ => panic!("channel loss was not reported"),
        }
        assert!(
            forwarder
                .admit(DnsTransport::Tcp, source, socket(9))
                .is_err()
        );
    }

    #[test]
    fn dns_admissions_of_closed_sockets_are_reclaimed_at_the_bound() {
        let ChannelPair {
            channel,
            events: _events,
            primary_sender,
            mut primary_receiver,
        } = channel_pair();
        let forwarder = PeerDnsForwarder::new(channel);
        {
            let mut admitted = lock(&forwarder.admitted);
            for port in 0..FORWARDED_DNS_ADMISSIONS_PER_PEER {
                // Inode 0 is never installed, so every entry is stale.
                admitted.udp.insert(
                    SocketAddr::from(([127, 0, 0, 1], 20_000 + u16::try_from(port).unwrap())),
                    0,
                );
            }
        }
        let primary = std::thread::spawn(move || {
            let frame = primary_receiver.recv::<PeerToPrimary>().unwrap().unwrap();
            let PeerToPrimary::DnsRevoke { transport, sources } = frame.message else {
                panic!("expected reclamation first, got {:?}", frame.message);
            };
            assert_eq!(transport, DnsTransport::Udp);
            assert_eq!(sources.len(), FORWARDED_DNS_ADMISSIONS_PER_PEER);
            let frame = primary_receiver.recv::<PeerToPrimary>().unwrap().unwrap();
            let PeerToPrimary::DnsAdmit { id, .. } = frame.message else {
                panic!("expected the admission, got {:?}", frame.message);
            };
            primary_sender
                .send(&PrimaryToPeer::DnsAdmitResult { id, errno: None })
                .unwrap();
        });
        forwarder
            .admit(
                DnsTransport::Udp,
                "127.0.0.1:41000".parse().unwrap(),
                socket(3),
            )
            .unwrap();
        primary.join().unwrap();
        assert_eq!(lock(&forwarder.admitted).len(), 1);
    }

    #[test]
    fn reader_routes_decisions_and_lifecycle_to_their_owners() {
        let ChannelPair {
            channel,
            events,
            primary_sender,
            primary_receiver: _primary_receiver,
        } = channel_pair();
        let (decision_tx, decision_rx) = oneshot::channel();
        lock(&channel.opens).insert(5, decision_tx);
        primary_sender
            .send(&PrimaryToPeer::TcpDecision {
                id: 5,
                decision: TcpOpenDecision::RelayReady,
            })
            .unwrap();
        // A decision for an abandoned open is dropped, not misrouted.
        primary_sender
            .send(&PrimaryToPeer::TcpDecision {
                id: 6,
                decision: TcpOpenDecision::RelayReady,
            })
            .unwrap();
        primary_sender.send(&PrimaryToPeer::Freeze).unwrap();
        primary_sender
            .send(&PrimaryToPeer::Terminate {
                enforcement_lost: true,
            })
            .unwrap();
        assert!(matches!(
            events.recv_timeout(Duration::from_secs(5)),
            Ok(PeerEvent::Freeze)
        ));
        assert!(matches!(
            events.recv_timeout(Duration::from_secs(5)),
            Ok(PeerEvent::Terminate {
                enforcement_lost: true
            })
        ));
        assert_eq!(
            decision_rx.blocking_recv().unwrap(),
            TcpOpenDecision::RelayReady
        );
        // A second welcome is a protocol violation that ends the channel.
        primary_sender
            .send(&PrimaryToPeer::Welcome {
                protected_control_port: None,
            })
            .unwrap();
        assert!(matches!(
            events.recv_timeout(Duration::from_secs(5)),
            Ok(PeerEvent::ChannelLost(_))
        ));
    }
}
