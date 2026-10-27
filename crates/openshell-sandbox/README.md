# Sandbox runtime

`openshell-sandbox` owns the Linux workload isolation mechanisms and their kernel
qualification probes. The `linux` module contains seccomp notifications and child
filters, task-memory access, process-signal mediation, procfs descriptor lookup,
socket identity, Landlock qualification, and the workload launch thread.

`sandbox::linux` composes policy enforcement. The top-level `linux` module owns
the lower-level mechanisms used by that orchestration and the boundary server.
Unsafe kernel ABI, process-launch, and descriptor-ownership operations stay in
this runtime crate behind safe APIs where their contracts can be enforced.

The network broker retains source socket descriptors only while preparing a
workload endpoint. A successful connection or `listen` releases that reference;
the kernel then tracks the lifetime through workload-owned descriptors. Native
`accept` and repeated `listen` preserve the socket's loopback confinement. Closing
the last workload reference to a listener removes it without waiting for registry
collection. Broker source descriptors always use close-on-exec independently of
the workload's requested descriptor flags.

A boundary configured with `RuntimeInitiatedTlsTcp` binds no listener. It dials
only the driver-provided supervisor addresses, which must be concrete,
non-loopback, and share one port, and serves TLS and gRPC over that outbound
connection. It keeps one spare connection that the supervisor has not yet used
and dials a replacement when the supervisor starts HTTP/2 on it or the spare
closes. Live connections keep the same disconnect, freeze, and recovery-deadline
handling as listener mode, and the workload still cannot connect to the control
port.

## Peer workload runtimes

A Kubernetes sandbox may run peer workload containers next to `agent` (see
`openshell_sandbox_backend::peer_workloads` for the shared layout). Each peer
container runs `openshell-sandbox peer`, a subordinate runtime that is PID 1 of
its container. It consumes its one-use token, qualifies its own container (its
synthetic DNS probe uses an ephemeral loopback port, never `127.0.0.53:53`),
and joins the primary runtime over its private control socket
(`peer_protocol`). The peer runtime owns its workload's launcher, seccomp
broker, Landlock and binary identity in its own PID namespace and root
filesystem; it serves no endpoint and holds no supervisor credential.

The primary runs a barrier before it dials or listens for its supervisor: it
accepts exactly one connection per peer socket and unlinks the socket, requires
`SO_PEERCRED` to be the workload identity from outside its own PID namespace
(PID 0) and the token to match the recorded digest, and waits until every peer
reports its broker ready, bounded by `PEER_CONNECT_TIMEOUT_SECS`. Failure at any
step means the boundary is never served.

Mediation stays single-sourced. A peer broker forwards each external TCP open;
the primary queues it in its own broker with the peer's name as the identity's
execution environment and returns the supervisor's decision, and the peer hands
back the relayed stream with `SCM_RIGHTS`. Resolvers accept replies only from
the configured nameserver, so peers serve no DNS relay: a peer broker registers
each workload DNS socket's loopback source with the primary's relay, which then
answers it in the shared network namespace. Admissions are bounded per peer and
reclaimed by the peer once their sockets close.

Peers share the agent's lifecycle. Confirmation requires every peer to be
connected and reports each mechanism only as strong as the weakest runtime
(boolean conjunction, lowest Landlock ABI). `start_agent` starts every peer with
the agent's policy, CA material and provider environment, plus the peer's own
command and environment, before it starts the agent. The peer workload runs in
the peer runtime's working directory, which the container runtime sets to the
peer image's `WORKDIR` (`/` when unset). Freeze, thaw, recovery expiry and
termination propagate to peers, and peers terminate when the agent exits. A peer
runtime that fails or disconnects, or a peer workload that exits on its own,
terminates the agent tree and every other peer, and the primary then exits with
an error so the Pod fails. A peer runtime that loses the primary freezes its
broker, kills its workload tree and exits non-zero. Peer boundaries must use
runtime-initiated supervisor control.

Provider environment updates reach every peer before the agent's snapshot
changes; an update is reported applied only when every peer applied it. A
relay decision always resolves: a peer answers a decision for an open it no
longer tracks with a relay failure, and the primary bounds the wait for a
peer's relayed stream.

Known limitation: peers share the primary's capacity rather than adding their
own. Forwarded TCP opens use the primary broker's single open queue, and the
supervisor's binary-identity pin cache is shared by every execution
environment, so a busy peer can exhaust either for the whole sandbox.
