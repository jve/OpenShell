// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "e2e-kubernetes")]

//! Peer workload containers share Pod localhost and a declared `emptyDir`
//! with `agent` while staying inside the sandbox policy and lifecycle.
//!
//! The peer runs a different image from the agent. It resolves and reaches a
//! policy-allowed host endpoint through its own DNS relay and the primary
//! runtime's mediation, cannot reach a policy-denied port on the same host,
//! and its abnormal exit terminates the whole sandbox.
//!
//! Run against a gateway with `allow_driver_config` enabled
//! (`deploy/helm/openshell/ci/values-peer-workloads.yaml`), with and without
//! the shared gateway supervisor overlay
//! (`deploy/helm/openshell/ci/values-supervisor.yaml`). The host endpoints
//! need the `host.openshell.internal` alias, which the Kubernetes wrapper
//! enables by default.

use std::io::Write as _;
use std::process::Stdio;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use openshell_e2e::harness::cli::wait_for_sandbox_phase;
use openshell_e2e::harness::sandbox::SandboxGuard;
use tempfile::NamedTempFile;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

const TEST_HOST: &str = "host.openshell.internal";
const PEER_NAME: &str = "mesh-peer";
/// A different image from the agent's (Python 3.13 instead of 3.12), pinned
/// on ghcr.io because anonymous public.ecr.aws pulls from shared CI runners
/// hit data limits.
const PEER_IMAGE: &str = "ghcr.io/astral-sh/uv:0.12.17-python3.13-trixie-slim@sha256:5b7499c3e4048c8f9afcca908c2f2c486923cd441b857976fb6a871e6a090737";
const MESH_DIR: &str = "/tmp/niuu-mesh";
const AGENT_PORT: u16 = 17480;
const PEER_PORT: u16 = 17482;
const MESH_PEER_VALUE: &str = "tcp://127.0.0.1:17480";
const ALLOWED_BODY: &str = "PEER_EGRESS_ALLOWED";
const TERMINATION_TIMEOUT: Duration = Duration::from_mins(3);

/// Host endpoint that counts accepted connections and answers HTTP requests.
struct HostEndpoint {
    port: u16,
    accepted: Arc<AtomicUsize>,
    task: JoinHandle<()>,
}

impl HostEndpoint {
    async fn start() -> Self {
        let listener = TcpListener::bind(("0.0.0.0", 0))
            .await
            .expect("bind host endpoint");
        let port = listener.local_addr().expect("host endpoint address").port();
        let accepted = Arc::new(AtomicUsize::new(0));
        let counter = accepted.clone();
        let task = tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                counter.fetch_add(1, Ordering::SeqCst);
                tokio::spawn(async move {
                    let mut request = Vec::new();
                    let mut buffer = [0_u8; 1024];
                    while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                        match stream.read(&mut buffer).await {
                            Ok(0) | Err(_) => return,
                            Ok(read) => request.extend_from_slice(&buffer[..read]),
                        }
                    }
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{ALLOWED_BODY}",
                        ALLOWED_BODY.len()
                    );
                    let _ = stream.write_all(response.as_bytes()).await;
                    let _ = stream.shutdown().await;
                });
            }
        });
        Self {
            port,
            accepted,
            task,
        }
    }

    fn accepted(&self) -> usize {
        self.accepted.load(Ordering::SeqCst)
    }
}

impl Drop for HostEndpoint {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Allow Python to reach only `allowed_port` on the test host.
fn policy(allowed_port: u16) -> NamedTempFile {
    let mut file = tempfile::Builder::new()
        .suffix(".yaml")
        .tempfile()
        .expect("create policy file");
    write!(
        file,
        r"version: 1
filesystem_policy:
  include_workdir: true
  read_only: [/usr, /lib, /proc, /dev/urandom, /app, /etc, /var/log]
  read_write: [/sandbox, /tmp, /dev/null]
landlock:
  compatibility: best_effort
network_policies:
  peer_workloads:
    name: peer_workloads
    endpoints:
      - host: {TEST_HOST}
        port: {allowed_port}
        protocol: rest
        access: full
    binaries:
      - path: /usr/bin/python*
      - path: /usr/local/bin/python*
      - path: /sandbox/.uv/python/*/bin/python*
"
    )
    .expect("write policy file");
    file.flush().expect("flush policy file");
    file
}

/// The peer workload: wait for the agent, exercise the shared volume, Pod
/// localhost in both directions, policy DNS, and allowed and denied egress,
/// publish a report on the shared volume, then serve until told to die.
fn peer_script(allowed_port: u16, denied_port: u16) -> String {
    format!(
        r#"
import json, os, pathlib, signal, socket, threading, time

mesh = pathlib.Path({MESH_DIR:?})
report = {{}}

def wait_for(path, seconds=600):
    deadline = time.monotonic() + seconds
    while not path.exists():
        if time.monotonic() > deadline:
            raise SystemExit(f"timed out waiting for {{path}}")
        time.sleep(0.1)

def serve_agent():
    server = socket.socket()
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", {PEER_PORT}))
    server.listen()
    while True:
        conn, _ = server.accept()
        with conn:
            if conn.recv(128) == b"agent-to-peer":
                conn.sendall(b"peer-reply")

threading.Thread(target=serve_agent, daemon=True).start()

report["mesh_peer_env"] = os.environ.get("MESH_PEER")
report["token_consumed"] = not os.path.exists("/.openshell/peer-boot/token")
report["no_bootstrap_secret"] = not os.path.exists("/.openshell/bootstrap-input")

wait_for(mesh / "agent-hello")
report["shared_volume"] = (mesh / "agent-hello").read_text() == "hello-from-agent"
workspace_hello = pathlib.Path("/sandbox/agent-workspace-hello")
wait_for(workspace_hello)
report["shared_workspace"] = workspace_hello.read_text() == "hello-from-agent-workspace"

for _ in range(300):
    try:
        with socket.create_connection(("127.0.0.1", {AGENT_PORT}), timeout=1) as conn:
            conn.sendall(b"peer-to-agent")
            report["peer_to_agent"] = conn.recv(128) == b"agent-reply"
        break
    except OSError:
        time.sleep(0.1)
else:
    report["peer_to_agent"] = False

try:
    answers = socket.getaddrinfo({TEST_HOST:?}, {allowed_port}, type=socket.SOCK_STREAM)
    report["dns"] = len(answers) > 0
except OSError as error:
    report["dns"] = f"failed: {{error}}"

try:
    with socket.create_connection(({TEST_HOST:?}, {allowed_port}), timeout=15) as conn:
        conn.sendall(f"GET / HTTP/1.1\r\nHost: {TEST_HOST}:{allowed_port}\r\nConnection: close\r\n\r\n".encode())
        conn.settimeout(15)
        response = b""
        while chunk := conn.recv(4096):
            response += chunk
    report["allowed_egress"] = {ALLOWED_BODY:?}.encode() in response
except OSError as error:
    report["allowed_egress"] = f"failed: {{error}}"

try:
    with socket.create_connection(({TEST_HOST:?}, {denied_port}), timeout=10) as conn:
        conn.sendall(b"GET / HTTP/1.1\r\nConnection: close\r\n\r\n")
        conn.settimeout(10)
        report["denied_egress"] = conn.recv(4096) == b""
except OSError:
    report["denied_egress"] = True

tmp = mesh / "peer-report.tmp"
tmp.write_text(json.dumps(report))
tmp.rename(mesh / "peer-report.json")

wait_for(mesh / "peer-die", seconds=3600)
os.kill(os.getpid(), signal.SIGKILL)
"#
    )
}

/// The agent side: share a file, answer the peer's localhost call, call the
/// peer's localhost listener, and print the peer's report.
const AGENT_SCRIPT: &str = r#"
import json, pathlib, socket, threading, time

mesh = pathlib.Path("/tmp/niuu-mesh")

def reply():
    server = socket.socket()
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", 17480))
    server.listen()
    server.settimeout(120)
    conn, _ = server.accept()
    with conn:
        if conn.recv(128) == b"peer-to-agent":
            conn.sendall(b"agent-reply")
    server.close()

listener = threading.Thread(target=reply)
listener.start()
pathlib.Path("/sandbox/agent-workspace-hello").write_text("hello-from-agent-workspace")
(mesh / "agent-hello").write_text("hello-from-agent")

for _ in range(1200):
    try:
        with socket.create_connection(("127.0.0.1", 17482), timeout=1) as conn:
            conn.sendall(b"agent-to-peer")
            agent_to_peer = conn.recv(128) == b"peer-reply"
        break
    except OSError:
        time.sleep(0.1)
else:
    agent_to_peer = False

listener.join()
report_path = mesh / "peer-report.json"
for _ in range(1200):
    if report_path.exists():
        break
    time.sleep(0.1)
report = json.loads(report_path.read_text())
report["agent_to_peer"] = agent_to_peer
print("PEER_REPORT " + json.dumps(report, sort_keys=True))
"#;

fn kubectl_command() -> tokio::process::Command {
    let mut command = tokio::process::Command::new("kubectl");
    if let Ok(context) = std::env::var("OPENSHELL_E2E_KUBE_CONTEXT_ACTIVE")
        && !context.trim().is_empty()
    {
        command.arg("--context").arg(context);
    }
    command
}

/// Run `kubectl <args> -o json`; `None` when `--ignore-not-found` printed
/// nothing.
async fn kubectl_json(args: &[&str]) -> Option<serde_json::Value> {
    let output = kubectl_command()
        .args(args)
        .args(["-o", "json"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await
        .unwrap_or_else(|error| panic!("spawn kubectl {args:?}: {error}"));
    assert!(
        output.status.success(),
        "kubectl {args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    if output.stdout.iter().all(u8::is_ascii_whitespace) {
        return None;
    }
    Some(serde_json::from_slice(&output.stdout).expect("parse kubectl JSON"))
}

/// The workload Pod of an `OpenShell` sandbox, in whichever namespace the
/// workspace mode placed it, if it still exists. The Pod is named after its
/// Sandbox resource.
async fn workload_pod(name: &str) -> Option<serde_json::Value> {
    let list = kubectl_json(&[
        "get",
        "sandboxes.agents.x-k8s.io",
        "--all-namespaces",
        "-l",
        &format!("openshell.ai/sandbox-name={name}"),
    ])
    .await?;
    let resource = match list["items"].as_array().expect("Sandbox items").as_slice() {
        [] => return None,
        [resource] => resource,
        _ => panic!("expected one Sandbox resource for {name}: {list}"),
    };
    let namespace = resource["metadata"]["namespace"]
        .as_str()
        .expect("Sandbox namespace");
    let pod_name = resource["metadata"]["name"].as_str().expect("Sandbox name");
    kubectl_json(&[
        "-n",
        namespace,
        "get",
        "pod",
        pod_name,
        "--ignore-not-found",
    ])
    .await
}

/// Driver config: one peer from a different image sharing `flock-ipc` with
/// the agent.
fn driver_config(allowed_port: u16, denied_port: u16) -> String {
    serde_json::json!({"kubernetes": {
        "volumes": [{"name": "flock-ipc", "empty_dir": {}}],
        "containers": {
            "agent": {"volume_mounts": [
                {"name": "flock-ipc", "mount_path": MESH_DIR, "read_only": false}
            ]},
            "workloads": [{
                "name": PEER_NAME,
                "image": PEER_IMAGE,
                "command": [
                    "/usr/local/bin/python3", "-u", "-c",
                    peer_script(allowed_port, denied_port)
                ],
                "environment": {"MESH_PEER": MESH_PEER_VALUE},
                "resources": {"limits": {"memory": "256Mi"}},
                "volume_mounts": [
                    {"name": "flock-ipc", "mount_path": MESH_DIR, "read_only": false}
                ]
            }]
        }
    }})
    .to_string()
}

/// The admitted Pod runs the peer runtime ahead of `agent`, and the peer's
/// workload environment is not on the Pod.
fn assert_rendered_peer(pod: &serde_json::Value) {
    let containers = pod["spec"]["containers"]
        .as_array()
        .expect("Pod containers")
        .iter()
        .map(|container| container["name"].as_str().expect("container name"))
        .collect::<Vec<_>>();
    assert_eq!(containers, [PEER_NAME, "agent"], "{pod}");
    let peer = &pod["spec"]["containers"][0];
    assert_eq!(peer["image"], PEER_IMAGE);
    assert_eq!(
        peer["command"],
        serde_json::json!(["/.openshell/runtime/openshell-sandbox", "peer"])
    );
    assert!(
        !peer["env"]
            .as_array()
            .into_iter()
            .flatten()
            .any(|entry| entry["name"] == "MESH_PEER"),
        "peer environment must travel in the boundary config, not the Pod: {peer}"
    );
    assert!(
        peer["volumeMounts"]
            .as_array()
            .into_iter()
            .flatten()
            .any(|mount| mount["name"] == "workspace" && mount["mountPath"] == "/sandbox"),
        "peer must share the agent's OpenShell workspace: {peer}"
    );
}

/// Every check the peer and agent report must have passed.
fn assert_peer_report(output: &str) {
    let report = output
        .lines()
        .find_map(|line| line.trim().strip_prefix("PEER_REPORT "))
        .unwrap_or_else(|| panic!("agent printed no peer report:\n{output}"));
    let report: serde_json::Value = serde_json::from_str(report).expect("parse peer report");
    for (check, expected) in [
        ("mesh_peer_env", serde_json::json!(MESH_PEER_VALUE)),
        ("token_consumed", serde_json::json!(true)),
        ("no_bootstrap_secret", serde_json::json!(true)),
        ("shared_volume", serde_json::json!(true)),
        ("shared_workspace", serde_json::json!(true)),
        ("peer_to_agent", serde_json::json!(true)),
        ("agent_to_peer", serde_json::json!(true)),
        ("dns", serde_json::json!(true)),
        ("allowed_egress", serde_json::json!(true)),
        ("denied_egress", serde_json::json!(true)),
    ] {
        assert_eq!(report[check], expected, "peer check {check}: {report}");
    }
}

/// Wait until no container of the sandbox's workload Pod is running.
async fn wait_for_no_running_containers(name: &str) {
    let deadline = tokio::time::Instant::now() + TERMINATION_TIMEOUT;
    loop {
        let pod = workload_pod(name).await.unwrap_or_default();
        let running = pod["status"]["containerStatuses"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|status| !status["state"]["running"].is_null())
            .map(|status| status["name"].as_str().unwrap_or_default().to_string())
            .collect::<Vec<_>>();
        if running.is_empty() {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "containers still running after the peer died: {running:?}"
        );
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

#[tokio::test]
async fn peer_workloads_share_localhost_and_volume_under_sandbox_policy() {
    let allowed = HostEndpoint::start().await;
    let denied = HostEndpoint::start().await;
    let policy = policy(allowed.port);
    let mut sandbox = SandboxGuard::create(&[
        "--policy",
        policy.path().to_str().expect("UTF-8 policy path"),
        "--driver-config-json",
        &driver_config(allowed.port, denied.port),
    ])
    .await
    .expect("create a sandbox with a peer workload container");

    assert_rendered_peer(
        &workload_pod(&sandbox.name)
            .await
            .expect("running sandbox has a workload Pod"),
    );

    let output = sandbox
        .exec(&["python3", "-c", AGENT_SCRIPT])
        .await
        .expect("exchange traffic with the peer over Pod localhost");
    assert_peer_report(&output);
    assert!(
        allowed.accepted() > 0,
        "the allowed host endpoint saw no peer connection"
    );
    assert_eq!(
        denied.accepted(),
        0,
        "a policy-denied peer connection reached the host"
    );

    // An abnormal peer exit ends the whole sandbox group: the agent does not
    // keep running with a missing peer, and no peer survives the agent.
    sandbox
        .exec(&["touch", &format!("{MESH_DIR}/peer-die")])
        .await
        .expect("signal the peer workload to die");
    wait_for_sandbox_phase(&sandbox.name, "Error", TERMINATION_TIMEOUT)
        .await
        .unwrap_or_else(|error| panic!("peer death did not terminate the sandbox:\n{error}"));
    wait_for_no_running_containers(&sandbox.name).await;

    sandbox.cleanup().await;
}

/// Recreating a sandbox under the name of one that is still terminating must
/// wait for the old workload Pod instead of colliding with it. The gateway
/// frees the name when deletion starts, while Kubernetes keeps the old Pod for
/// its grace period; a workload that ignores SIGTERM holds it there.
#[tokio::test]
async fn recreate_under_a_terminating_name_waits_for_the_old_pod() {
    let name = openshell_e2e::harness::sandbox::unique_sandbox_name();
    let first = SandboxGuard::create(&["--name", &name])
        .await
        .expect("create the first generation");
    first
        .exec(&[
            "sh",
            "-c",
            "nohup sh -c 'trap \"\" TERM; while :; do sleep 1; done' >/dev/null 2>&1 &",
        ])
        .await
        .expect("start a workload that ignores SIGTERM");
    let old_pod_uid = workload_pod(&name)
        .await
        .expect("first generation has a workload Pod")["metadata"]["uid"]
        .clone();

    let delete = openshell_e2e::harness::binary::openshell_cmd()
        .args(["sandbox", "delete", &name])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("start deleting the first generation");

    let deadline = tokio::time::Instant::now() + TERMINATION_TIMEOUT;
    let mut second = loop {
        match SandboxGuard::create(&["--name", &name]).await {
            Ok(sandbox) => break sandbox,
            Err(error) if error.to_ascii_lowercase().contains("already") => {
                assert!(
                    tokio::time::Instant::now() < deadline,
                    "the name was never freed: {error}"
                );
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
            Err(error) => panic!("recreating a terminating sandbox name failed: {error}"),
        }
    };
    let new_pod = workload_pod(&name)
        .await
        .expect("second generation has a workload Pod");
    assert_ne!(new_pod["metadata"]["uid"], old_pod_uid, "{new_pod}");
    let output = second
        .exec(&["echo", "second-generation"])
        .await
        .expect("second generation runs");
    assert!(output.contains("second-generation"), "{output}");

    let _ = delete.wait_with_output().await;
    // The first generation is gone; its guard would delete the name, which
    // now belongs to the second.
    std::mem::forget(first);
    second.cleanup().await;
}
