// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "e2e-kubernetes")]

//! Regular pod containers share localhost while retaining the OpenShell fence.
//! Run with the existing supervisor sidecar topology Helm overlay.

use std::io::Write;

use openshell_e2e::harness::sandbox::SandboxGuard;
use tempfile::NamedTempFile;

#[tokio::test]
async fn regular_workloads_share_localhost_without_egress_bypass() {
    let mut policy = NamedTempFile::new().unwrap();
    policy
        .write_all(
            br#"version: 1
filesystem_policy:
  include_workdir: true
  read_only: [/usr, /bin, /lib, /proc, /dev/urandom, /app, /etc, /var/log]
  read_write: [/sandbox, /tmp, /dev/null]
landlock:
  compatibility: best_effort
process:
  run_as_user: "1000"
  run_as_group: "1000"
network_policies: {}
"#,
        )
        .unwrap();
    let peer = r#"
import os, socket, threading, time
assert not os.path.exists('/var/run/secrets/openshell/token')
try:
    socket.create_connection(('1.1.1.1', 443), timeout=2).close()
except OSError:
    pass
else:
    raise AssertionError('direct egress bypassed OpenShell')
def callback():
    for _ in range(300):
        try:
            with socket.create_connection(('127.0.0.1', 17480), timeout=1) as c:
                c.sendall(b'peer-to-agent')
                assert c.recv(128) == b'agent-reply'
            open('/sandbox/peer-callback', 'w').write('ok')
            return
        except OSError:
            time.sleep(.1)
    raise AssertionError('agent localhost listener unavailable')
threading.Thread(target=callback, daemon=True).start()
s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind(('127.0.0.1',17482)); s.listen()
while True:
    c,_=s.accept()
    with c:
        assert c.recv(128) == b'agent-to-peer'
        c.sendall(b'peer-reply')
"#;
    let config = serde_json::json!({"kubernetes": {"containers": {"workloads": [{
        "name": "mesh-peer", "image": "python:3.12-alpine",
        "command": ["python3", "-u", "-c", peer]
    }]}}})
    .to_string();
    let mut sandbox = SandboxGuard::create(&[
        "--from",
        "python:3.12-alpine",
        "--policy",
        policy.path().to_str().unwrap(),
        "--driver-config-json",
        &config,
    ])
    .await
    .expect("create a sandbox with a regular peer container");
    let output = sandbox
        .exec(&[
            "python3",
            "-c",
            r#"
import pathlib, socket, threading, time
def reply():
    s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
    s.bind(('127.0.0.1',17480)); s.listen(); s.settimeout(30)
    c,_=s.accept()
    with c:
        assert c.recv(128) == b'peer-to-agent'
        c.sendall(b'agent-reply')
    s.close()
t=threading.Thread(target=reply); t.start()
for _ in range(300):
    try:
        with socket.create_connection(('127.0.0.1',17482), timeout=1) as c:
            c.sendall(b'agent-to-peer')
            assert c.recv(128) == b'peer-reply'
        break
    except OSError: time.sleep(.1)
else: raise AssertionError('peer localhost listener unavailable')
t.join()
for _ in range(100):
    p=pathlib.Path('/sandbox/peer-callback')
    if p.exists() and p.read_text() == 'ok': break
    time.sleep(.1)
assert p.read_text() == 'ok', 'peer callback did not finish writing the shared workspace'
print('bidirectional-localhost-and-egress-fence-ok')
"#,
        ])
        .await
        .expect("communicate in both directions over pod localhost");
    assert!(output.contains("bidirectional-localhost-and-egress-fence-ok"));
    sandbox.cleanup().await;
}
