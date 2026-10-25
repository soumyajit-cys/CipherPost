# Capture Placement

This guide outlines how to position the CipherPost sensor to capture SMTP/IMAP/POP3 traffic.

## Methods

### 1. Host-Mode Capture
The sensor runs directly on the same host as the mail server.
- **Pros**: Simplest setup; sees loopback traffic easily.
- **Cons**: Consumes resources on the mail server; risks capturing unrelated traffic if not filtered properly.
- **Requirements**: `CAP_NET_RAW` and `CAP_NET_ADMIN`.

### 2. Mirror / SPAN Port
The sensor runs on a dedicated machine that receives a copy of traffic from a switch via SPAN port.
- **Pros**: Zero impact on the mail server performance; isolates analysis.
- **Cons**: Requires network-level configuration (managed switches/TAP).
- **Requirements**: Dedicated hardware or VM connected to the mirrored port.

### 3. Container Sidecar
The sensor runs in a container sharing the network namespace with the mail server.
- **Pros**: Easy to deploy in Kubernetes; shares network.
- **Cons**: Requires container orchestration-specific setup.
- **Requirements**: `networkMode: host`.

## Visibility & Limitations

### TLS 1.3
CipherPost observes the TLS handshake. In TLS 1.3, the certificate is **encrypted** and thus not visible to a passive sensor. However, the sensor still sees the cipher suite negotiation, server name indication (SNI) in the ClientHello (unless ECH is used), and session metadata.

### Downstream-Strip
If there is a proxy (like a load balancer) terminating TLS between the capture point and the mail server, the sensor will only see the decrypted traffic. It must be placed *after* TLS termination to see plaintext traffic.

## Required Capabilities
- `CAP_NET_RAW`: To capture raw packets.
- `CAP_NET_ADMIN`: To manage interface filters and socket options.

## Checklist for Bidirectional Capture
- [ ] Can capture see client-to-server (submission)?
- [ ] Can capture see server-to-client (response)?
- [ ] Are TLS handshakes correctly parsed?
- [ ] Are certificate chains correctly identified (when in TLS 1.2 or plaintext)?
