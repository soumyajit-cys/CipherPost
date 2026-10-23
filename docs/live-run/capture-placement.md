# Capture Placement

This guide outlines how to position CipherPost to capture SMTP/IMAP/POP3 traffic.

## Methods

### 1. Host-Mode
The sensor runs directly on the host.
- **Pros**: Simplest setup, sees loopback traffic.
- **Cons**: Consumes resources on the host, risks capturing irrelevant traffic if not filtered.
- **Requirements**: `CAP_NET_RAW` and `CAP_NET_ADMIN`.

### 2. Mirror / SPAN
The sensor runs on a dedicated machine receiving traffic via a mirror port.
- **Pros**: Zero impact on the mail server, isolates analysis.
- **Cons**: Requires network-level configuration ( car).
- **Requirements**: way hardware or VM.

### 3. Container Sidecar
The sensor runs in a container sharing the network namespace with the mail server.
- **Pros**: Easy to deploy in Kubernetes, shares network.
- **Cons**: Requires container-specific setup.
- **Requirements**: `networkMode: host`.

## Visibility & Limitations

### TLS 1.3
CipherPost observes the TLS handshake. In TLS 1.3, many extensions are encrypted, but the sensor still sees the certificate (if not encrypted) and cipher suite negotiation.

### Downstream-Strip
If a proxy or load balancer strips TLS encryption between the capture point and the mail server, CipherPost will only see the decrypted traffic. It must be placed *after* TLS termination to see plaintext.

## Required Capabilities
- `CAP_NET_RAW`: To capture raw packets.
- `CAP_NET_ADMIN`: To manage interface filters and socket options.

## Checklist for Bidirectional Capture
- [ ] Can capture see client-to-server (submission)?
- [ ] Can capture see server-to-client (response)?
- [ ] Are TLS handshakes correctly parsed?
- [ ] Are certificate chains correctly identified?
