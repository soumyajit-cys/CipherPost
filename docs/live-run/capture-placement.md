# Capture placement (what each option can and cannot observe)

CipherPost is passive: it reports what the capture point actually saw and
labels everything else `not observable` (see `docs/what-we-cannot-see.md`).
Where you place the capture therefore decides what the tool *can* know.
This page covers the three placement options, TLS 1.3 limits, the
downstream-strip limitation, required capabilities, filtering, and how to
confirm the capture sees both directions of a session.

## Placement options

### 1. Host-mode capture on the mail host

The capture worker runs directly on the mail server (bare metal, or a
container with `network_mode: host`).

- **Can observe**: everything arriving at or leaving the mail host's
  interfaces on the mail ports — both directions of every external and
  local mail session, including loopback-to-the-host traffic only if the
  capture listens on `lo` as well (default interface is `CIPHERPOST_LIVE_IFACE`).
- **Cannot observe**: traffic between two *other* hosts that never touches
  this machine (e.g. client-to-client), and traffic inside containers
  running with their own network namespace (`veth` pairs are visible only
  if you capture the right veth/bridge — see the Docker section).
- **Watch out for**: consuming CPU/memory on the mail server itself, and
  capturing unrelated traffic if the BPF filter is too wide.

### 2. Mirror / SPAN port (dedicated sensor host)

The switch or TAP copies mail VLAN traffic to a sensor NIC; the capture
worker runs on that sensor only.

- **Can observe**: every packet the switch mirrors — typically the full
  bidirectional mail conversation, unmodified, including SYN/FIN/RST.
- **Cannot observe**: anything the mirror session does not deliver (wrong
  VLAN, ingress-only SPAN, oversubscribed mirror dropping packets), and
  traffic that never traverses the switch (host-local loopback).
- **Watch out for**: switch mirror-port drops under load look identical to
  "quiet mail" — check `capinfos`/switch counters when session counts fall.

### 3. Container sidecar sharing the network namespace

The capture container runs in the mail container's network namespace
(compose: `network_mode: "service:mail"`; K8s: same pod).

- **Can observe**: exactly what the mail container's network stack sees:
  packets on the shared namespace's interface(s), including
  container-to-container traffic on the same bridge network and
  host-published traffic after NAT (as seen from inside).
- **Cannot observe**: host traffic on other interfaces, other containers'
  traffic (unless they share the same namespace), and — critically — the
  *pre-NAT* view of Docker-published ports (see next section).
- **Watch out for**: NAT translations change ports/addresses on
  published-port traffic, which can distort 5-tuple-based flow history.

## Docker specifics: published ports go through NAT

When a port is published (`-p 127.0.0.1:587:587`), client connections
terminate through Docker's userland proxy or DNAT rules: on the *host*
interfaces you see the NATed flow, and inside the container you see the
translated one. The two views differ in address/port, so:

- decide **which interface** should see both directions (usually the bridge
  interface inside the lab network, e.g. `eth0` of the compose network, or
  the host's `docker0`/bridge);
- **confirm with tcpdump/tshark before trusting the pipeline**:

```bash
# on the host: is the client->server leg visible pre- or post-NAT?
sudo tcpdump -ni any -c 20 'tcp port 587'
# inside the mail container (docker exec -it cipherpost-mail sh):
tcpdump -ni eth0 -c 20 'tcp port 587'
# decode the same window with tshark to see both handshake legs:
sudo tshark -i any -f 'tcp port 587' -T fields -e ip.src -e tcp.srcport \
  -e ip.dst -e tcp.dstport -e tls.handshake.type -c 20
```

A healthy capture shows *both* the client→server packets (SYN, ClientHello
`tls.handshake.type==1`) and the server→client replies (SYN-ACK,
ServerHello `type==2`) on the interface the capture worker listens on.

## TLS 1.3 visibility (per docs/what-we-cannot-see.md)

- **Certificates are NOT observable passively in TLS 1.3**: the Certificate
  message is encrypted. Cert rules (expired, self-signed, untrusted chain,
  weak signature, short key) **skip** these sessions — they never pass or
  fail on data that was not observed. Out-of-band chain recovery is only
  available via the opt-in `cipherpost probe` (authorized hosts only).
- **Still observable in 1.3**: ClientHello (versions, ciphers, groups,
  key-share offers, SNI unless ECH, ALPN), ServerHello (selected
  version/cipher/group, HRR, downgrade sentinels), handshake timing, and
  any plaintext before STARTTLS.
- TLS 1.0–1.2 handshakes expose certificates in cleartext; the certificate
  rules apply normally there.

## Downstream-strip limitation

A capture point sees only the bytes that reach it. If an on-path attacker
strips the STARTTLS offer **upstream of the sensor**, the offer never
appears in the capture: CipherPost reports absence of TLS
(`plaintext-mail-protocol`) plus plaintext-continuation evidence — it never
reconstructs unseen bytes or alleges a specific stripping event it did not
observe. `starttls-strip-attempt` fires **only** when the offer IS on the
wire (server advertised or client requested) and no TLS handshake follows.
Placing the sensor between the potential stripper and the mail server (not
downstream of it) is what makes strip evidence visible.

## Required capabilities (never full privilege)

The capture needs `CAP_NET_RAW` (raw/AF_PACKET sockets) and
`CAP_NET_ADMIN` (interface/BPF management):

```yaml
# compose
cap_add: [NET_RAW, NET_ADMIN]   # never privileged: true / user: root
```

`deploy/live-run/docker-compose.yml` and `docker/docker-compose.yml` use
exactly these caps with a non-root appuser. If you see `permission denied`
from the capture but the interface exists, the caps are missing — add the
two caps, do not switch to `privileged`.

## Filter to mail ports only

The BPF filter defaults to the mail ports
(`CIPHERPOST_LIVE_BPF_PORTS=25,587,465,110,995,143,993`) and should stay
that narrow:

- on a shared/host-mode capture it prevents capturing unrelated traffic
  (SSH, HTTPS browsing, DNS) that would waste disk and dilute findings;
- raw capture segments are purged on a rolling window
  (`RAW_RETENTION_SECONDS`, default 6 h) — do not widen the filter and then
  extend the window to "keep more": that captures non-mail users' traffic.
- add extra ports only with `CIPHERPOST_LIVE_EXTRA_PORTS` when your mail
  topology genuinely uses nonstandard ports.

## Checklist: confirm you see both directions

Run these **after** starting the lab (or any new capture point) and before
trusting reports. Commands use the lab from `docs/live-run/setup.md`.

1. [ ] **Capture is up**: `GET /api/v1/live/status` shows the agent
   `online` and non-zero packets (or `tcpdump -c 1` on the capture
   interface succeeds).
2. [ ] **Client→server leg visible**:
   `sudo tshark -i <iface> -f 'tcp port 587' -c 5 'tcp.flags.syn==1 && tcp.flags.ack==0'`
   prints the client's SYN when a submission starts.
3. [ ] **Server→client leg visible**: same capture shows the SYN-ACK
   (`tcp.flags.syn==1 && tcp.flags.ack==1`) from the mail server.
4. [ ] **Handshake visible in the pipeline**: send one message via
   `openssl s_client -connect 127.0.0.1:465 ...` (see setup.md) and confirm
   a session appears in `GET /api/v1/sessions?protocol=SMTP`.
5. [ ] **TLS version parsed**: the new session shows a non-null
   `tls_version` (for TLS 1.3 sessions certificate fields stay empty —
   that is correct, not a bug).
6. [ ] **Plaintext leg (negative check)**: on `deliberately-broken`, one
   plaintext SMTP session appears with `tls_version: null` and the
   plaintext evidence, proving absence-of-TLS is detected rather than
   silently dropped.

If step 3 fails while 2 succeeds, you are capturing a one-way mirror
(check SPAN direction) or NAT is splitting the flow (see Docker section).
If both fail, the BPF filter or interface is wrong — fix before the live
run, not during it.
