# Task 5 evidence: label spot-check (2026-10-09)

Five captures drawn with fixed seed `20261009` (`random.Random(20261009).sample(captures, 5)`). Configuration, expected
findings (from manifest, written from lab config), and current tool output
side by side. Owner: fill in the reviewer verdict column.

| Capture | Agreement (config vs tool) | Reviewer verdict |
|---|---|---|
| mail_pop12_implicit995_lab_01.pcap | match (untrusted TP; no-tls FP absent) |  |
| pq_gap_lab_01.pcap | match (no findings; HRR legitimate) |  |
| mail_smtp_self587_lab_01.pcap | match (self-signed + untrusted TP) |  |
| pq_hrr_lab_01.pcap | match (no findings; requested group offered) |  |
| mail_smtp13_implicit465_lab_01.pcap | match (clean TLS 1.3) |  |

## Detail

```
### mail_pop12_implicit995_lab_01.pcap
config: {"harness": "scripts/lab_mail.py", "driver": "scripts/lab_capture.sh", "certs": "scripts/lab_certs.sh", "scenario": "pop12_implicit995", "evidence": "docs/evidence/real-eval.md"}
provenance: complete
expected:
  - session 3 untrusted-certificate-chain present=True: lab CA
  - session 3 no-tls-on-implicit-port present=False: TLS present
tool output:
  - session 0 127.0.0.1:58026->127.0.0.1:995 tls=None findings=[]
  - session 1 127.0.0.1:58030->127.0.0.1:995 tls=None findings=[]
  - session 2 127.0.0.1:58044->127.0.0.1:995 tls=None findings=[]
  - session 3 127.0.0.1:58056->127.0.0.1:995 tls=TLS1.2 findings=['untrusted-certificate-chain']

### pq_gap_lab_01.pcap
config: {"harness": "openssl 3.6.1 s_server/s_client (manual commands)", "driver": null, "certs": null, "scenario": "pq_gap_lab_01", "evidence": "docs/evidence/pq-interop.md#toolchain"}
provenance: partial (commands documented in evidence doc; no runnable script committed)
expected:
  - session 0 downgrade-attack-detected present=False: HRR is legitimate negotiation here, not a sentinel downgrade
  - session 0 hrr-group-mismatch present=False: requested X25519 was in the offered groups
  - session 0 tls-version-downgrade-suspected present=False: TLS 1.3 negotiated
tool output:
  - session 0 127.0.0.1:45828->127.0.0.1:465 tls=TLS1.3 findings=[]

### mail_smtp_self587_lab_01.pcap
config: {"harness": "scripts/lab_mail.py", "driver": "scripts/lab_capture.sh", "certs": "scripts/lab_certs.sh", "scenario": "smtp_self587", "evidence": "docs/evidence/real-eval.md"}
provenance: complete
expected:
  - session 3 self-signed-certificate present=True: self-signed leaf by config
  - session 3 untrusted-certificate-chain present=True: self-signed untrusted
  - session 3 expired-certificate present=False: valid dates
tool output:
  - session 0 127.0.0.1:38076->127.0.0.1:587 tls=None findings=[]
  - session 1 127.0.0.1:38088->127.0.0.1:587 tls=None findings=[]
  - session 2 127.0.0.1:38104->127.0.0.1:587 tls=None findings=[]
  - session 3 127.0.0.1:38106->127.0.0.1:587 tls=TLS1.2 findings=['self-signed-certificate', 'untrusted-certificate-chain']

### pq_hrr_lab_01.pcap
config: {"harness": "openssl 3.6.1 s_server/s_client (manual commands)", "driver": null, "certs": null, "scenario": "pq_hrr_lab_01", "evidence": "docs/evidence/pq-interop.md#toolchain"}
provenance: partial (commands documented in evidence doc; no runnable script committed)
expected:
  - session 0 hrr-group-mismatch present=False: requested X448 was in the offered groups
  - session 0 downgrade-attack-detected present=False: no sentinel bytes present
  - session 0 tls-version-downgrade-suspected present=False: TLS 1.3 negotiated
tool output:
  - session 0 127.0.0.1:57956->127.0.0.1:465 tls=TLS1.3 findings=[]

### mail_smtp13_implicit465_lab_01.pcap
config: {"harness": "scripts/lab_mail.py", "driver": "scripts/lab_capture.sh", "certs": "scripts/lab_certs.sh", "scenario": "smtp13_implicit465", "evidence": "docs/evidence/real-eval.md"}
provenance: complete
expected:
  - session 3 tls-version-tls1-0 present=False: 1.3
  - session 3 untrusted-certificate-chain present=False: TLS 1.3 blind
  - session 3 no-tls-on-implicit-port present=False: TLS present
  - session 3 downgrade-attack-detected present=False: no sentinel
tool output:
  - session 0 127.0.0.1:55624->127.0.0.1:465 tls=None findings=[]
  - session 1 127.0.0.1:55632->127.0.0.1:465 tls=None findings=[]
  - session 2 127.0.0.1:37086->127.0.0.1:465 tls=None findings=[]
  - session 3 127.0.0.1:37102->127.0.0.1:465 tls=TLS1.3 findings=[]

```
