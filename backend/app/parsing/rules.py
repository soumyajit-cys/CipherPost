"""
Stage 3: Deterministic rules engine for cryptographic posture.

This is the PRIMARY, auditable detection layer. ML augments it but never
replaces it. Each rule is a pure function over a SessionAnalysis and emits
Findings tagged with id, severity, plain-language explanation and a standard
reference (NIST SP 800-52r2, OWASP TLS Cheat Sheet, RFC 5246/8446).

Knowledge tables (allowed TLS versions, allowed ciphers, minimum key sizes,
required signature algo strengths) are explicit and data-driven for review.
"""
from __future__ import annotations

import datetime
import fnmatch
from dataclasses import dataclass, field
from typing import Callable

from app.parsing.handshake import (
    ClientHelloInfo, ServerHelloInfo, CertificateInfo, CipherMeta, CIPHER_DB,
    lookup_cipher, version_name, TLS_VERSION_NAMES,
)
from app.parsing.certificates import CertAnalysis


@dataclass
class Severity:
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class Finding:
    rule_id: str
    rule_name: str
    severity: str
    title: str
    description: str
    reference: str
    kind: str = "rule"
    evidence: dict = field(default_factory=dict)


@dataclass
class SessionAnalysis:
    session_id: str
    protocol: str
    five_tuple: str
    is_starttls: bool
    tls_version: int | None = None
    negotiated_version_name: str | None = None
    cipher: str | None = None
    cipher_meta: CipherMeta | None = None
    cipher_iana: int | None = None
    cipher_strength: float | None = None
    client_hello: ClientHelloInfo | None = None
    server_hello: ServerHelloInfo | None = None
    certificate: CertificateInfo | None = None
    certs: list[CertAnalysis] = field(default_factory=list)
    chain_result: str = "no-cert"
    chain_error: str = ""
    started_tls: bool = False
    tls_bytes: int = 0
    findings: list[Finding] = field(default_factory=list)
    # Phase 4: TLS 1.3 visibility model. Records exactly what was observable;
    # rules that need unobserved data skip via not_observable (never guess).
    #   {"tls13": bool, "cert_chain": "observed"|"not_observable_tls13"|"absent",
    #    "sni": "observed"|"absent"|"ech_outer", "hrr": bool, ...}
    visibility: dict = field(default_factory=dict)
    not_observable: list[str] = field(default_factory=list)  # skipped rule_ids

    def add(self, rule_id, rule_name, severity, title, description, reference, **evidence):
        self.findings.append(Finding(
            rule_id=rule_id, rule_name=rule_name, severity=severity,
            title=title, description=description, reference=reference,
            evidence=evidence,
        ))


# ---------------------------------------------------------------------------
# Knowledge tables (reviewable / auditable)
# ---------------------------------------------------------------------------

# Allowed TLS versions per current baseline (NIST SP 800-52r2 → TLS 1.2+ preferred)
ALLOWED_TLS_VERSIONS = {0x0303: "deprecated-baseline", 0x0304: "current"}

WEAK_VERSIONS = {
    0x0300: ("SSLV3", Severity.CRITICAL, "SSLv3 is broken (POODLE, CVE-2014-3566) and MUST NOT be used."),
    0x0301: ("TLS1.0", Severity.HIGH, "TLS 1.0 is deprecated (NIST SP 800-52r2 disallows below 1.2; RFC 8996)."),
    0x0302: ("TLS1.1", Severity.HIGH, "TLS 1.1 is deprecated (RFC 8996; NIST SP 800-52r2)."),
}
CATEGORY_STRENGTH = {
    "export": ("export-grade cipher", Severity.CRITICAL),
    "null": ("null encryption cipher", Severity.CRITICAL),
    "rc4": ("RC4 stream cipher", Severity.HIGH),
    "des": ("legacy 3DES", Severity.MEDIUM),
    "stream": ("stream cipher", Severity.MEDIUM),
    "cbc": ("CBC-mode cipher", Severity.LOW),
    "aead": ("AEAD cipher", Severity.INFO),
}

MIN_RSA_KEY = 2048
MIN_EC_KEY = 224
MIN_EC_GROUP = {29, 23, 24, 25, 28, 256, 257, 258}  # common safe ECDHE groups incl X25519(29)

NOT_ALLOWED_AUTH = {"anon", "export", "null"}


# ---------------------------------------------------------------------------
# Rules
# ---------------------------------------------------------------------------

def rule_deprecated_version(sa: SessionAnalysis):
    if sa.tls_version in WEAK_VERSIONS:
        name, sev, why = WEAK_VERSIONS[sa.tls_version]
        sa.add(
            f"tls-version-{name.lower().replace('.', '-')}",
            f"Deprecated TLS version: {name}",
            sev,
            f"{name} negotiated",
            f"This session negotiated {name}. {why} NIST SP 800-52r2 and RFC 8996"
            " require TLS 1.2 or TLS 1.3 for email transport.",
            "NIST SP 800-52r2 §3.1; RFC 8996; OWASP TLS Cheat Sheet §'understand TLS 1.2'",
            negotiated_version=version_name(sa.tls_version), raw=hex(sa.tls_version),
        )


def rule_tls13_no_tls12_upgrade(sa: SessionAnalysis):
    pass  # informational handled elsewhere


def rule_non_aead_cipher(sa: SessionAnalysis):
    if sa.cipher_meta and sa.cipher_meta.kind in ("cbc", "stream"):
        sa.add(
            "non-aead-bulk-cipher",
            "Non-AEAD bulk cipher",
            Severity.LOW if sa.cipher_meta.kind == "cbc" else Severity.MEDIUM,
            f"{sa.cipher} uses legacy bulk encryption",
            f"The negotiated cipher {sa.cipher} does not use an authenticated AEAD"
            " mode (AES-GCM/CCM or ChaCha20-Poly1305). CBC-mode ciphers are subject to"
            " padding-oracle attacks (e.g. Lucky13) and lack integrity protection the"
            " same way. Prefer AEAD ciphers (NIST SP 800-52r2 preference).",
            "NIST SP 800-52r2 §3.3.1; OWASP TLS Cheat Sheet",
            cipher=sa.cipher, kind=sa.cipher_meta.kind,
        )


def rule_weak_cipher(sa: SessionAnalysis):
    if sa.cipher_meta is None:
        return
    if sa.cipher_meta.export_class in ("export", "null", "rc4"):
        # handled by dedicated rules (export/rc4/null)
        return
    if sa.cipher_meta.kind not in ("cbc", "stream"):
        return
    cat, sev = CATEGORY_STRENGTH[sa.cipher_meta.kind]
    if sa.cipher_meta.strength <= 0.3:
        sev = Severity.CRITICAL if sa.cipher_meta.key_len <= 56 else Severity.MEDIUM
    sa.add(
        "weak-cipher-suite",
        "Weak cipher suite",
        sev,
        f"{sa.cipher} classified {cat}",
        f"The negotiated cipher {sa.cipher} (effective key {sa.cipher_meta.key_len}-bit) is"
        f" classified as a {cat}. NIST SP 800-52r2 disallows short/weak ciphers for"
        " government TLS traffic and recommends blocking them at the server.",
        "NIST SP 800-52r2 App A; OWASP TLS Cheat Sheet",
        cipher=sa.cipher, iana=hex(sa.cipher_iana or 0),
        strength=sa.cipher_meta.strength, key_len=sa.cipher_meta.key_len,
    )


def rule_non_pfs(sa: SessionAnalysis):
    if sa.cipher_meta and not sa.cipher_meta.pfs:
        sa.add(
            "non-pfs-key-exchange",
            "No forward secrecy (PFS)",
            Severity.MEDIUM,
            f"{sa.cipher} uses static key exchange",
            f"The negotiated cipher {sa.cipher} does not use ephemeral (EC)DHE key"
            " exchange. If the server private key is compromised, all past sessions"
            " can be decrypted (no forward secrecy). Prefer ECDHE suites.",
            "NIST SP 800-52r2 §3.3.1; OWASP TLS Cheat Sheet §'use forward secrecy'",
            cipher=sa.cipher, kex=sa.cipher_meta.kex,
        )


def rule_export_cipher(sa: SessionAnalysis):
    if sa.cipher_meta and sa.cipher_meta.export_class == "export":
        sa.add(
            "export-grade-cipher",
            "Export-grade cipher suite",
            Severity.CRITICAL,
            "Export cipher suite negotiated",
            f"{sa.cipher} is an EXPORT-grade cipher with a {sa.cipher_meta.key_len}-bit key."
            " Export ciphers (40/56-bit) are trivially brute-forcable and are the basis"
            " of the FREAK attack (CVE-2015-0204).",
            "NIST SP 800-52r2 App A; CVE-2015-0204",
            cipher=sa.cipher, iana=hex(sa.cipher_iana or 0),
        )


def rule_cert_expired(sa: SessionAnalysis):
    if not require_usable_certs(sa, "expired-certificate"):
        return
    for ci, cert in enumerate(sa.certs):
        if not cert or not cert.expired:
            continue
        sa.add(
            "expired-certificate",
            "Expired certificate",
            Severity.HIGH,
            "Certificate in chain is expired",
            f"The certificate '{cert.subject_cn}' (issued {cert.not_before}, expires "
            f"{cert.not_after}, {cert.days_remaining} days ago) has EXPIRED. TLS clients"
            " will reject the handshake; mail delivery is likely failing or being"
            " downgraded.",
            "RFC 5280 §4.1.2.5; NIST SP 800-52r2 §3.3.3",
            subject=cert.subject_cn, index=ci, not_after=str(cert.not_after),
        )


def rule_cert_not_yet_valid(sa: SessionAnalysis):
    if not require_usable_certs(sa, "certificate-not-yet-valid"):
        return
    for ci, cert in enumerate(sa.certs):
        if cert and cert.not_yet_valid:
            sa.add(
                "certificate-not-yet-valid",
                "Certificate not yet valid",
                Severity.MEDIUM,
                "Certificate start date is in the future",
                f"Certificate '{cert.subject_cn}' is not valid until {cert.not_before};"
                " indicating a signing clock problem or time-skew on the mail server.",
                "RFC 5280 §4.1.2.5",
                subject=cert.subject_cn, index=ci,
            )


def rule_cert_self_signed(sa: SessionAnalysis):
    if not require_usable_certs(sa, "self-signed-certificate"):
        return
    for ci, cert in enumerate(sa.certs):
        if cert and cert.is_self_signed and ci == 0:
            sa.add(
                "self-signed-certificate",
                "Self-signed certificate",
                Severity.MEDIUM,
                "Leaf certificate is self-signed",
                f"The presented certificate '{cert.subject_cn}' is self-signed. Clients"
                " that strictly validate will reject it; opportunistic/trust-on-first-use"
                " mail clients may accept it silently, which is a MITM risk.",
                "RFC 5280 §6.1; NIST SP 800-52r2 §3.3.3",
                subject=cert.subject_cn,
            )


def rule_chain_untrusted(sa: SessionAnalysis):
    if not require_usable_certs(sa, "untrusted-certificate-chain"):
        return
    if sa.chain_result in ("untrusted", "invalid-sig", "hostname-mismatch", "expired",
                           "not-yet-valid", "parse-error"):
        if sa.chain_result == "untrusted":
            sev = Severity.HIGH
            msg = "does not chain to a trusted root in the configured trust store"
        elif sa.chain_result == "invalid-sig":
            sev = Severity.HIGH
            msg = "failed signature validation against its issuer"
        elif sa.chain_result == "hostname-mismatch":
            sev = Severity.MEDIUM
            msg = "hostname does not match the certificate SANs"
        elif sa.chain_result == "parse-error":
            sev = Severity.MEDIUM
            msg = "could not be parsed as X.509"
        else:
            sev = Severity.HIGH
            msg = sa.chain_error
        sa.add(
            "untrusted-certificate-chain",
            "Untrusted certificate chain",
            sev,
            f"Chain validation failed: {sa.chain_result}",
            f"The server's certificate chain {msg}. Email clients will reject the TLS"
            " session or fall back to insecure plaintext, enabling downgrade/MITM.",
            "RFC 5280 §6; NIST SP 800-52r2 §3.3.3",
            result=sa.chain_result, detail=sa.chain_error,
        )


def rule_weak_signature(sa: SessionAnalysis):
    if not require_usable_certs(sa, "weak-signature-algorithm"):
        return
    for ci, cert in enumerate(sa.certs):
        if cert and cert.weak_signature:
            sa.add(
                "weak-signature-algorithm",
                "Weak signature algorithm on certificate",
                Severity.HIGH,
                f"Certificate signed with {cert.signature_alg}",
                f"The certificate '{cert.subject_cn}' uses signature algorithm"
                f" {cert.signature_alg}. SHA-1/MD5 signature algorithms are"
                " cryptographically broken (collision attacks) and MUST NOT be used"
                " for certificates.",
                "NIST SP 800-52r2 §3.3.3; RFC 8446 App B.1.1",
                subject=cert.subject_cn, algorithm=cert.signature_alg, index=ci,
            )


def rule_short_key(sa: SessionAnalysis):
    if not require_usable_certs(sa, "short-public-key"):
        return
    for ci, cert in enumerate(sa.certs):
        if cert and cert.short_key:
            sa.add(
                "short-public-key",
                "Short public key size",
                Severity.HIGH,
                f"Certificate public key only {cert.pubkey_bits} bits",
                f"Certificate '{cert.subject_cn}' uses a {cert.pubkey_alg} public key of"
                f" {cert.pubkey_bits} bits. NIST SP 800-52r2 requires RSA >= 2048,"
                f" ECDSA >= 224 bits (256-bit curve recommended).",
                "NIST SP 800-52r2 §3.3.3.1; NIST SP 800-57 Part 1",
                subject=cert.subject_cn, algorithm=cert.pubkey_alg, bits=cert.pubkey_bits,
            )


def rule_rc4(sa: SessionAnalysis):
    if sa.cipher_meta and "RC4" in (sa.cipher or ""):
        sa.add(
            "rc4-cipher",
            "RC4 cipher suite",
            Severity.HIGH,
            "RC4 negotiated",
            f"{sa.cipher} uses the RC4 stream cipher. RC4 biases allow practical"
            " plaintext recovery (Bar-Mitzvah/BEAST variants) and it is prohibited"
            " in RFC 7465 for TLS.",
            "RFC 7465; NIST SP 800-52r2 App A",
            cipher=sa.cipher,
        )


def rule_3des(sa: SessionAnalysis):
    if sa.cipher_meta and "3DES" in (sa.cipher or ""):
        sa.add(
            "3des-cipher",
            "3DES cipher suite",
            Severity.MEDIUM,
            "3DES negotiated",
            f"{sa.cipher} uses 3DES. 3DES/EDE has only ~112 bits of security and is"
            " subject to Sweet32 online birthday attacks; prohibited after 2023.",
            "NIST 800-131A Rev 2; RFC 8429",
            cipher=sa.cipher,
        )


def rule_ssl_in_plaintext(sa: SessionAnalysis):
    # plaintext SMTP/IMAP/POP3 with NO STARTTLS offered/used
    if not sa.started_tls and not sa.tls_bytes:
        sa.add(
            "plaintext-mail-protocol",
            "Plaintext mail session (no TLS)",
            Severity.HIGH,
            "Email credentials/messages sent in cleartext",
            f"{sa.protocol} session carried no TLS. If STARTTLS was expected this is a"
            " protocol-stripping / MITM indicator; credentials and message bodies were"
            " transmitted in cleartext and are recoverable from the capture.",
            "RFC 3207 §4 (SMTP); NIST SP 800-52r2 §3.3",
            plaintext_bytes=getattr(sa, "plaintext_bytes", 0),
        )


def rule_starttls_strip(sa: SessionAnalysis):
    if sa.saw_starttls_offer and not sa.started_tls and not sa.tls_bytes:
        sa.add(
            "starttls-strip-attempt",
            "Possible STARTTLS stripping",
            Severity.CRITICAL,
            "STARTTLS advertised but no handshake followed",
            f"The {sa.protocol} server advertised STARTTLS capability (or the client"
            " requested it) but the session proceeded without a TLS handshake. An"
            " active attacker may have suppressed/forged the STARTTLS response to force"
            " plaintext (STRIPTLS / STARTTLS downgrade). Clients MUST refuse to continue"
            " when STARTTLS is not honored.",
            "RFC 3207 §4.1.2; OWASP SMTP Transport Security through STARTTLS",
        )


def rule_no_client_hello_pfs_capability(sa: SessionAnalysis):
    if sa.client_hello and sa.tls_version and sa.tls_version < 0x0304:
        # Client offered any ECDHE-capable or DHE suite?
        pfs_offered = any(
            (m.pfs if (m := lookup_cipher(cs)) else False)
            for cs in sa.client_hello.cipher_suites
        )
        if not pfs_offered:
            sa.add(
                "client-no-pfs-suites",
                "Client offers no forward-secrecy suites",
                Severity.LOW,
                "ClientHello advertises no ECDHE/DHE cipher suites",
                "The client's offered cipher list contains no ephemeral-DH suites,"
                " so a PFS-capable server will fall back to a static key exchange if"
                " this client is relicensed maintenance.",
                "OWASP TLS Cheat Sheet §'use forward secrecy'",
                offered=[hex(c) for c in sa.client_hello.cipher_suites],
            )


def rule_alpn_missing(sa: SessionAnalysis):
    if sa.client_hello and sa.client_hello.alpn == [] and sa.tls_version == 0x0304:
        sa.add(
            "alpn-not-negotiated",
            "ALPN not used",
            Severity.INFO,
            "No ALPN protocol negotiated",
            "TLS 1.3 sessions should negotiate an ALPN value (e.g. 'smtp'); none was"
            " offered. On shared ports this can be a downgrade or misconfiguration.",
            "RFC 7301",
        )


def rule_legacy_groups(sa: SessionAnalysis):
    """Deprecated named groups offered or (worse) selected. IANA marks curves
    1..25 deprecated; a negotiated deprecated group is HIGH, offered-only LOW
    (client capability, not server fault). GREASE is never analyzed."""
    from app.parsing.handshake import (
        DEPRECATED_GROUPS, MODERN_FS_GROUPS, strip_grease, group_name,
        HYBRID_PQ_GROUPS, PURE_PQ_GROUPS, OBSOLETE_KYBER_DRAFTS,
    )
    ch, sh = sa.client_hello, sa.server_hello
    if ch is None:
        return
    offered = [g for g in strip_grease(ch.supported_groups)
               if g in DEPRECATED_GROUPS]
    selected = getattr(sh, "selected_group", None) if sh else None
    if selected in DEPRECATED_GROUPS:
        sa.add(
            "deprecated-group-negotiated",
            "Deprecated key-exchange group negotiated",
            Severity.HIGH,
            f"Deprecated group {group_name(selected)} negotiated",
            "The server selected a key-exchange group IANA marks deprecated"
            " (curves 1..25). Renegotiate with a modern group (X25519, FFDHE,"
            " or a hybrid post-quantum group).",
            "RFC 8422-bis; IANA TLS Supported Groups registry",
            group=group_name(selected),
        )
    elif offered:
        sa.add(
            "deprecated-group-offered",
            "Client offers only deprecated groups" if not any(
                g in MODERN_FS_GROUPS for g in strip_grease(ch.supported_groups)) else
            "Client offers deprecated groups",
            Severity.MEDIUM if not any(
                g in MODERN_FS_GROUPS for g in strip_grease(ch.supported_groups))
            else Severity.LOW,
            "Deprecated groups in ClientHello",
            "The client offers IANA-deprecated groups (curves 1..25). "
            f"Offered: {[group_name(g) for g in offered]}. "
            "The server should prefer modern groups.",
            "RFC 8422-bis; IANA TLS Supported Groups registry",
            groups=[group_name(g) for g in offered],
        )


def rule_no_modern_pfs_group(sa: SessionAnalysis):
    """Client offers groups but none capable of modern forward secrecy."""
    from app.parsing.handshake import MODERN_FS_GROUPS, strip_grease, group_name
    ch = sa.client_hello
    if ch is None or not ch.supported_groups:
        return
    offered = strip_grease(ch.supported_groups)
    if offered and not any(g in MODERN_FS_GROUPS for g in offered):
        sa.add(
            "no-modern-pfs-group",
            "No modern forward-secrecy group offered",
            Severity.MEDIUM,
            "Client offers no modern PFS-capable group",
            "The ClientHello offers key-exchange groups but none of X25519,"
            " X448, FFDHE-2048+, or hybrid post-quantum groups. Sessions will"
            " negotiate weaker/legacy key exchange.",
            "OWASP TLS Cheat Sheet §'use forward secrecy'",
            offered=[group_name(g) for g in offered],
        )


def rule_downgrade_sentinel(sa: SessionAnalysis):
    """RFC 8446 §4.1.3 downgrade protection: server random sentinel means the
    server also supports a higher version than negotiated. CRITICAL only when
    the client actually offered higher (proven); otherwise silent."""
    sh, ch = sa.server_hello, sa.client_hello
    if sh is None or not sh.downgrade_sentinel:
        return
    offered_max = max(ch.offered_versions) if ch and ch.offered_versions else None
    negotiated = sa.tls_version
    if (offered_max is not None and negotiated is not None
            and offered_max > negotiated):
        sa.add(
            "downgrade-attack-detected",
            "TLS downgrade attack detected",
            Severity.CRITICAL,
            "Server downgrade sentinel with higher version offered",
            f"The server random carries the {sh.downgrade_sentinel} downgrade"
            f" sentinel while the client offered {hex(offered_max)} but only"
            f" {hex(negotiated)} was negotiated. This is the RFC 8446 active-"
            "downgrade signal: investigate for MITM immediately.",
            "RFC 8446 §4.1.3",
            sentinel=sh.downgrade_sentinel,
        )


def rule_hrr_anomaly(sa: SessionAnalysis):
    """HelloRetryRequest is normal; a selected group the client never offered
    is not (server confusion or tampering)."""
    from app.parsing.handshake import strip_grease, group_name
    sh, ch = sa.server_hello, sa.client_hello
    if sh is None or not sh.is_hrr:
        return
    selected = sh.selected_group
    offered = strip_grease(ch.supported_groups) if ch else []
    if selected is not None and offered and selected not in offered:
        sa.add(
            "hrr-group-mismatch",
            "HelloRetryRequest selects unoffered group",
            Severity.MEDIUM,
            "HRR requests a group the client never offered",
            f"The HelloRetryRequest selects {group_name(selected)} which was"
            " not in the ClientHello supported_groups. Normal servers only"
            " request offered groups; investigate server state or tampering.",
            "RFC 8446 §4.1.4",
            selected=group_name(selected),
        )


def rule_tls_version_downgrade(sa: SessionAnalysis):
    """Negotiated version below the client's best offer. HIGH only for
    ≤1.1 (attack-plausible); 1.3→1.2 is an INFO posture note (server may
    simply lack 1.3) — never called an attack without evidence."""
    ch = sa.client_hello
    if ch is None or not ch.offered_versions or sa.tls_version is None:
        return
    best = max(ch.offered_versions)
    if sa.tls_version >= best:
        return
    if sa.tls_version <= 0x0302 and best >= 0x0303:
        sa.add(
            "tls-version-downgrade-suspected",
            "Negotiated version below best offer",
            Severity.HIGH,
            "Server negotiated below the client's best offer",
            f"Client offered up to {hex(best)} but {hex(sa.tls_version)} was"
            " negotiated. A legacy-only server is possible, but so is active"
            " version downgrade — verify the server's configured versions.",
            "RFC 8446 §4.1.3; RFC 8996",
            offered=hex(best), negotiated=hex(sa.tls_version),
        )
    elif sa.tls_version == 0x0303 and best == 0x0304:
        sa.add(
            "tls13-not-negotiated",
            "TLS 1.3 offered but 1.2 negotiated",
            Severity.INFO,
            "Server does not negotiate TLS 1.3",
            "The client offered TLS 1.3 but the server negotiated 1.2. Usually"
            " a server that has not enabled 1.3 yet — a hardening opportunity,"
            " not evidence of attack.",
            "RFC 8446",
        )


def rule_ech_present(sa: SessionAnalysis):
    """Encrypted Client Hello outer observed: inner SNI is not observable."""
    ch = sa.client_hello
    if ch is not None and ch.ech_outer:
        sa.add(
            "ech-observed",
            "Encrypted Client Hello in use",
            Severity.INFO,
            "ECH outer ClientHello observed",
            "The client used Encrypted Client Hello (RFC 8744, ext 0xfe0d):"
            " the inner SNI and parameters are encrypted and NOT observable"
            " passively. Certificate/host attribution for this session is"
            " limited to the outer (public) name.",
            "RFC 8744 (draft-ietf-tls-esni)",
            outer_sni=ch.sni,
        )


def rule_legacy_compression(sa: SessionAnalysis):
    """TLS 1.3 forbids compression; offering anything but null with 1.3 is odd."""
    ch = sa.client_hello
    if ch is None or sa.tls_version != 0x0304:
        return
    if ch.compression and ch.compression != [0]:
        sa.add(
            "legacy-compression-offered",
            "Non-null compression with TLS 1.3",
            Severity.LOW,
            "Client offers legacy compression",
            "TLS 1.3 forbids compression (RFC 8446 §9.2); the ClientHello"
            " offered compression methods anyway. Likely a legacy stack,"
            " worth noting for client inventory.",
            "RFC 8446 §9.2",
            offered=ch.compression,
        )


def rule_unknown_cipher(sa: SessionAnalysis):
    if sa.cipher_iana and sa.cipher_meta is None:
        sa.add(
            "unknown-cipher-suite",
            "Unrecognized cipher suite",
            Severity.MEDIUM,
            f"Cipher suite 0x{sa.cipher_iana:04x} not in knowledge base",
            "A cipher suite was negotiated that CipherPost does not recognize. This"
            " warrants investigation: it may be exotic, a GREASE value, or require"
            " updating the cipher knowledge base.",
            "IANA TLS Cipher Suite Registry",
            cipher_iana=hex(sa.cipher_iana or 0),
        )


def rule_no_tls_on_tls_port(sa: SessionAnalysis):
    if sa.is_implicit_tls_port and not sa.started_tls and not sa.tls_bytes:
        sa.add(
            "no-tls-on-implicit-port",
            "No TLS on implicit-TLS port",
            Severity.CRITICAL,
            f"Port {sa.port} expects TLS but none seen",
            f"Traffic on implicit-TLS port {sa.port} ({sa.protocol}s) carried no TLS"
            " handshake. Either the server is misconfigured, the traffic is being"
            " passively downgraded, or a non-compliant client is sending plaintext.",
            "RFC 8314 §3.1; NIST SP 800-52r2 §3.3",
            port=sa.port,
        )


def rule_handshake_incomplete(sa: SessionAnalysis):
    if sa.started_tls and not sa.client_hello:
        sa.add(
            "tls-handshake-incomplete",
            "TLS handshake incomplete/opaque",
            Severity.MEDIUM,
            "TLS records present but no ClientHello parsed",
            "TLS activity was detected but a ClientHello could not be parsed from the"
            " client stream. Possible causes: fragmented handshake across many records,"
            " an exotic client, or an injection attempt.",
            "RFC 5246 §7.4.1.2",
        )


ALL_RULES: list[Callable[[SessionAnalysis], None]] = [
    rule_deprecated_version,
    rule_non_aead_cipher,
    rule_weak_cipher,
    rule_export_cipher,
    rule_non_pfs,
    rule_rc4,
    rule_3des,
    rule_cert_expired,
    rule_cert_not_yet_valid,
    rule_cert_self_signed,
    rule_chain_untrusted,
    rule_weak_signature,
    rule_short_key,
    rule_ssl_in_plaintext,
    rule_starttls_strip,
    rule_no_client_hello_pfs_capability,
    rule_no_tls_on_tls_port,
    rule_handshake_incomplete,
    rule_unknown_cipher,
    rule_legacy_groups,
    rule_no_modern_pfs_group,
    rule_downgrade_sentinel,
    rule_hrr_anomaly,
    rule_tls_version_downgrade,
    rule_ech_present,
    rule_legacy_compression,
]


def run_rules(sa: SessionAnalysis) -> list[Finding]:
    for rule in ALL_RULES:
        try:
            rule(sa)
        except Exception:
            continue
    return sa.findings


# Phase 4: certificate observability. On TLS 1.3 the Certificate message is
# encrypted, so a passive observer sees no usable certs. Rules that need
# certificates must skip (recorded in sa.not_observable) rather than pass or
# fail on unobserved data. A cert counts as observed only if it actually
# parsed as X.509 (valid dates + real subject).
CERT_RULE_IDS = (
    "expired-certificate",
    "certificate-not-yet-valid",
    "self-signed-certificate",
    "untrusted-certificate-chain",
    "weak-signature-algorithm",
    "short-public-key",
)


def certs_usable(sa: SessionAnalysis) -> bool:
    for c in sa.certs or []:
        if (c is not None and c.not_before is not None
                and (c.subject_cn or "") not in ("", "<unparseable>", "<oid missing>")):
            return True
    return False


def require_usable_certs(sa: SessionAnalysis, rule_id: str) -> bool:
    """False + record when a cert rule must skip (TLS 1.3, nothing observed)."""
    if certs_usable(sa):
        return True
    if (sa.visibility or {}).get("tls13"):
        if rule_id not in sa.not_observable:
            sa.not_observable.append(rule_id)
        return False
    return True


def max_severity(findings: list[Finding]) -> str | None:
    order = {Severity.INFO: 0, Severity.LOW: 1, Severity.MEDIUM: 2, Severity.HIGH: 3, Severity.CRITICAL: 4}
    if not findings:
        return None
    return max(findings, key=lambda f: order.get(f.severity, 0)).severity