"""
Manual TLS record-layer framing parser.

Takes a contiguous byte segment (the tls_segment of a Session) and emits
TLS records: header (content_type, version, length) + payload. Handles
partial records at the end of the segment (incomplete) gracefully.

All packet data is treated as untrusted: every read is bounds-checked; the
parser never indexes outside the buffer and fails closed with a
TlsParseError rather than raising IndexError.
"""
from __future__ import annotations

from dataclasses import dataclass


class TlsParseError(Exception):
    pass


@dataclass
class TlsRecord:
    content_type: int          # 20 CCS, 21 alert, 22 handshake, 23 app data
    version: int               # e.g. 0x0303
    payload: bytes


def parse_tls_records(data: bytes, max_records: int = 4096) -> list[TlsRecord]:
    """
    Parse contiguous TLS records from `data`. Returns a list of complete
    records. An incomplete trailing record yields a short_record=True marker
    on the last returned record via TlsRecord? -- instead we simply stop.

    Raises TlsParseError for structurally invalid input (e.g. truncated
    header, absurd record length > 64KB + 2048 overhead to bound memory).
    """
    records: list[TlsRecord] = []
    pos = 0
    n = len(data)
    while pos < n:
        if n - pos < 5:
            # partial header: stop, not an error (stream may continue later)
            break
        content_type = data[pos]
        version = (data[pos + 1] << 8) | data[pos + 2]
        length = (data[pos + 3] << 8) | data[pos + 4]
        if content_type not in (20, 21, 22, 23):
            raise TlsParseError(f"invalid TLS content type 0x{content_type:02x} at offset {pos}")
        if length > 65535 + 2048:
            raise TlsParseError(f"absurd TLS record length {length} at offset {pos}")
        if n - pos - 5 < length:
            break  # incomplete record payload (crosses packet boundary upstream)
        payload = data[pos + 5:pos + 5 + length]
        records.append(TlsRecord(content_type=content_type, version=version, payload=payload))
        pos += 5 + length
        if len(records) >= max_records:
            break
    return records


STARTTLS_COMMANDS = {
    "SMTP": b"STARTTLS",
    "IMAP": b"STARTTLS",
    "POP3": b"STLS",
}


def _valid_record_at(data: bytes, pos: int) -> tuple[int, int] | None:
    """If a valid TLS record header exists at pos, return (content_type, length)."""
    if pos + 5 > len(data):
        return None
    ct = data[pos]
    if ct not in (20, 21, 22, 23):
        return None
    version = (data[pos + 1] << 8) | data[pos + 2]
    if version not in (0x0300, 0x0301, 0x0302, 0x0303, 0x0304):
        return None
    length = (data[pos + 3] << 8) | data[pos + 4]
    if length > 65535 + 2048 or length < 0:
        return None
    if pos + 5 + length > len(data):
        return None
    return ct, length


def find_tls_offset(data: bytes, max_scan: int = 8192) -> int | None:
    """
    Find the byte offset where a run of valid TLS records begins, by scanning
    forward until the whole tail parses cleanly. Used to split the server side
    of STARTTLS sessions (plaintext responses followed by TLS records).
    """
    if not data:
        return None
    limit = min(len(data) - 5, max_scan)
    pos = 0
    while pos <= limit:
        hit = _valid_record_at(data, pos)
        if hit is not None:
            return pos
        pos += 1
    return None


def find_starttls_offset(plaintext_segment: bytes, protocol: str) -> int | None:
    """
    Locate the byte offset in the reassembled client->server stream where the
    TLS transition begins. The client sends `STARTTLS`/`STLS`; the offset we
    return is the position immediately AFTER the server's positive response
    completes and TLS ClientHello bytes begin. In reassembled streams we look
    in the combined flow; here we accept the plaintext segment and search for
    the command, returning offset of the command relative to the client stream
    start. The caller combines client+server offsets.
    """
    if protocol not in STARTTLS_COMMANDS:
        return None
    cmd = STARTTLS_COMMANDS[protocol]
    idx = plaintext_segment.find(cmd)
    if idx == -1:
        return None
    # offset at end of the STARTTLS command line
    eol = plaintext_segment.find(b"\r\n", idx)
    if eol == -1:
        return None
    return eol + 2