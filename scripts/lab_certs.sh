#!/bin/bash
# Lab certificate authority + server certs for Item 3 (blocker-closure lab).
# Generates a 30-day lab CA and five server certs in OUT dir (default
# /tmp/opencode/maillab). Lab only: never use these certs outside loopback
# testing. Requires openssl 3.x (record version in evidence docs).
set -u
OUT=${1:-/tmp/opencode/maillab}
mkdir -p "$OUT"
cd "$OUT" || exit 1
openssl req -x509 -newkey rsa:2048 -keyout ca.key -out ca.crt -days 30 \
  -nodes -subj "/CN=Mail Lab CA" 2>/dev/null
mkcert() { # name subj days extra-SAN-line-or-empty
  openssl req -newkey rsa:2048 -keyout "$1.key" -out "$1.csr" -nodes \
    -subj "$2" 2>/dev/null
  if [ -n "${4:-}" ]; then
    printf '%s\n' "$4" > "$1.ext"
    openssl x509 -req -in "$1.csr" -CA ca.crt -CAkey ca.key -CAcreateserial \
      -out "$1.crt" -days "$3" -extfile "$1.ext" 2>/dev/null
  else
    openssl x509 -req -in "$1.csr" -CA ca.crt -CAkey ca.key -CAcreateserial \
      -out "$1.crt" -days "$3" 2>/dev/null
  fi
}
SAN="subjectAltName=DNS:mail.lab.test"
mkcert good "/CN=mail.lab.test" 30 "$SAN"
mkcert expired "/CN=mail.lab.test" 0 "$SAN"          # 0-day: already expired
mkcert wronghost "/CN=other.host.test" 30 "subjectAltName=DNS:other.host.test"
openssl req -x509 -newkey rsa:2048 -keyout self.key -out self.crt -days 30 \
  -nodes -subj "/CN=mail.lab.test" -addext "subjectAltName=DNS:mail.lab.test" 2>/dev/null
openssl req -newkey rsa:2048 -keyout weak.csr.key -out weak.csr -nodes \
  -subj "/CN=mail.lab.test" 2>/dev/null
openssl x509 -req -in weak.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out weak.crt -days 30 -sha1 -extfile <(printf '%s\n' "$SAN") 2>/dev/null \
  || echo "NOTE: sha1 signing unsupported by this openssl (weaksig scenario unavailable)"
ls ca.crt good.crt expired.crt self.crt wronghost.crt weak.crt 2>/dev/null
