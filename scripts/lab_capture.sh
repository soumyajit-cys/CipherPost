#!/bin/bash
# Item 3 capture driver: runs each lab scenario (server + client) under dumpcap.
# Usage: ./scripts/lab_capture.sh <outdir> [scenario-name ...]
# Lab dirs: certs in /tmp/opencode/maillab, harness scripts/lab_mail.py.
# Process management is PID-based (never pkill pattern matching).
LAB=/tmp/opencode/maillab
OUT=${1:-/tmp/opencode/maillab/caps}; shift || true
mkdir -p "$OUT"

DCAP_PID=""; SRV_PID=""

start_cap() { # name
  dumpcap -i lo -F pcap -w "$OUT/$1.raw.pcap" >/dev/null 2>&1 &
  DCAP_PID=$!
  sleep 2
  kill -0 $DCAP_PID 2>/dev/null || { echo "dumpcap failed to start"; return 1; }
  # readiness probe: dumpcap startup on loaded hosts is slow; do not start
  # the scenario until a probe SYN to a closed port is visible in the file.
  timeout 2 bash -c "</dev/tcp/127.0.0.1/59999" 2>/dev/null
  for _ in $(seq 1 15); do
    if [ "$(tshark -r "$OUT/$1.raw.pcap" -Y "tcp.port==59999" 2>/dev/null | wc -l)" -ge 2 ]; then
      return 0
    fi
    sleep 1
    timeout 2 bash -c "</dev/tcp/127.0.0.1/59999" 2>/dev/null
  done
  echo "dumpcap readiness probe failed for $1"
  return 1
}
start_server() { # args...
  timeout 25 python3 scripts/lab_mail.py server "$@" >/dev/null 2>&1 &
  SRV_PID=$!
  sleep 2
}
stop_all() {
  [ -n "$SRV_PID" ] && kill "$SRV_PID" 2>/dev/null
  [ -n "$DCAP_PID" ] && kill "$DCAP_PID" 2>/dev/null
  sleep 1
  SRV_PID=""; DCAP_PID=""
}
finish() { # name port
  tshark -r "$OUT/$1.raw.pcap" -Y "tcp.port==$2" -F pcap -w "$OUT/$1.pcap" 2>/dev/null
  rm -f "$OUT/$1.raw.pcap"
  echo "$1: $(capinfos "$OUT/$1.pcap" 2>/dev/null | grep -o 'Number of packets.*' | grep -o '[0-9]*' | head -n 1) pkts"
}
scli() { # uses SCARGS, DIALOG, NAME
  printf "%b" "$DIALOG" | timeout 12 openssl s_client $SCARGS -CAfile $LAB/ca.crt -quiet >>"$OUT/$NAME.tls.txt" 2>&1
  : > /dev/null
}

run() { # name port server_args... -- sclient_args... -- dialog
  NAME=$1; PORT=$2; shift 2
  SARGS=()
  while [ "$1" != "--" ]; do SARGS+=("$1"); shift; done; shift
  SCARGS=""
  while [ "$1" != "--" ]; do SCARGS="$SCARGS $1"; shift; done; shift
  DIALOG=$1
  : > "$OUT/$NAME.tls.txt"
  start_cap "$NAME" || return 1
  start_server "${SARGS[@]}"
  # shellcheck disable=SC2086
  printf "%b" "$DIALOG" | timeout 12 openssl s_client $SCARGS -CAfile $LAB/ca.crt -quiet >>"$OUT/$NAME.tls.txt" 2>&1
  stop_all
  finish "$NAME" "$PORT"
}

ONLY="$*"
want() { [ -z "$ONLY" ] && return 0; case " $ONLY " in *" $1 "*) return 0;; *) return 1;; esac; }

G=$LAB/good.crt; GK=$LAB/good.key

# shellcheck disable=SC2086
want smtp13_starttls587 && run smtp13_starttls587 587 smtp 587 --cert $G --key $GK -- -starttls smtp -connect 127.0.0.1:587 -tls1_3 -servername mail.lab.test -- 'EHLO c\r\nQUIT\r\n'
want smtp12_starttls587 && run smtp12_starttls587 587 smtp 587 --cert $G --key $GK -- -starttls smtp -connect 127.0.0.1:587 -tls1_2 -servername mail.lab.test -- 'EHLO c\r\nQUIT\r\n'
want smtp10_starttls587 && run smtp10_starttls587 587 smtp 587 --cert $G --key $GK --tlsmin 1.0 --tlsmax 1.0 --ciphers AES128-SHA@SECLEVEL=0 -- -starttls smtp -connect 127.0.0.1:587 -tls1 -cipher AES128-SHA@SECLEVEL=0 -- 'EHLO c\r\nQUIT\r\n'
want smtp11_starttls587 && run smtp11_starttls587 587 smtp 587 --cert $G --key $GK --tlsmin 1.1 --tlsmax 1.1 --ciphers AES128-SHA@SECLEVEL=0 -- -starttls smtp -connect 127.0.0.1:587 -tls1_1 -cipher AES128-SHA@SECLEVEL=0 -- 'EHLO c\r\nQUIT\r\n'
want smtp_weakcbc587 && run smtp_weakcbc587 587 smtp 587 --cert $G --key $GK --tlsmin 1.2 --tlsmax 1.2 --ciphers AES128-SHA@SECLEVEL=0 -- -starttls smtp -connect 127.0.0.1:587 -tls1_2 -cipher AES128-SHA@SECLEVEL=0 -servername mail.lab.test -- 'EHLO c\r\nQUIT\r\n'
want smtp_expired587 && run smtp_expired587 587 smtp 587 --cert $LAB/expired.crt --key $LAB/expired.key --tlsmin 1.2 --tlsmax 1.2 -- -starttls smtp -connect 127.0.0.1:587 -tls1_2 -servername mail.lab.test -- 'EHLO c\r\nQUIT\r\n'
want smtp_self587 && run smtp_self587 587 smtp 587 --cert $LAB/self.crt --key $LAB/self.key --tlsmin 1.2 --tlsmax 1.2 -- -starttls smtp -connect 127.0.0.1:587 -tls1_2 -servername mail.lab.test -- 'EHLO c\r\nQUIT\r\n'
want smtp_wronghost587 && run smtp_wronghost587 587 smtp 587 --cert $LAB/wronghost.crt --key $LAB/wronghost.key --tlsmin 1.2 --tlsmax 1.2 -- -starttls smtp -connect 127.0.0.1:587 -tls1_2 -servername mail.lab.test -- 'EHLO c\r\nQUIT\r\n'
want smtp_weaksig587 && run smtp_weaksig587 587 smtp 587 --cert $LAB/weak.crt --key $LAB/weak.csr.key --tlsmin 1.2 --tlsmax 1.2 --ciphers AES128-SHA@SECLEVEL=0 -- -starttls smtp -connect 127.0.0.1:587 -tls1_2 -cipher AES128-SHA@SECLEVEL=0 -servername mail.lab.test -- 'EHLO c\r\nQUIT\r\n'
want smtp13_expired_blind587 && run smtp13_expired_blind587 587 smtp 587 --cert $LAB/expired.crt --key $LAB/expired.key -- -starttls smtp -connect 127.0.0.1:587 -tls1_3 -servername mail.lab.test -- 'EHLO c\r\nQUIT\r\n'

if want smtp_nostarttls587; then
  NAME=smtp_nostarttls587; PORT=587; : > "$OUT/$NAME.tls.txt"
  start_cap "$NAME"
  start_server smtp 587 --cert $G --key $GK --no-starttls
  timeout 10 python3 -c "import socket;s=socket.create_connection(('127.0.0.1',587),timeout=8);f=s.makefile('rwb');f.readline();f.write(b'EHLO c\r\n');f.flush();[f.readline() for _ in range(3)];f.write(b'QUIT\r\n');f.flush();f.readline();s.close()" >/dev/null 2>&1
  stop_all; finish "$NAME" "$PORT"
fi
if want smtp_strip_ignored587; then
  NAME=smtp_strip_ignored587; PORT=587; : > "$OUT/$NAME.tls.txt"
  start_cap "$NAME"
  start_server smtp 587 --cert $G --key $GK
  timeout 10 python3 -c "import socket,base64;s=socket.create_connection(('127.0.0.1',587),timeout=8);f=s.makefile('rwb');f.readline();f.write(b'EHLO c\r\n');f.flush();[f.readline() for _ in range(3)];tok=base64.b64encode(b'\x00user\x00secret').decode();f.write(('AUTH PLAIN '+tok+'\r\n').encode());f.flush();f.readline();f.write(b'QUIT\r\n');f.flush();f.readline();s.close()" >/dev/null 2>&1
  stop_all; finish "$NAME" "$PORT"
fi
if want smtp_stripped_proxy587; then
  NAME=smtp_stripped_proxy587; PORT=587; : > "$OUT/$NAME.tls.txt"
  timeout 25 python3 scripts/lab_strip_proxy.py 587 1587 >/dev/null 2>&1 &
  PROXY_PID=$!
  timeout 25 python3 scripts/lab_mail.py server smtp 1587 --cert $G --key $GK >/dev/null 2>&1 &
  REAL_PID=$!
  sleep 1
  start_cap "$NAME"
  sleep 1
  timeout 10 python3 -c "import socket,base64;s=socket.create_connection(('127.0.0.1',587),timeout=8);f=s.makefile('rwb');f.readline();f.write(b'EHLO c\r\n');f.flush();[f.readline() for _ in range(2)];tok=base64.b64encode(b'\x00user\x00secret').decode();f.write(('AUTH PLAIN '+tok+'\r\n').encode());f.flush();f.readline();f.write(b'QUIT\r\n');f.flush();f.readline();s.close()" >/dev/null 2>&1
  kill $PROXY_PID $REAL_PID 2>/dev/null
  stop_all; finish "$NAME" "$PORT"
fi

want smtp12_implicit465 && run smtp12_implicit465 465 smtp-implicit 465 --cert $G --key $GK --tlsmin 1.2 --tlsmax 1.2 -- -connect 127.0.0.1:465 -tls1_2 -servername mail.lab.test -- 'EHLO c\r\nQUIT\r\n'
want smtp13_implicit465 && run smtp13_implicit465 465 smtp-implicit 465 --cert $G --key $GK -- -connect 127.0.0.1:465 -tls1_3 -servername mail.lab.test -- 'EHLO c\r\nQUIT\r\n'
want smtp10_implicit465 && run smtp10_implicit465 465 smtp-implicit 465 --cert $G --key $GK --tlsmin 1.0 --tlsmax 1.0 --ciphers AES128-SHA@SECLEVEL=0 -- -connect 127.0.0.1:465 -tls1 -cipher AES128-SHA@SECLEVEL=0 -- 'EHLO c\r\nQUIT\r\n'
want imap13_starttls143 && run imap13_starttls143 143 imap 143 --cert $G --key $GK -- -starttls imap -connect 127.0.0.1:143 -tls1_3 -servername mail.lab.test -- 'a001 LOGOUT\r\n'
if want imap_plain143; then
  NAME=imap_plain143; PORT=143; : > "$OUT/$NAME.tls.txt"
  start_cap "$NAME"
  start_server imap 143 --cert $G --key $GK --no-starttls
  timeout 10 python3 -c "import socket;s=socket.create_connection(('127.0.0.1',143),timeout=8);f=s.makefile('rwb');f.readline();f.write(b'a001 CAPABILITY\r\n');f.flush();f.readline();f.readline();f.write(b'a002 LOGOUT\r\n');f.flush();f.readline();s.close()" >/dev/null 2>&1
  stop_all; finish "$NAME" "$PORT"
fi
want imap13_implicit993 && run imap13_implicit993 993 imap-implicit 993 --cert $G --key $GK -- -connect 127.0.0.1:993 -tls1_3 -servername mail.lab.test -- 'a001 LOGOUT\r\n'
want pop13_stls110 && run pop13_stls110 110 pop3 110 --cert $G --key $GK -- -starttls pop3 -connect 127.0.0.1:110 -tls1_3 -servername mail.lab.test -- 'QUIT\r\n'
if want pop_plain110; then
  NAME=pop_plain110; PORT=110; : > "$OUT/$NAME.tls.txt"
  start_cap "$NAME"
  start_server pop3 110 --cert $G --key $GK --no-starttls
  timeout 10 python3 -c "import socket;s=socket.create_connection(('127.0.0.1',110),timeout=8);f=s.makefile('rwb');f.readline();f.write(b'CAPA\r\n');f.flush();[f.readline() for _ in range(4)];f.write(b'QUIT\r\n');f.flush();f.readline();s.close()" >/dev/null 2>&1
  stop_all; finish "$NAME" "$PORT"
fi
want pop12_implicit995 && run pop12_implicit995 995 pop3-implicit 995 --cert $G --key $GK --tlsmin 1.2 --tlsmax 1.2 -- -connect 127.0.0.1:995 -tls1_2 -servername mail.lab.test -- 'QUIT\r\n'
want imap12_login143 && run imap12_login143 143 imap 143 --cert $G --key $GK --tlsmin 1.2 --tlsmax 1.2 -- -starttls imap -connect 127.0.0.1:143 -tls1_2 -servername mail.lab.test -- 'a001 LOGIN user secret\r\na002 LOGOUT\r\n'
echo ALLDONE
