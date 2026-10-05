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
  # dumpcap on lo (proven in Item 2 PQ runs). Requires a quiet box: stray
  # capturers/CPU hogs starve AF_PACKET delivery; keep runs serial and clean.
  dumpcap -i lo -F pcap -w "$OUT/$1.raw.pcap" >/dev/null 2>&1 &
  DCAP_PID=$!
  sleep 8
  kill -0 $DCAP_PID 2>/dev/null || { echo "capturer failed to start"; return 1; }
}
start_server() { # pollport harness_args...
  PORT=$1; shift
  if timeout 2 bash -c "</dev/tcp/127.0.0.1/$PORT" 2>/dev/null; then
    echo "ABORTED, port $PORT already held (stray server?)" | tee -a "$OUT/driver.log"
    return 1
  fi
  timeout 300 python3 scripts/lab_mail.py server "$@" >"$OUT/srv_$PORT.log" 2>&1 &
  SRV_PID=$!
  # wait until the port is actually listening (bind can lag or fail)
  for _ in $(seq 1 10); do
    if timeout 2 bash -c "</dev/tcp/127.0.0.1/$PORT" 2>/dev/null; then
      sleep 1
      return 0
    fi
    kill -0 $SRV_PID 2>/dev/null || { echo "server for port $PORT died early"; cat "$OUT/srv_$PORT.log"; return 1; }
    sleep 1
  done
  echo "server for port $PORT never listened"
  return 1
}
stop_all() {
  # Kill child capturers first (tshark forks dumpcap; killing only the parent
  # orphans the child, whose unflushed tail data is then lost with it).
  [ -n "$DCAP_PID" ] && pkill -P "$DCAP_PID" 2>/dev/null
  [ -n "$SRV_PID" ] && kill "$SRV_PID" 2>/dev/null
  [ -n "$DCAP_PID" ] && kill "$DCAP_PID" 2>/dev/null
  ( wait_cap ) & WAITCAP_PID=$!
  # wait for capturer exit so its write buffer is flushed to disk
  for _ in $(seq 1 10); do
    [ -n "$DCAP_PID" ] && kill -0 "$DCAP_PID" 2>/dev/null || break
    sleep 1
  done
  sleep 2
  echo "[$NAME] capturer exit: $DCAP_EXIT" >> "$OUT/driver.log"
  SRV_PID=""; DCAP_PID=""
}

# wait_cap: wait for capturer death with timestamp (diagnoses early death).
wait_cap() {
  wait $DCAP_PID 2>/dev/null
  DCAP_EXIT=$?
  date "+cap-dead %T (exit=$DCAP_EXIT)" >> "$OUT/driver.log"
}
finish() { # name port
  # Wait until no process holds the raw file (dead-but-unreaped writers or a
  # missed kill would otherwise let us filter a still-growing file).
  for _ in $(seq 1 10); do
    fuser -s "$OUT/$1.raw.pcap" 2>/dev/null || break
    sleep 1
  done
  # lo capture is already Ethernet: plain filter, no conversion.
  tshark -r "$OUT/$1.raw.pcap" -Y "tcp.port==$2" -F pcap -w "$OUT/$1.pcap" 2>/dev/null
  echo "[$1] raw kept at $OUT/$1.raw.pcap size=$(stat -c%s "$OUT/$1.raw.pcap")" >> "$OUT/driver.log"
  _n=$(capinfos "$OUT/$1.pcap" 2>/dev/null | grep -o 'Number of packets.*' | grep -o '[0-9]*' | head -n 1)
  _hello=$(tshark -r "$OUT/$1.pcap" -Y 'tls.handshake.type==1' 2>/dev/null | wc -l)
  echo "$1: ${_n:-0} pkts, ${_hello:-0} hellos"
}
# paced_stdin: emit each CRLF-terminated line with 1s spacing. A full dialog
# fired in milliseconds intermittently vanishes from loopback capture on this
# host (see docs/evidence/real-eval.md); pacing changes timing only, never bytes.
paced_stdin() {
  python3 -c "
import sys, time
data = sys.stdin.buffer.read().decode().replace(chr(13) + chr(10), chr(10)).split(chr(10))
for line in data:
    if not line:
        continue
    sys.stdout.buffer.write((line + chr(13) + chr(10)).encode())
    sys.stdout.buffer.flush()
    time.sleep(1)
"
}

run() { # name port server_args... -- sclient_args... -- dialog
  NAME=$1; PORT=$2; shift 2
  : > "$OUT/$NAME.tls.txt"
  SARGS=()
  while [ "$1" != "--" ]; do SARGS+=("$1"); shift; done; shift
  SCARGS=""
  while [ "$1" != "--" ]; do SCARGS="$SCARGS $1"; shift; done; shift
  DIALOG=$1
  echo "[$NAME] starting cap" >> "$OUT/driver.log"; date +%T >> "$OUT/driver.log"
  date "+cap-start %T" >> "$OUT/driver.log"
  start_cap "$NAME" || return 1
  echo "[$NAME] cap live dcap=$DCAP_PID dcap_is=$(ps -p $DCAP_PID -o comm= 2>/dev/null) rawbytes=$(stat -c%s "$OUT/$NAME.raw.pcap")" >> "$OUT/driver.log"
  date "+srv-start %T" >> "$OUT/driver.log"
  start_server "$PORT" "${SARGS[@]}" || return 1
  date "+cli-start %T" >> "$OUT/driver.log"
  # shellcheck disable=SC2086
  printf "%b" "$DIALOG" | paced_stdin | openssl s_client $SCARGS -CAfile $LAB/ca.crt -quiet >>"$OUT/$NAME.tls.txt" 2>&1 & CLI_PID=$!
  # wait for dialog idle (no tls.txt growth for 2s = both sides done talking),
  # then kill the client: its RST/FIN completes the stream so reassembly emits
  # the session instead of dropping it as incomplete. (s_client -quiet idles on
  # stdin EOF; without this it lingers past capture end.)
  _last=-1; _still=0
  for _ in $(seq 1 25); do
    _size=$(stat -c%s "$OUT/$NAME.tls.txt" 2>/dev/null || echo 0)
    if [ "$_size" = "$_last" ]; then _still=$((_still+1)); else _still=0; fi
    _last=$_size
    kill -0 $CLI_PID 2>/dev/null || break
    [ "$_still" -ge 2 ] && [ "$_size" -gt 0 ] && break
    sleep 1
  done
  if kill -0 $CLI_PID 2>/dev/null; then
    echo "[$NAME] client alive at kill time, killing $CLI_PID" >> "$OUT/driver.log"
    kill $CLI_PID 2>/dev/null
  else
    echo "[$NAME] client already exited before kill" >> "$OUT/driver.log"
  fi
  wait $CLI_PID 2>/dev/null
  for _ in $(seq 1 5); do
    kill -0 $CLI_PID 2>/dev/null || break
    sleep 1
  done
  if kill -0 $CLI_PID 2>/dev/null; then
    echo "[$NAME] WARNING client $CLI_PID survived TERM, KILLing" >> "$OUT/driver.log"
    kill -9 $CLI_PID 2>/dev/null
    sleep 1
  fi
  date "+cli-end %T" >> "$OUT/driver.log"
  echo "[$NAME] pre-stop dcap_alive=$(kill -0 $DCAP_PID 2>/dev/null && echo yes || echo NO) dcap_is=$(ps -p $DCAP_PID -o comm= 2>/dev/null) rawbytes=$(stat -c%s "$OUT/$NAME.raw.pcap")" >> "$OUT/driver.log"
  stop_all
  echo "[$NAME] post-stop rawbytes=$(stat -c%s "$OUT/$NAME.raw.pcap")" >> "$OUT/driver.log"
  finish "$NAME" "$PORT"
}

ONLY="$*"
want() { [ -z "$ONLY" ] && return 0; case " $ONLY " in *" $1 "*) return 0;; *) return 1;; esac; }

run_implicit() { # name port kind tlsmin tlsmax ciphers(-- or -) server_cert server_key
  NAME=$1; PORT=$2; KIND=$3; TMIN=$4; TMAX=$5; CIPH=$6; CERT=$7; KEY=$8
  : > "$OUT/$NAME.tls.txt"
  echo "[$NAME] starting cap" >> "$OUT/driver.log"
  start_cap "$NAME" || return 1
  date "+srv-start %T" >> "$OUT/driver.log"
  if [ "$CIPH" = "-" ]; then CARG=""; else CARG="--ciphers $CIPH"; fi
  # shellcheck disable=SC2086
  start_server "$PORT" "$KIND" "$PORT" --cert "$CERT" --key "$KEY" --tlsmin "$TMIN" --tlsmax "$TMAX" $CARG || return 1
  date "+cli-start %T" >> "$OUT/driver.log"
  # shellcheck disable=SC2086
  timeout 25 python3 scripts/lab_mail.py client-implicit "$KIND" "$PORT" --tlsmin "$TMIN" --tlsmax "$TMAX" $CARG >>"$OUT/$NAME.tls.txt" 2>&1
  date "+cli-end %T" >> "$OUT/driver.log"
  sleep 2
  stop_all
  finish "$NAME" "$PORT"
}

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
  start_server 587 smtp 587 --cert $G --key $GK --no-starttls
  timeout 10 python3 -c "import socket;s=socket.create_connection(('127.0.0.1',587),timeout=8);f=s.makefile('rwb');f.readline();f.write(b'EHLO c\r\n');f.flush();[f.readline() for _ in range(3)];import time as _t;_t.sleep(1);f.write(b'QUIT\r\n');f.flush();f.readline();s.close()" >/dev/null 2>&1
  sleep 5
  stop_all; finish "$NAME" "$PORT"
fi
if want smtp_strip_ignored587; then
  NAME=smtp_strip_ignored587; PORT=587; : > "$OUT/$NAME.tls.txt"
  start_cap "$NAME"
  start_server 587 smtp 587 --cert $G --key $GK
  timeout 10 python3 -c "import socket,base64;s=socket.create_connection(('127.0.0.1',587),timeout=8);f=s.makefile('rwb');f.readline();f.write(b'EHLO c\r\n');f.flush();[f.readline() for _ in range(3)];tok=base64.b64encode(b'\x00user\x00secret').decode();f.write(('AUTH PLAIN '+tok+'\r\n').encode());f.flush();f.readline();s.close()  # victim disconnects after creds (no QUIT): hang-proof, realistic" >/dev/null 2>&1
  sleep 5
  stop_all; finish "$NAME" "$PORT"
fi
if want smtp_stripped_proxy587; then
  NAME=smtp_stripped_proxy587; PORT=587; : > "$OUT/$NAME.tls.txt"
  _held=0
  for _p in 587 1587; do
    if timeout 2 bash -c "</dev/tcp/127.0.0.1/$_p" 2>/dev/null; then
      echo "$NAME: ABORTED, port $_p held" | tee -a "$OUT/driver.log"
      _held=1
    fi
  done
  if [ "$_held" = "1" ]; then echo "$NAME: skipped"; else
  timeout 300 python3 scripts/lab_strip_proxy.py 587 1587 >/dev/null 2>&1 &
  PROXY_PID=$!
  timeout 300 python3 scripts/lab_mail.py server smtp 1587 --cert $G --key $GK >/dev/null 2>&1 &
  REAL_PID=$!
  sleep 1
  start_cap "$NAME"
  sleep 1
  timeout 10 python3 -c "import socket,base64;s=socket.create_connection(('127.0.0.1',587),timeout=8);f=s.makefile('rwb');f.readline();f.write(b'EHLO c\r\n');f.flush();
while True:
    ln=f.readline().decode(errors='replace')
    if ln.startswith('250 ') or not ln: break
tok=base64.b64encode(b'\x00user\x00secret').decode();f.write(('AUTH PLAIN '+tok+'\r\n').encode());f.flush();f.readline();import time as _t;_t.sleep(1);f.write(b'QUIT\r\n');f.flush();f.readline();s.close()" >"$OUT/$NAME.out.txt" 2>"$OUT/$NAME.err.txt"
  kill $PROXY_PID $REAL_PID 2>/dev/null
  stop_all; finish "$NAME" "$PORT"
  fi
fi

want smtp12_implicit465 && run_implicit smtp12_implicit465 465 smtp-implicit 1.2 1.2 "-" $G $GK
want smtp13_implicit465 && run_implicit smtp13_implicit465 465 smtp-implicit 1.3 1.3 "-" $G $GK
want smtp10_implicit465 && run_implicit smtp10_implicit465 465 smtp-implicit 1.0 1.0 "AES128-SHA@SECLEVEL=0" $G $GK
want imap13_starttls143 && run imap13_starttls143 143 imap 143 --cert $G --key $GK -- -starttls imap -connect 127.0.0.1:143 -tls1_3 -servername mail.lab.test -- 'a001 LOGOUT\r\n'
if want imap_plain143; then
  NAME=imap_plain143; PORT=143; : > "$OUT/$NAME.tls.txt"
  start_cap "$NAME"
  start_server 143 imap 143 --cert $G --key $GK --no-starttls
  timeout 10 python3 -c "import socket;s=socket.create_connection(('127.0.0.1',143),timeout=8);f=s.makefile('rwb');f.readline();f.write(b'a001 CAPABILITY\r\n');f.flush();f.readline();f.readline();import time as _t;_t.sleep(1);f.write(b'a002 LOGOUT\r\n');f.flush();f.readline();s.close()" >/dev/null 2>&1
  sleep 5
  stop_all; finish "$NAME" "$PORT"
fi
want imap13_implicit993 && run_implicit imap13_implicit993 993 imap-implicit 1.3 1.3 "-" $G $GK
want pop13_stls110 && run pop13_stls110 110 pop3 110 --cert $G --key $GK -- -starttls pop3 -connect 127.0.0.1:110 -tls1_3 -servername mail.lab.test -- 'QUIT\r\n'
if want pop_plain110; then
  NAME=pop_plain110; PORT=110; : > "$OUT/$NAME.tls.txt"
  start_cap "$NAME"
  start_server 110 pop3 110 --cert $G --key $GK --no-starttls
  timeout 10 python3 -c "import socket;s=socket.create_connection(('127.0.0.1',110),timeout=8);f=s.makefile('rwb');f.readline();f.write(b'CAPA\r\n');f.flush();[f.readline() for _ in range(4)];import time as _t;_t.sleep(1);f.write(b'QUIT\r\n');f.flush();f.readline();s.close()" >/dev/null 2>&1
  sleep 5
  stop_all; finish "$NAME" "$PORT"
fi
want pop12_implicit995 && run_implicit pop12_implicit995 995 pop3-implicit 1.2 1.2 "-" $G $GK
want imap12_login143 && run imap12_login143 143 imap 143 --cert $G --key $GK --tlsmin 1.2 --tlsmax 1.2 -- -starttls imap -connect 127.0.0.1:143 -tls1_2 -servername mail.lab.test -- 'a001 LOGIN user secret\r\na002 LOGOUT\r\n'
echo ALLDONE
