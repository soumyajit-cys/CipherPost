#!/bin/bash
# Item 3 capture driver: runs each lab scenario (server + client) under dumpcap.
# Usage: ./scripts/lab_capture.sh <outdir> [scenario-name ...]
# Lab dirs: certs in /tmp/opencode/maillab, harness scripts/lab_mail.py.
# Each scenario: dumpcap on lo (3s head start) -> server -> client -> filter port.
LAB=/tmp/opencode/maillab
OUT=${1:-/tmp/opencode/maillab/caps}; shift || true
mkdir -p "$OUT"
HARNESS="python3 scripts/lab_mail.py server"

start_cap() { dumpcap -i lo -F pcap -w "$OUT/$1.raw.pcap" >/dev/null 2>&1 & sleep 3; }
stop_cap() { pkill -f "dumpcap -i lo" 2>/dev/null; pkill -f "lab_mail.py server" 2>/dev/null; sleep 1; }
finish() { # name port
  tshark -r "$OUT/$1.raw.pcap" -Y "tcp.port==$2" -F pcap -w "$OUT/$1.pcap" 2>/dev/null
  rm -f "$OUT/$1.raw.pcap"
  echo "$1: $(capinfos "$OUT/$1.pcap" 2>/dev/null | grep -oP 'Number of packets\s+=\s+\K\d+') pkts"
}
scli() { # extra s_client args read from stdin dialog via $DIALOG
  printf "%b" "$DIALOG" | timeout 12 openssl s_client $SCARGS -CAfile $LAB/ca.crt -quiet >>"$OUT/$NAME.tls.txt" 2>&1
}

run() { # name port server_args sclient_args dialog
  NAME=$1; PORT=$2; SARGS=$3; SCARGS=$4; DIALOG=$5
  start_cap "$NAME"
  timeout 25 python3 scripts/lab_mail.py server $SARGS >/dev/null 2>&1 &
  sleep 2
  scli
  stop_cap
  finish "$NAME" "$PORT"
}

ONLY="$*"
want() { [ -z "$ONLY" ] && return 0; case " $ONLY " in *" $1 "*) return 0;; *) return 1;; esac; }

want smtp13_starttls587 && run smtp13_starttls587 587 "smtp 587 --cert $LAB/good.crt --key $LAB/good.key" "-starttls smtp -connect 127.0.0.1:587 -tls1_3 -servername mail.lab.test" 'EHLO c\r\nQUIT\r\n'
want smtp12_starttls587 && run smtp12_starttls587 587 "smtp 587 --cert $LAB/good.crt --key $LAB/good.key" "-starttls smtp -connect 127.0.0.1:587 -tls1_2 -servername mail.lab.test" 'EHLO c\r\nQUIT\r\n'
want smtp10_starttls587 && run smtp10_starttls587 587 "smtp 587 --cert $LAB/good.crt --key $LAB/good.key --tlsmin 1.0 --tlsmax 1.0 --ciphers AES128-SHA@SECLEVEL=0" "-starttls smtp -connect 127.0.0.1:587 -tls1 -cipher AES128-SHA@SECLEVEL=0" 'EHLO c\r\nQUIT\r\n'
want smtp11_starttls587 && run smtp11_starttls587 587 "smtp 587 --cert $LAB/good.crt --key $LAB/good.key --tlsmin 1.1 --tlsmax 1.1 --ciphers AES128-SHA@SECLEVEL=0" "-starttls smtp -connect 127.0.0.1:587 -tls1_1 -cipher AES128-SHA@SECLEVEL=0" 'EHLO c\r\nQUIT\r\n'
want smtp_weakcbc587 && run smtp_weakcbc587 587 "smtp 587 --cert $LAB/good.crt --key $LAB/good.key --tlsmin 1.2 --tlsmax 1.2 --ciphers AES128-SHA@SECLEVEL=0" "-starttls smtp -connect 127.0.0.1:587 -tls1_2 -cipher AES128-SHA@SECLEVEL=0 -servername mail.lab.test" 'EHLO c\r\nQUIT\r\n'
want smtp_expired587 && run smtp_expired587 587 "smtp 587 --cert $LAB/expired.crt --key $LAB/expired.key --tlsmin 1.2 --tlsmax 1.2" "-starttls smtp -connect 127.0.0.1:587 -tls1_2 -servername mail.lab.test" 'EHLO c\r\nQUIT\r\n'
want smtp_self587 && run smtp_self587 587 "smtp 587 --cert $LAB/self.crt --key $LAB/self.key --tlsmin 1.2 --tlsmax 1.2" "-starttls smtp -connect 127.0.0.1:587 -tls1_2 -servername mail.lab.test" 'EHLO c\r\nQUIT\r\n'
want smtp_wronghost587 && run smtp_wronghost587 587 "smtp 587 --cert $LAB/wronghost.crt --key $LAB/wronghost.key --tlsmin 1.2 --tlsmax 1.2" "-starttls smtp -connect 127.0.0.1:587 -tls1_2 -servername mail.lab.test" 'EHLO c\r\nQUIT\r\n'
want smtp_weaksig587 && run smtp_weaksig587 587 "smtp 587 --cert $LAB/weak.crt --key $LAB/weak.csr.key --tlsmin 1.2 --tlsmax 1.2 --ciphers AES128-SHA@SECLEVEL=0" "-starttls smtp -connect 127.0.0.1:587 -tls1_2 -cipher AES128-SHA@SECLEVEL=0 -servername mail.lab.test" 'EHLO c\r\nQUIT\r\n'
want smtp13_expired_blind587 && run smtp13_expired_blind587 587 "smtp 587 --cert $LAB/expired.crt --key $LAB/expired.key" "-starttls smtp -connect 127.0.0.1:587 -tls1_3 -servername mail.lab.test" 'EHLO c\r\nQUIT\r\n'

# plaintext / strip scenarios use raw python clients
raw_client() { timeout 10 python3 -c "$1" >/dev/null 2>&1; }
if want smtp_nostarttls587; then
  NAME=smtp_nostarttls587; PORT=587
  start_cap "$NAME"
  timeout 25 python3 scripts/lab_mail.py server smtp 587 --cert $LAB/good.crt --key $LAB/good.key --no-starttls >/dev/null 2>&1 &
  sleep 2
  raw_client "import socket;s=socket.create_connection(('127.0.0.1',587),timeout=8);f=s.makefile('rwb');print(f.readline());f.write(b'EHLO c\r\n');f.flush();[print(f.readline()) for _ in range(3)];f.write(b'QUIT\r\n');f.flush();print(f.readline());s.close()"
  stop_cap; finish "$NAME" "$PORT"
fi
if want smtp_strip_ignored587; then
  NAME=smtp_strip_ignored587; PORT=587
  start_cap "$NAME"
  timeout 25 python3 scripts/lab_mail.py server smtp 587 --cert $LAB/good.crt --key $LAB/good.key >/dev/null 2>&1 &
  sleep 2
  raw_client "import socket,base64;s=socket.create_connection(('127.0.0.1',587),timeout=8);f=s.makefile('rwb');f.readline();f.write(b'EHLO c\r\n');f.flush();d=b'';import select;[f.write(b'') or None];lines=[f.readline() for _ in range(3)];tok=base64.b64encode(b'\x00user\x00secret').decode();f.write(('AUTH PLAIN '+tok+'\r\n').encode());f.flush();print(f.readline());f.write(b'QUIT\r\n');f.flush();print(f.readline());s.close()"
  stop_cap; finish "$NAME" "$PORT"
fi
if want smtp_stripped_proxy587; then
  NAME=smtp_stripped_proxy587; PORT=587
  timeout 25 python3 scripts/lab_mail.py server smtp 1587 --cert $LAB/good.crt --key $LAB/good.key >/dev/null 2>&1 &
  sleep 1
  timeout 25 python3 -c "
import socket,threading
def pipe(a,b,flt=None):
    try:
        while True:
            d=a.recv(65536)
            if not d: break
            if flt: d=flt(d)
            b.sendall(d)
    except Exception: pass
    try: b.shutdown(socket.SHUT_WR)
    except Exception: pass
srv=socket.socket();srv.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);srv.bind(('127.0.0.1',587));srv.listen(1)
c,_=srv.accept()
up=socket.create_connection(('127.0.0.1',1587),timeout=8)
t1=threading.Thread(target=pipe,args=(c,up));t2=threading.Thread(target=pipe,args=(up,c,lambda d:d.replace(b'STARTTLS',b'XXXXXXXX')))
t1.start();t2.start();t1.join();t2.join()" >/dev/null 2>&1 &
  sleep 1
  start_cap "$NAME"
  sleep 2
  raw_client "import socket,base64;s=socket.create_connection(('127.0.0.1',587),timeout=8);f=s.makefile('rwb');f.readline();f.write(b'EHLO c\r\n');f.flush();lines=[f.readline() for _ in range(2)];tok=base64.b64encode(b'\x00user\x00secret').decode();f.write(('AUTH PLAIN '+tok+'\r\n').encode());f.flush();print(f.readline());f.write(b'QUIT\r\n');f.flush();print(f.readline());s.close()"
  stop_cap; finish "$NAME" "$PORT"
fi

want smtp12_implicit465 && run smtp12_implicit465 465 "smtp-implicit 465 --cert $LAB/good.crt --key $LAB/good.key --tlsmin 1.2 --tlsmax 1.2" "-connect 127.0.0.1:465 -tls1_2 -servername mail.lab.test" 'EHLO c\r\nQUIT\r\n'
want smtp13_implicit465 && run smtp13_implicit465 465 "smtp-implicit 465 --cert $LAB/good.crt --key $LAB/good.key" "-connect 127.0.0.1:465 -tls1_3 -servername mail.lab.test" 'EHLO c\r\nQUIT\r\n'
want smtp10_implicit465 && run smtp10_implicit465 465 "smtp-implicit 465 --cert $LAB/good.crt --key $LAB/good.key --tlsmin 1.0 --tlsmax 1.0 --ciphers AES128-SHA@SECLEVEL=0" "-connect 127.0.0.1:465 -tls1 -cipher AES128-SHA@SECLEVEL=0" 'EHLO c\r\nQUIT\r\n'
want imap13_starttls143 && run imap13_starttls143 143 "imap 143 --cert $LAB/good.crt --key $LAB/good.key" "-starttls imap -connect 127.0.0.1:143 -tls1_3 -servername mail.lab.test" 'a001 LOGOUT\r\n'
if want imap_plain143; then
  NAME=imap_plain143; PORT=143
  start_cap "$NAME"
  timeout 25 python3 scripts/lab_mail.py server imap 143 --cert $LAB/good.crt --key $LAB/good.key --no-starttls >/dev/null 2>&1 &
  sleep 2
  raw_client "import socket;s=socket.create_connection(('127.0.0.1',143),timeout=8);f=s.makefile('rwb');print(f.readline());f.write(b'a001 CAPABILITY\r\n');f.flush();print(f.readline());print(f.readline());f.write(b'a002 LOGOUT\r\n');f.flush();print(f.readline());s.close()"
  stop_cap; finish "$NAME" "$PORT"
fi
want imap13_implicit993 && run imap13_implicit993 993 "imap-implicit 993 --cert $LAB/good.crt --key $LAB/good.key" "-connect 127.0.0.1:993 -tls1_3 -servername mail.lab.test" 'a001 LOGOUT\r\n'
want pop13_stls110 && run pop13_stls110 110 "pop3 110 --cert $LAB/good.crt --key $LAB/good.key" "-starttls pop3 -connect 127.0.0.1:110 -tls1_3 -servername mail.lab.test" 'QUIT\r\n'
if want pop_plain110; then
  NAME=pop_plain110; PORT=110
  start_cap "$NAME"
  timeout 25 python3 scripts/lab_mail.py server pop3 110 --cert $LAB/good.crt --key $LAB/good.key --no-starttls >/dev/null 2>&1 &
  sleep 2
  raw_client "import socket;s=socket.create_connection(('127.0.0.1',110),timeout=8);f=s.makefile('rwb');print(f.readline());f.write(b'CAPA\r\n');f.flush();l=[];[l.append(f.readline()) for _ in range(4)];print(l);f.write(b'QUIT\r\n');f.flush();print(f.readline());s.close()"
  stop_cap; finish "$NAME" "$PORT"
fi
want pop12_implicit995 && run pop12_implicit995 995 "pop3-implicit 995 --cert $LAB/good.crt --key $LAB/good.key --tlsmin 1.2 --tlsmax 1.2" "-connect 127.0.0.1:995 -tls1_2 -servername mail.lab.test" 'QUIT\r\n'
want imap12_login143 && run imap12_login143 143 "imap 143 --cert $LAB/good.crt --key $LAB/good.key --tlsmin 1.2 --tlsmax 1.2" "-starttls imap -connect 127.0.0.1:143 -tls1_2 -servername mail.lab.test" 'a001 LOGIN user secret\r\na002 LOGOUT\r\n'
echo ALLDONE
