#!/bin/bash
# Mail lab entrypoint: configures Postfix/Dovecot for the requested TLS profile,
# creates fixed lab accounts, and starts the daemons in the foreground.
# Lab-only. Accounts and passwords are fixed test values, never production.
set -eu

PROFILE="${TLS_PROFILE:-modern}"
MAIL_DOMAIN="${MAIL_DOMAIN:-lab.test}"
CERT_DIR="${CERT_DIR:-/etc/lab-certs}"
CERT="${CERT:-$CERT_DIR/good.crt}"
KEY="${KEY:-$CERT_DIR/good.key}"

echo "[mail-lab] profile=$PROFILE domain=$MAIL_DOMAIN cert=$CERT"

# --- TLS profile mapping -----------------------------------------------------
# modern            : TLS 1.2+ only, strong ciphers (expected: no weak-TLS findings)
# legacy-tolerant   : TLS 1.0/1.1 allowed (expected: protocol-version findings)
# deliberately-broken: expired cert, weak ciphers, plaintext AUTH on 587
#                     (expected: expired-certificate, weak-cipher, plaintext findings)
case "$PROFILE" in
  modern)
    TLS_MIN="1.2"; TLS_MAX="1.3"; CIPHERS="HIGH:!aNULL:!MD5:!3DES:!RC4"; AUTH_TLS_ONLY="yes"
    ;;
  legacy-tolerant)
    TLS_MIN="1.0"; TLS_MAX="1.3"; CIPHERS="ALL:!aNULL:!eNULL"; AUTH_TLS_ONLY="yes"
    ;;
  deliberately-broken)
    TLS_MIN="1.0"; TLS_MAX="1.3"; CIPHERS="ALL:!aNULL:!eNULL"; AUTH_TLS_ONLY="no"
    CERT="${CERT:-$CERT_DIR/expired.crt}"
    KEY="${KEY:-$CERT_DIR/expired.key}"
    ;;
  *)
    echo "[mail-lab] unknown TLS_PROFILE '$PROFILE' (use modern|legacy-tolerant|deliberately-broken)" >&2
    exit 2
    ;;
esac

# --- Lab accounts (fixed, documented, never real) ----------------------------
LAB_USER="${LAB_USER:-alice}"
LAB_PASS="${LAB_PASS:-alice-lab-pass}"
mkdir -p /home/"$LAB_USER"
if ! id "$LAB_USER" >/dev/null 2>&1; then
  useradd -m -s /usr/sbin/nologin "$LAB_USER" || true
fi
echo "$LAB_USER:$LAB_PASS" | chpasswd

# --- Postfix main.cf ---------------------------------------------------------
postconf -e "myhostname = mail.$MAIL_DOMAIN"
postconf -e "mydomain = $MAIL_DOMAIN"
postconf -e "myorigin = \$mydomain"
postconf -e "mydestination = \$myhostname, localhost.\$mydomain, localhost, \$mydomain"
postconf -e "inet_interfaces = all"
postconf -e "inet_protocols = all"
postconf -e "smtpd_tls_cert_file = $CERT"
postconf -e "smtpd_tls_key_file = $KEY"
postconf -e "smtpd_tls_mandatory_protocols = >=TLSv$TLS_MIN, <=TLSv$TLS_MAX"
postconf -e "smtpd_tls_protocols = >=TLSv$TLS_MIN, <=TLSv$TLS_MAX"
postconf -e "smtp_tls_mandatory_protocols = >=TLSv$TLS_MIN, <=TLSv$TLS_MAX"
postconf -e "smtp_tls_protocols = >=TLSv$TLS_MIN, <=TLSv$TLS_MAX"
postconf -e "smtpd_tls_mandatory_ciphers = export"   # allow the profile's cipher list below
postconf -e "smtpd_tls_ciphers = $CIPHERS"
postconf -e "smtpd_tls_mandatory_ciphers = $CIPHERS"
postconf -e "smtpd_tls_auth_only = $AUTH_TLS_ONLY"
postconf -e "smtpd_sasl_type = dovecot"
postconf -e "smtpd_sasl_path = private/auth"
postconf -e "smtpd_sasl_auth_enable = yes"
postconf -e "smtpd_sasl_security_options = noanonymous"
postconf -e "broken_sasl_auth_clients = yes"
postconf -e "smtpd_recipient_restrictions = permit_sasl_authenticated,permit_mynetworks,reject_unauth_destination"
postconf -e "smtpd_tls_security_level = may"
postconf -e "smtp_tls_security_level = may"
postconf -e "smtp_tls_CAfile = $CERT_DIR/ca.crt"

# Explicit listeners: submission on 587 (always), SMTPS on 465 in
# deliberately-broken (to allow plaintext AUTH on a "secure" port).
cat >> /etc/postfix/master.cf <<EOF

submission inet n       -       y       -       -       smtpd
  -o syslog_name=postfix/submission
  -o smtpd_tls_security_level=may
  -o smtpd_sasl_auth_enable=yes
  -o smtpd_tls_auth_only=$AUTH_TLS_ONLY
  -o smtpd_tls_mandatory_protocols=>=TLSv$TLS_MIN,<=TLSv$TLS_MAX
  -o smtpd_tls_protocols=>=TLSv$TLS_MIN,<=TLSv$TLS_MAX
  -o smtpd_tls_ciphers=$CIPHERS
smtps     inet  n       -       y       -       -       smtpd
  -o syslog_name=postfix/smtps
  -o smtpd_tls_wrappermode=yes
  -o smtpd_sasl_auth_enable=yes
  -o smtpd_tls_auth_only=$AUTH_TLS_ONLY
  -o smtpd_tls_mandatory_protocols=>=TLSv$TLS_MIN,<=TLSv$TLS_MAX
  -o smtpd_tls_protocols=>=TLSv$TLS_MIN,<=TLSv$TLS_MAX
  -o smtpd_tls_ciphers=$CIPHERS
EOF

# --- Dovecot ------------------------------------------------------------------
cat > /etc/dovecot/conf.d/99-lab.conf <<EOF
disable_plaintext_auth = $( [ "$AUTH_TLS_ONLY" = "yes" ] && echo yes || echo no )
ssl = required
ssl_cert = <$CERT
ssl_key = <$KEY
ssl_min_protocol = TLSv$TLS_MIN
ssl_max_protocol = TLSv$TLS_MAX
ssl_cipher_list = $CIPHERS
mail_location = maildir:/home/%n/Maildir
protocols = imap pop3
service auth {
  unix_listener /var/spool/postfix/private/auth {
    mode = 0660
    user = postfix
    group = postfix
  }
}
EOF

mkdir -p /var/spool/postfix/private/auth
chown postfix:postfix /var/spool/postfix/private/auth || true
chown postfix:postfix /var/spool/postfix/private || true

# --- Start daemons ------------------------------------------------------------
echo "[mail-lab] starting dovecot + postfix (profile=$PROFILE)"
dovecot -F &
exec postfix start -c /etc/postfix 2>/dev/null || postfix start-fg
