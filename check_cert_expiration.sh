#!/bin/bash

# Nagios plugin to check certificate expiration

PROGNAME=$(basename "$0")

STATE_OK=0
STATE_WARNING=1
STATE_CRITICAL=2
STATE_UNKNOWN=3

usage() {
    cat <<EOF
Usage: $PROGNAME -s <source> [-w <warn_days>] [-c <critical_days>] [-f <format>]

Options:
  -s <source>         Certificate source: filesystem path or HTTP/HTTPS URL
  -w <warn_days>      Days before expiration to warn (default: 30)
  -c <critical_days>  Days before expiration to go critical (default: 15)
  -f <format>         Certificate format passed to openssl -inform (default: DER)
  -h                  Show this help message

Examples:
  $PROGNAME -s /etc/ssl/certs/mycert.der
  $PROGNAME -s https://example.com/cert.der -w 60 -c 30
  $PROGNAME -s /etc/ssl/certs/mycert.pem -f PEM
EOF
}

WARN_DAYS=30
CRITICAL_DAYS=15
FORMAT="DER"
SOURCE=""

while getopts ":s:w:c:f:h" opt; do
    case $opt in
        s) SOURCE="$OPTARG" ;;
        w) WARN_DAYS="$OPTARG" ;;
        c) CRITICAL_DAYS="$OPTARG" ;;
        f) FORMAT="$OPTARG" ;;
        h) usage; exit $STATE_OK ;;
        :) echo "UNKNOWN: Option -$OPTARG requires an argument."; exit $STATE_UNKNOWN ;;
        \?) echo "UNKNOWN: Invalid option -$OPTARG."; exit $STATE_UNKNOWN ;;
    esac
done

if [ -z "$SOURCE" ]; then
    echo "UNKNOWN: No certificate source specified. Use -s."
    exit $STATE_UNKNOWN
fi

if ! [[ "$WARN_DAYS" =~ ^[0-9]+$ ]]; then
    echo "UNKNOWN: Warning threshold must be a non-negative integer."
    exit $STATE_UNKNOWN
fi

if ! [[ "$CRITICAL_DAYS" =~ ^[0-9]+$ ]]; then
    echo "UNKNOWN: Critical threshold must be a non-negative integer."
    exit $STATE_UNKNOWN
fi

if [ "$CRITICAL_DAYS" -gt "$WARN_DAYS" ]; then
    echo "UNKNOWN: Critical threshold ($CRITICAL_DAYS days) must be <= warning threshold ($WARN_DAYS days)."
    exit $STATE_UNKNOWN
fi

CERT_FILE=""
TMPFILE=""

if [[ "$SOURCE" =~ ^https?:// ]]; then
    TMPFILE=$(mktemp /tmp/check_cert_expiration.XXXXXX)
    if ! curl -sSL --max-time 30 -o "$TMPFILE" "$SOURCE" 2>/dev/null; then
        rm -f "$TMPFILE"
        echo "UNKNOWN: Failed to download certificate from $SOURCE"
        exit $STATE_UNKNOWN
    fi
    CERT_FILE="$TMPFILE"
else
    if [ ! -f "$SOURCE" ]; then
        echo "UNKNOWN: Certificate file not found: $SOURCE"
        exit $STATE_UNKNOWN
    fi
    if [ ! -r "$SOURCE" ]; then
        echo "UNKNOWN: Certificate file not readable: $SOURCE"
        exit $STATE_UNKNOWN
    fi
    CERT_FILE="$SOURCE"
fi

cleanup() {
    [ -n "$TMPFILE" ] && rm -f "$TMPFILE"
}
trap cleanup EXIT

WARN_SECONDS=$(( WARN_DAYS * 86400 ))
CRITICAL_SECONDS=$(( CRITICAL_DAYS * 86400 ))

OPENSSL_OUT=$(openssl x509 -inform "$FORMAT" -in "$CERT_FILE" -noout -enddate 2>&1)
OPENSSL_RC=$?

if [ $OPENSSL_RC -ne 0 ]; then
    echo "UNKNOWN: Failed to parse certificate from $SOURCE (format: $FORMAT). openssl error: $OPENSSL_OUT"
    exit $STATE_UNKNOWN
fi

EXPIRY_DATE=$(echo "$OPENSSL_OUT" | sed 's/notAfter=//')

openssl x509 -inform "$FORMAT" -in "$CERT_FILE" -noout -checkend "$CRITICAL_SECONDS" > /dev/null 2>&1
if [ $? -ne 0 ]; then
    echo "CRITICAL: Certificate from $SOURCE expires on $EXPIRY_DATE (within ${CRITICAL_DAYS} days)"
    exit $STATE_CRITICAL
fi

openssl x509 -inform "$FORMAT" -in "$CERT_FILE" -noout -checkend "$WARN_SECONDS" > /dev/null 2>&1
if [ $? -ne 0 ]; then
    echo "WARNING: Certificate from $SOURCE expires on $EXPIRY_DATE (within ${WARN_DAYS} days)"
    exit $STATE_WARNING
fi

echo "OK: Certificate from $SOURCE expires on $EXPIRY_DATE (more than ${WARN_DAYS} days away)"
exit $STATE_OK
