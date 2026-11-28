#!/usr/bin/env bash
# Dev only: makes a throwaway CA and broker certificate, and stores them as Secret ostiara-system/ostiara-broker-tls.
set -euo pipefail

dir="${1:-bin/tls}"
mkdir -p "$dir"
umask 077

openssl req -x509 -newkey rsa:2048 -nodes -days 30 -subj "/CN=ostiara dev CA" \
  -keyout "$dir/ca.key" -out "$dir/ca.crt" 2>/dev/null

cat > "$dir/san.ext" <<EXT
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = DNS:localhost, IP:127.0.0.1, DNS:ostiara-broker, DNS:ostiara-broker.ostiara-system, DNS:ostiara-broker.ostiara-system.svc, DNS:ostiara-broker.ostiara-system.svc.cluster.local
EXT

openssl req -new -newkey rsa:2048 -nodes -subj "/CN=ostiara-broker" \
  -keyout "$dir/tls.key" -out "$dir/tls.csr" 2>/dev/null
openssl x509 -req -in "$dir/tls.csr" -CA "$dir/ca.crt" -CAkey "$dir/ca.key" -CAcreateserial \
  -days 30 -extfile "$dir/san.ext" -out "$dir/tls.crt" 2>/dev/null
rm -f "$dir/tls.csr" "$dir/san.ext" "$dir/ca.srl"

kubectl create namespace ostiara-system --dry-run=client -o yaml | kubectl apply -f - >/dev/null
kubectl -n ostiara-system create secret tls ostiara-broker-tls \
  --cert "$dir/tls.crt" --key "$dir/tls.key" --dry-run=client -o yaml | kubectl apply -f - >/dev/null

echo "Secret ostiara-system/ostiara-broker-tls updated. Point the CLI at the CA with:"
echo "  export OSTIARA_CA=$dir/ca.crt"
