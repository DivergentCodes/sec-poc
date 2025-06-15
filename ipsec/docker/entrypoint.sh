#!/bin/bash
set -e

# Configure SNAT for the VPN traffic
#iptables -t nat -A POSTROUTING -s $LOCAL_PRIVATE_CIDR -d $REMOTE_PRIVATE_CIDR -j MASQUERADE
iptables -t nat -A POSTROUTING -s $LOCAL_PRIVATE_CIDR -o eth1 -j MASQUERADE

# Start charon-systemd (correct binary on Ubuntu)
echo "[*] Starting charon-systemd..."
/usr/sbin/charon-systemd --debug &

# Wait for the VICI socket to appear
for i in {1..360}; do
  if [[ -S /var/run/charon.vici ]]; then
    break
  fi
  echo "[*] Waiting for VICI socket... $i"
  sleep 1
done

# Load the swanctl config
echo "[*] Loading swanctl configuration..."
swanctl --load-all

sleep 3

# List the security associations
swanctl --list-sas

# Keep container alive
tail -f /dev/null