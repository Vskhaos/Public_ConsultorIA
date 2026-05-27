#!/bin/sh
set -e
# Copia la key del secret a HOME con perms correctos (autossh la lee así).
cp /run/secrets/ssh_key /tmp/ssh_key
chmod 600 /tmp/ssh_key
exec /usr/bin/autossh -M 0 -N \
  -o ServerAliveInterval=10 \
  -o ServerAliveCountMax=3 \
  -o StrictHostKeyChecking=accept-new \
  -o UserKnownHostsFile=/tmp/known_hosts \
  -o ExitOnForwardFailure=yes \
  -i /tmp/ssh_key \
  -L 0.0.0.0:5432:127.0.0.1:5432 \
  -L 0.0.0.0:9000:127.0.0.1:9000 \
  -L 0.0.0.0:5601:127.0.0.1:5601 \
  -L 0.0.0.0:8082:127.0.0.1:8082 \
  -p 50022 auditor@198.51.100.87
