#!/bin/bash
# backup_vps.sh — Backup diario de la plataforma a /home/auditor/backups/.
#
# Estrategia: cada blob se genera en /tmp del host remoto, se cifra IN-STREAM
# con age en el remoto (la pubkey va con un -i en la línea), y se baja por scp.
# El blob nunca aparece en plano en disk del orchestrator.
#
# Topología post-migración 2026-05-13:
#   - VPS1 (consultor-backend): solo stack swarm (api/frontend/admin/traefik),
#     no contiene data persistente.
#   - VPS3 (consultor-data-v2): postgres consultor + minio + wazuh + zabbix.
#   - VPS4 (consultor-pay): BTCPay stack (bitcoind+nbxplorer+btcpayserver+pay-postgres).
#   - Orchestrator local: memory_postgres (pgvector con findings cifrados Fase A).
#
# Recovery: descargar el .age + descifrar con la privada offline:
#   age -d -i <privada> blob.dump.age > blob.dump
#
# Cron: timer systemd backup-vps.timer ejecuta esto diariamente.

set -uo pipefail

BACKUP_ROOT="/home/auditor/backups"
DAILY_DIR="$BACKUP_ROOT/daily"
WEEKLY_DIR="$BACKUP_ROOT/weekly"
LOG_FILE="$BACKUP_ROOT/backup.log"
RECIPIENTS_FILE="/home/auditor/.config/age/recipients.txt"
TODAY=$(date +%Y-%m-%d)
DOW=$(date +%u)   # 1=Mon ... 7=Sun
SNAP="$DAILY_DIR/$TODAY"
DAILY_KEEP=14
WEEKLY_KEEP=8
START_TS=$(date +%s)

if [ ! -s "$RECIPIENTS_FILE" ]; then
  echo "FATAL: no existe $RECIPIENTS_FILE con la pubkey age — abortando." >&2
  exit 1
fi
RECIPIENTS=$(grep -oE "age1[a-z0-9]+" "$RECIPIENTS_FILE" | head -1)
if [ -z "$RECIPIENTS" ]; then
  echo "FATAL: pubkey age vacía en $RECIPIENTS_FILE" >&2
  exit 1
fi

mkdir -p "$SNAP" "$WEEKLY_DIR"
chmod 700 "$BACKUP_ROOT" "$DAILY_DIR" "$WEEKLY_DIR" "$SNAP" 2>/dev/null

log()  { echo "[$(date '+%F %T')] $*" | tee -a "$LOG_FILE"; }
fail() { log "ERROR: $*"; }

# remote_dump_enc: ejecuta el dump en remoto y lo cifra in-stream con age
# antes de mandarlo por ssh. El plaintext nunca toca disk del orchestrator.
# Args: host_alias, remote_cmd, local_filename (sin .age), min_size_bytes
remote_dump_enc() {
  local host="$1" cmd="$2" local_name="$3" min_size="${4:-1000}"
  local out="$SNAP/${local_name}.age"

  # Ejecutamos: en el remoto, dump | age -r <pub> ; baja por stdout de ssh.
  # `age` necesita estar instalado en el remoto (apt install age).
  if ! ssh -o LogLevel=ERROR "$host" \
        "$cmd 2>/dev/null | age -r '$RECIPIENTS'" > "$out" 2>/dev/null; then
    fail "$local_name: ssh/dump/age falló"
    rm -f "$out"
    return 1
  fi

  local size
  size=$(stat -c%s "$out" 2>/dev/null || echo 0)
  if [ "$size" -lt "$min_size" ]; then
    fail "$local_name: ciphertext < $min_size bytes (real=$size)"
    rm -f "$out"
    return 1
  fi
  log "      OK $local_name.age ($(du -h "$out" | cut -f1))"
  return 0
}

# local_dump_enc: igual que remote_dump_enc pero el dump es local (orchestrator).
# Args: local_cmd, local_filename, min_size_bytes
local_dump_enc() {
  local cmd="$1" local_name="$2" min_size="${3:-1000}"
  local out="$SNAP/${local_name}.age"
  if ! bash -c "$cmd 2>/dev/null | age -r '$RECIPIENTS'" > "$out" 2>/dev/null; then
    fail "$local_name: dump local/age falló"
    rm -f "$out"
    return 1
  fi
  local size
  size=$(stat -c%s "$out" 2>/dev/null || echo 0)
  if [ "$size" -lt "$min_size" ]; then
    fail "$local_name: ciphertext < $min_size bytes (real=$size)"
    rm -f "$out"
    return 1
  fi
  log "      OK $local_name.age ($(du -h "$out" | cut -f1))"
  return 0
}

log "─── Backup $TODAY START (cifrado age → $RECIPIENTS) ───"

# ── 1. consultor_postgres (datos clientes) — VPS3 ─────────────────────────
log "[1/8] consultor_postgres dump (VPS3)…"
remote_dump_enc vps3 \
  'CID=$(sudo docker ps -qf name=consultor_data_postgres) && sudo docker exec "$CID" pg_dump -U api_user -d auditoria_db -F c' \
  consultor_postgres.dump 5000

# ── 2. orchestrator memory_postgres (findings vector store) — local ──────
log "[2/8] memory_postgres dump (orchestrator local)…"
local_dump_enc \
  'CID=$(docker ps -qf name=ai_memory_memory-postgres) && docker exec "$CID" pg_dump -U memory -d memory -F c' \
  memory_postgres.dump 5000

# ── 3. monitoring zabbix-db — VPS3 ────────────────────────────────────────
log "[3/8] zabbix-db dump (VPS3)…"
remote_dump_enc vps3 \
  'CID=$(sudo docker ps -qf name=monitoring_zabbix-db) && sudo docker exec "$CID" pg_dump -U zabbix -F c zabbix' \
  zabbix-db.dump 100000

# ── 4. wazuh_etc volume — VPS3 ────────────────────────────────────────────
log "[4/8] wazuh_etc volume (VPS3)…"
remote_dump_enc vps3 \
  'sudo docker run --rm -v monitoring_wazuh_etc:/d alpine tar czf - -C /d .' \
  wazuh_etc.tgz 50000

# ── 5. pay-postgres (BTCPay) — VPS4 ───────────────────────────────────────
log "[5/8] pay-postgres dump (VPS4)…"
remote_dump_enc vps4 \
  'CID=$(sudo docker ps -qf name=pay-pay-postgres-1) && sudo docker exec "$CID" pg_dumpall -U postgres' \
  pay_postgres.dumpall 1000

# ── 6. BTCPay state (keys + nbxplorer) — VPS4 ─────────────────────────────
# IMPORTANTE: incluye /var/lib/pay/btcpay/{Main,LocalStorage,key-*.xml} — el
# key XML es el master del store BTCPay. Sin estos files + el dump de
# pay-postgres NO se pueden recuperar los fondos aunque tengamos la blockchain.
log "[6/8] BTCPay state (VPS4)…"
remote_dump_enc vps4 \
  'sudo tar czf - -C /var/lib/pay btcpay nbxplorer 2>/dev/null' \
  btcpay_state.tgz 1000

# ── 7. MinIO audit-files volume — VPS3 ────────────────────────────────────
# Volume nombrado o bind-mount? Probamos primero por nombre de volume swarm.
log "[7/8] MinIO audit-files volume (VPS3)…"
MINIO_VOL_CMD='V=$(sudo docker volume ls -q | grep -E "consultor_data_minio|minio.*data" | head -1); [ -z "$V" ] && V=$(sudo docker inspect $(sudo docker ps -qf name=consultor_data_minio) --format "{{range .Mounts}}{{if eq .Destination \"/data\"}}{{.Source}}{{end}}{{end}}"); sudo tar czf - -C "$V" .'
remote_dump_enc vps3 "$MINIO_VOL_CMD" minio_audit-files.tgz 1000

# ── 8. Configs stack — VPS1 (+ pay-stack de VPS4 + monitoring de VPS3) ────
log "[8/8] configs (VPS1 stack + VPS4 pay + VPS3 monitoring)…"
remote_dump_enc vps1 \
  'tar czf - -C /home/auditor stack 2>/dev/null' \
  configs_vps1.tgz 1000
remote_dump_enc vps4 \
  'sudo tar czf - -C /opt/pay . 2>/dev/null' \
  configs_vps4_pay.tgz 1000
remote_dump_enc vps3 \
  'sudo tar czf - -C /srv/consultor . 2>/dev/null' \
  configs_vps3_srv.tgz 1000

# ── Promote weekly los domingos ──────────────────────────────────────────
if [ "$DOW" = "7" ]; then
  log "Promoviendo a weekly/ (domingo)…"
  cp -al "$SNAP" "$WEEKLY_DIR/$TODAY" 2>/dev/null \
    && log "      OK weekly/$TODAY" \
    || fail "promote weekly"
fi

# ── Cleanup retención ────────────────────────────────────────────────────
log "Cleanup retención (>${DAILY_KEEP}d daily, >${WEEKLY_KEEP}sem weekly)…"
find "$DAILY_DIR" -maxdepth 1 -mindepth 1 -type d -mtime +"$DAILY_KEEP" -exec rm -rf {} \; 2>/dev/null
find "$WEEKLY_DIR" -maxdepth 1 -mindepth 1 -type d -mtime +$((WEEKLY_KEEP * 7)) -exec rm -rf {} \; 2>/dev/null

ELAPSED=$(( $(date +%s) - START_TS ))
TOTAL=$(du -sh "$SNAP" 2>/dev/null | cut -f1)
log "─── Backup $TODAY END (${ELAPSED}s, total $TOTAL) ───"
echo
