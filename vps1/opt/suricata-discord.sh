#!/bin/bash

# === CONFIGURACIÓN ===
WEBHOOK_URL="<REDACTED>"
LOG_FILE="/var/log/suricata/eve.json"

if [ ! -f "$LOG_FILE" ]; then
  echo "[ERROR] El archivo $LOG_FILE no existe."
  exit 1
fi

send_alert() {
  local json_line="$1"

  signature=$(echo "$json_line" | jq -r '.alert.signature // "Unknown"')
  category=$(echo "$json_line" | jq -r '.alert.category // "N/A"')
  severity=$(echo "$json_line" | jq -r '.alert.severity // "N/A"')
  src_ip=$(echo "$json_line" | jq -r '.src_ip // "N/A"')
  src_port=$(echo "$json_line" | jq -r '.src_port // "N/A"')
  dest_ip=$(echo "$json_line" | jq -r '.dest_ip // "N/A"')
  dest_port=$(echo "$json_line" | jq -r '.dest_port // "N/A"')
  timestamp=$(echo "$json_line" | jq -r '.timestamp // "N/A"')

  # ✅ Solo alertas si el destino es puerto 21 (FTP) o 22 (SSH)
  if [[ "$dest_port" != "21" && "$dest_port" != "22" ]]; then
    return 0  # Ignorar
  fi

  # ✅ Opcional: también incluir si la regla menciona SSH/FTP (por si hay tráfico desde tu host)
  # if ! echo "$signature" | grep -qiE "ssh|ftp|scan|brute|login"; then
  #   return 0
  # fi

  # Formato limpio con embeds de Discord
  msg=$(
    jq -n \
      --arg sig "$signature" \
      --arg cat "$category" \
      --arg sev "$severity" \
      --arg src "$src_ip:$src_port" \
      --arg dst "$dest_ip:$dest_port" \
      --arg ts "$timestamp" \
      '{
        embeds: [{
          title: "🚨 Ataque detectado en servicio crítico",
          color: 15548997,
          fields: [
            { name: "Servicio", value: ($dst | split(":")[-1] | if . == "22" then "SSH" elif . == "21" then "FTP" else "Otro" end), inline: true },
            { name: "Regla", value: $sig, inline: false },
            { name: "Origen", value: "`\($src)`", inline: true },
            { name: "Destino", value: "`\($dst)`", inline: true },
            { name: "Categoría", value: "\($cat) (Severidad \($sev))", inline: false },
            { name: "Hora", value: $ts, inline: false }
          ],
          footer: { text: "Suricata • Alerta de seguridad" }
        }]
      }'
  )

  curl -s -o /dev/null -X POST \
    -H "Content-Type: application/json" \
    -d "$msg" \
    "$WEBHOOK_URL"
}

echo "[INFO] Esperando alertas SSH/FTP en $LOG_FILE..."
tail -n0 -F "$LOG_FILE" | while IFS= read -r line; do
  if echo "$line" | jq -e '.event_type == "alert"' >/dev/null 2>&1; then
    send_alert "$line"
  fi
done
