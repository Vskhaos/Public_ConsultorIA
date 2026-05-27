#!/bin/bash
# daily_local_attack_report.sh
# Genera informe con apartados 1..7 según especificación del usuario.
# Requiere: bash, awk, grep, sed, sort, uniq, python3. whois recomendado.

LOG_SSH="/var/log/ssh.log"
LOG_FTP="/var/log/vsftpd.log"
DATE=$(date '+%Y-%m-%d')
REPORT_DIR="/var/reports"
REPORT="$REPORT_DIR/daily_attack_report_${DATE}.txt"
WHOIS_CACHE="/tmp/whois_cache.txt"

# Asegurar directorio
mkdir -p "$REPORT_DIR"
: > "$REPORT"
: > "$WHOIS_CACHE"

# Verificar que haya logs (al menos uno)
if [[ ! -f "$LOG_SSH" && ! -f "$LOG_FTP" ]]; then
    echo "ERROR: No se encontraron archivos de log ($LOG_SSH, $LOG_FTP)." >&2
    exit 1
fi

echo "Informe de Ataques - $DATE" >> "$REPORT"
echo "========================================" >> "$REPORT"
echo "" >> "$REPORT"

# Extraer IPs con etiqueta SERVICIO:IP
SSH_ATTACKS=""
FTP_ATTACKS=""

if [[ -f "$LOG_SSH" ]]; then
    # Ajusta los patrones si tu sshd usa otros mensajes de fallo
    SSH_ATTACKS=$(grep -E "(Failed password|Invalid user|authentication failure)" "$LOG_SSH" 2>/dev/null | \
        grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | sed 's/^/SSH:/')
fi

if [[ -f "$LOG_FTP" ]]; then
    FTP_ATTACKS=$(grep -E "FAIL LOGIN|FAIL" "$LOG_FTP" 2>/dev/null | \
        grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | sed 's/^/FTP:/')
fi

ALL_ATTACKS=$(printf "%s\n%s\n" "$SSH_ATTACKS" "$FTP_ATTACKS" | grep -v '^$')
if [[ -z "$ALL_ATTACKS" ]]; then
    echo "No se detectaron ataques hoy." >> "$REPORT"
    echo "Informe guardado en: $REPORT"
    exit 0
fi

# Guardar raw para procesar
echo "$ALL_ATTACKS" > /tmp/attacks_raw.txt
# -----------------------------------------
# Apartado 1: IPs que te han atacado y servicio
# -----------------------------------------
echo "1 Apartado (IPs que te han atacado y el servicio afectado)" >> "$REPORT"
echo "=============================" >> "$REPORT"
# Generar lista "IP SERVICIO" por línea, ordenar por IP y servicio, luego agrupar servicios únicos por IP
awk -F: '{ print $2 " " $1 }' /tmp/attacks_raw.txt | \
  sort -k1,1 -k2,2 | \
  awk '
  {
    ip=$1; svc=$2;
    if (ip != prev_ip) {
      if (prev_ip != "") {
        # imprimir la línea anterior
        printf("IP: %s -> %s\n", prev_ip, services) >> "'"$REPORT"'"
      }
      prev_ip = ip;
      services = svc;
    } else {
      # comprobar si svc ya está en services (lista separada por comas)
      found = 0;
      n = split(services, a, ",");
      for (i=1; i<=n; i++) if (a[i] == svc) found = 1;
      if (!found) services = services "," svc;
    }
  }
  END {
    if (prev_ip != "") {
      printf("IP: %s -> %s\n", prev_ip, services) >> "'"$REPORT"'"
    }
  }'
echo "" >> "$REPORT"
# -----------------------------------------
# Apartado 2: agrupar ataques de un mismo origen a un mismo servicio (resumen por servicio)
# -----------------------------------------
echo "2 Apartado (agrupar ataques por servicio)" >> "$REPORT"
echo "=============================" >> "$REPORT"
# Count per service (total ataques al servicio)
awk -F: '{count[$1]++} END {for (s in count) print "Servidor "s ": " count[s] " ataques"}' /tmp/attacks_raw.txt | sort >> "$REPORT"
echo "" >> "$REPORT"

# -----------------------------------------
# Apartado 3: agrupar ataques de un mismo origen a un mismo servicio (IP por servicio con cuenta)
# -----------------------------------------
echo "3 Apartado (agrupados: IP -> servicio [N ataques])" >> "$REPORT"
echo "=============================" >> "$REPORT"
# For each service: list IPs and counts
awk -F: '{k=$1":"$2; count[k]++} END {for (k in count) print k " " count[k]}' /tmp/attacks_raw.txt | \
    awk -F' ' '{ split($1,a,":"); print a[1]": "a[2]" ["$2"]"}' | sort >> "$REPORT"
echo "" >> "$REPORT"

# -----------------------------------------
# Prepara datos para apartados 4,5,6: totales por IP y whois (cache)
# -----------------------------------------
# totals per IP
cut -d: -f2 /tmp/attacks_raw.txt | sort | uniq -c | awk '{print $2" "$1}' > /tmp/totals_by_ip.txt
# file format: "IP count"

# función whois-cache: devuelve "COUNTRY|ISP"
whois_lookup() {
    ip="$1"
    # comprobar cache
    if grep -q "^$ip|" "$WHOIS_CACHE" 2>/dev/null; then
        grep "^$ip|" "$WHOIS_CACHE" | head -1 | cut -d'|' -f2-
        return
    fi
    # si whois no existe, regresar placeholders
    if ! command -v whois &>/dev/null; then
        echo "Desconocido|whois_no_disponible"
        echo "$ip|Desconocido|whois_no_disponible" >> "$WHOIS_CACHE"
        return
    fi
    out=$(whois "$ip" 2>/dev/null)
    # intentar extraer country (varias claves posibles)
    # CORRECCIÓN: separar las opciones -m 1 -E correctamente
    country=$(echo "$out" | grep -i -m 1 -E 'country|Country' | awk -F': ' '{print $2}' | tr -d '\r' | xargs 2>/dev/null)
    # intento ISP/org
    isp=$(echo "$out" | grep -i -m 1 -E 'org-name|OrgName|org|descr|owner|netname' | awk -F': ' '{ $1=""; print substr($0,2) }' | tr -d '\r' | xargs 2>/dev/null)
    # normalizar
    [[ -z "$country" ]] && country="Desconocido"
    [[ -z "$isp" ]] && isp="ISP_desconocido"
    # almacenar cache en formato IP|COUNTRY|ISP
    echo "$ip|$country|$isp" >> "$WHOIS_CACHE"
    echo "$country|$isp"
}

# Build enriched totals file with country and isp and services attacked
> /tmp/enriched_totals.txt
while read -r ip cnt; do
    whois_info=$(whois_lookup "$ip")
    country=$(echo "$whois_info" | cut -d'|' -f1)
    isp=$(echo "$whois_info" | cut -d'|' -f2)
    # services attacked by this IP (list)
    services=$(grep ":$ip$" /tmp/attacks_raw.txt | awk -F: '{print $1}' | sort -u | tr '\n' ',' | sed 's/,$//')
    echo "$ip|$cnt|$country|$isp|$services" >> /tmp/enriched_totals.txt
done < /tmp/totals_by_ip.txt

# -----------------------------------------
# Apartado 4,5,6: totales por IP, añadir país e ISP, ordenados desc
# -----------------------------------------
echo "4/5/6 Apartado (Ataques totales por IP con país y proveedor) — ordenado" >> "$REPORT"
echo "=============================" >> "$REPORT"
# Format: IP: [count] [Country-Region-City if available] [ISP] -> servicios
sort -t'|' -k2 -nr /tmp/enriched_totals.txt | while IFS='|' read -r ip cnt country isp services; do
    # country may be like 'US' or 'United States' depending whois; keep as-is
    echo "IP: $ip [$cnt] [$country] [$isp] -> $services" >> "$REPORT"
done
echo "" >> "$REPORT"

# -----------------------------------------
# Apartado 7: agrupar ataques por red de origen (identificar redes con >=2 IPs)
# -----------------------------------------
echo "7 Apartado (agrupar ataques por red de origen)" >> "$REPORT"
echo "=============================" >> "$REPORT"

# Pasamos la lista de IPs al python para agrupar en CIDRs donde haya >=2 IPs
cut -d'|' -f1 /tmp/enriched_totals.txt > /tmp/ips_for_group.txt

python3 - "$REPORT" /tmp/ips_for_group.txt <<'PY'
import sys, ipaddress, collections
report=sys.argv[1]
ipsfile=sys.argv[2]
ips=[]
with open(ipsfile) as f:
    for l in f:
        l=l.strip()
        if not l: continue
        try:
            ips.append(ipaddress.IPv4Address(l))
        except:
            pass
if not ips:
    with open(report,'a') as fo:
        fo.write("No hay IPs para agrupar por red.\n\n")
    sys.exit(0)

remaining=set(ips)
assigned=[]
# probar prefijos desde /32 a /8
for p in range(32,7,-1):
    if not remaining: break
    nets=collections.defaultdict(list)
    for ip in list(remaining):
        # calcular network object: create network via ipaddress with strict=False
        net = ipaddress.ip_network(f"{ip}/{p}", strict=False)
        nets[net].append(ip)
    for net,members in list(nets.items()):
        if len(members) >= 2:
            assigned.append((net, members))
            for m in members:
                remaining.discard(m)
# escribir resultado
with open(report,'a') as fo:
    if assigned:
        for net, members in sorted(assigned, key=lambda x: (x[0].prefixlen, x[0])):
            fo.write(f"Net: {net}  -> {len(members)} IPs: {', '.join(str(x) for x in sorted(members))}\n")
    else:
        fo.write("No se encontraron redes con >=2 IPs.\n")
    if remaining:
        fo.write("\nIPs no agrupadas (únicas):\n")
        for ip in sorted(remaining):
            fo.write(f"- {ip}\n")
    fo.write("\n")
PY

echo "Fin del informe." >> "$REPORT"

# limpiar ficheros temporales (deja cache whois por si se quiere reutilizar)
rm -f /tmp/attacks_raw.txt /tmp/totals_by_ip.txt /tmp/enriched_totals.txt /tmp/ips_for_group.txt

echo "Informe guardado en: $REPORT"
exit 0
