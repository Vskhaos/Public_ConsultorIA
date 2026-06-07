#!/bin/bash
# setup-monitoring.sh — Despliega el stack de monitorización en el servidor
# Ejecutar desde la máquina local con VPN activa.
set -e

SERVER="isard@10.20.30.40"
REMOTE_DIR="/opt/monitoring"

echo "==> [1/6] Copiando archivos al servidor..."
ssh "$SERVER" "sudo mkdir -p $REMOTE_DIR && sudo chown isard:isard $REMOTE_DIR"
scp monitoring/certs.yml "$SERVER:$REMOTE_DIR/certs.yml"
scp monitoring/ossec.conf "$SERVER:$REMOTE_DIR/ossec.conf"
scp monitoring-stack.yml "$SERVER:~/monitoring-stack.yml"

echo "==> [2/6] Configurando parámetros del kernel (Wazuh Indexer necesita vm.max_map_count)..."
ssh "$SERVER" "
  sudo sysctl -w vm.max_map_count=262144
  grep -q 'vm.max_map_count' /etc/sysctl.conf || echo 'vm.max_map_count=262144' | sudo tee -a /etc/sysctl.conf
"

echo "==> [3/6] Generando certificados SSL para Wazuh..."
ssh "$SERVER" "
  mkdir -p $REMOTE_DIR/certs
  docker run --rm \
    -v $REMOTE_DIR/certs.yml:/config/certs.yml \
    -v $REMOTE_DIR/certs:/certificates \
    wazuh/wazuh-certs-generator:0.0.2 -g -v
  # Renombrar certs al formato esperado por el stack
  cp $REMOTE_DIR/certs/wazuh-indexer/wazuh-indexer.pem  $REMOTE_DIR/certs/wazuh-indexer.pem
  cp $REMOTE_DIR/certs/wazuh-indexer/wazuh-indexer.key  $REMOTE_DIR/certs/wazuh-indexer.key
  cp $REMOTE_DIR/certs/wazuh-manager/wazuh-manager.pem  $REMOTE_DIR/certs/wazuh-manager.pem
  cp $REMOTE_DIR/certs/wazuh-manager/wazuh-manager.key  $REMOTE_DIR/certs/wazuh-manager.key
  cp $REMOTE_DIR/certs/wazuh-dashboard/wazuh-dashboard.pem $REMOTE_DIR/certs/wazuh-dashboard.pem
  cp $REMOTE_DIR/certs/wazuh-dashboard/wazuh-dashboard.key $REMOTE_DIR/certs/wazuh-dashboard.key
  cp $REMOTE_DIR/certs/root-ca/root-ca.pem $REMOTE_DIR/certs/root-ca.pem
  cp $REMOTE_DIR/certs/admin/admin.pem     $REMOTE_DIR/certs/admin.pem
  cp $REMOTE_DIR/certs/admin/admin.key     $REMOTE_DIR/certs/admin.key
  chmod 400 $REMOTE_DIR/certs/*.key
  echo 'Certificados generados OK'
"

echo "==> [4/6] Creando red compartida entre stacks..."
ssh "$SERVER" "
  docker network inspect shared_monitoring >/dev/null 2>&1 || \
    docker network create --driver overlay --attachable shared_monitoring
  echo 'Red shared_monitoring lista'
"

echo "==> [5/6] Desplegando stack de monitorización..."
ssh "$SERVER" "docker stack deploy -c ~/monitoring-stack.yml monitoring --with-registry-auth"

echo "==> [6/6] Instalando agentes en el host..."
ssh "$SERVER" "
  # Wazuh Agent
  wget -qO - https://packages.wazuh.com/key/GPG-KEY-WAZUH | sudo gpg --dearmor -o /usr/share/keyrings/wazuh.gpg
  echo 'deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main' | sudo tee /etc/apt/sources.list.d/wazuh.list
  sudo apt-get update -qq
  WAZUH_MANAGER='127.0.0.1' WAZUH_AGENT_NAME='servidor-host' sudo apt-get install -y wazuh-agent
  sudo systemctl enable wazuh-agent
  sudo systemctl start wazuh-agent
  echo 'Wazuh Agent instalado'

  # Zabbix Agent 2
  wget -qO /tmp/zabbix-release.deb https://repo.zabbix.com/zabbix/7.0/ubuntu/pool/main/z/zabbix-release/zabbix-release_7.0-2+ubuntu24.04_all.deb
  sudo dpkg -i /tmp/zabbix-release.deb
  sudo apt-get update -qq
  sudo apt-get install -y zabbix-agent2 zabbix-agent2-plugin-*
  sudo sed -i 's/^Server=127.0.0.1/Server=127.0.0.1/' /etc/zabbix/zabbix_agent2.conf
  sudo sed -i 's/^ServerActive=127.0.0.1/ServerActive=127.0.0.1/' /etc/zabbix/zabbix_agent2.conf
  sudo sed -i 's/^Hostname=Zabbix server/Hostname=servidor-host/' /etc/zabbix/zabbix_agent2.conf
  sudo systemctl enable zabbix-agent2
  sudo systemctl start zabbix-agent2
  echo 'Zabbix Agent 2 instalado'
"

echo ""
echo "======================================================"
echo "  Setup completado. Servicios disponibles (via VPN):"
echo "  Wazuh Dashboard : https://10.20.30.40:5601"
echo "  Zabbix Web      : http://10.20.30.40:8082"
echo "  Wazuh API       : https://10.20.30.40:55000"
echo ""
echo "  Credenciales Wazuh Dashboard:"
echo "    Usuario: admin"
echo "    Password: <REDACTED>"
echo ""
echo "  Credenciales Zabbix (primer login):"
echo "    Usuario: Admin"
echo "    Password: zabbix  (cámbiala al entrar)"
echo "======================================================"
