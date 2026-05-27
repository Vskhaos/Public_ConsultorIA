#!/bin/bash
# deploy.sh — Construye las imágenes y despliega el stack en Docker Swarm.
set -e

STACK_NAME="consultor"
SERVER_IP="10.20.30.40"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "── Comprobando Docker Swarm ──────────────────────────────────────────"
if ! docker info --format '{{.Swarm.LocalNodeState}}' 2>/dev/null | grep -q "active"; then
  echo "Swarm no activo. Inicializando con advertise-addr $SERVER_IP..."
  docker swarm init --advertise-addr "$SERVER_IP"
fi
echo "OK — nodo: $(docker info --format '{{.Swarm.NodeID}}')"

echo ""
echo "── Construyendo imágenes ─────────────────────────────────────────────"
docker build --pull -t audit-api:latest      "$SCRIPT_DIR/API"
echo "  OK audit-api:latest"

docker build --pull -t audit-frontend:latest "$SCRIPT_DIR/Frontend"
echo "  OK audit-frontend:latest"

docker build --pull -t audit-admin:latest    "$SCRIPT_DIR/Admin"
echo "  OK audit-admin:latest"

echo ""
echo "── Desplegando stack '$STACK_NAME' ───────────────────────────────────"
docker stack deploy --prune -c "$SCRIPT_DIR/docker-stack.yml" "$STACK_NAME"

echo "── Forzando actualización de imágenes ───────────────────────────────"
docker service update --force --image audit-api:latest      --detach=false "${STACK_NAME}_api"      2>/dev/null || true
docker service update --force --image audit-frontend:latest --detach=false "${STACK_NAME}_frontend" 2>/dev/null || true
docker service update --force --image audit-admin:latest    --detach=false "${STACK_NAME}_admin"    2>/dev/null || true

echo ""
echo "── Estado de los servicios ───────────────────────────────────────────"
sleep 3
docker stack services "$STACK_NAME"

echo ""
echo "Listo. Accede en:"
echo "  Formulario:  http://$SERVER_IP"
echo "  API docs:    http://$SERVER_IP/api/docs"
echo "  Admin:       http://$SERVER_IP/admin"
echo "  Traefik UI:  http://$SERVER_IP:8080  (solo desde localhost del servidor)"
echo "  MinIO UI:    http://$SERVER_IP:9001  (expón el puerto si es necesario)"
