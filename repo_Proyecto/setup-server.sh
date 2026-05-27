#!/bin/bash
# setup-server.sh — Prepara el servidor 10.20.30.40 desde cero.
# Ejecutar como root o con sudo en el servidor nuevo.
# Uso:  curl -sSL <url> | bash
#       o bien: scp setup-server.sh user@10.20.30.40: && ssh user@10.20.30.40 bash setup-server.sh
set -e

SERVER_IP="10.20.30.40"
RUNNER_USER="github-runner"
GITHUB_REPO="example-org/Proyecto"   # <── tu repo

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()    { echo -e "${GREEN}[INFO]${NC}  $*"; }
warning() { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error()   { echo -e "${RED}[ERR]${NC}   $*"; exit 1; }

# ── 0. Comprobaciones previas ─────────────────────────────────────────────────
[[ "$EUID" -ne 0 ]] && error "Ejecuta como root: sudo bash setup-server.sh"
info "Servidor: $SERVER_IP | RAM: $(free -h | awk '/Mem/{print $2}') | CPUs: $(nproc)"

# ── 1. Paquetes base ──────────────────────────────────────────────────────────
info "Actualizando paquetes..."
apt-get update -qq
apt-get install -y -qq \
    ca-certificates curl gnupg lsb-release \
    git jq unzip ufw

# ── 2. Docker Engine ──────────────────────────────────────────────────────────
if command -v docker &>/dev/null; then
    info "Docker ya instalado: $(docker --version)"
else
    info "Instalando Docker..."
    install -m 0755 -d /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
        | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
    chmod a+r /etc/apt/keyrings/docker.gpg
    echo \
        "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
        https://download.docker.com/linux/ubuntu \
        $(lsb_release -cs) stable" \
        > /etc/apt/sources.list.d/docker.list
    apt-get update -qq
    apt-get install -y -qq docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
    systemctl enable --now docker
    info "Docker instalado: $(docker --version)"
fi

# ── 3. Docker Swarm ───────────────────────────────────────────────────────────
if docker info --format '{{.Swarm.LocalNodeState}}' 2>/dev/null | grep -q "active"; then
    info "Swarm ya activo."
else
    info "Inicializando Docker Swarm..."
    docker swarm init --advertise-addr "$SERVER_IP"
    info "Swarm iniciado. Token de worker guardado en /root/swarm-worker-token.txt"
    docker swarm join-token worker -q > /root/swarm-worker-token.txt
fi

# ── 4. Firewall UFW ───────────────────────────────────────────────────────────
info "Configurando firewall..."
ufw --force reset >/dev/null
ufw default deny incoming >/dev/null
ufw default allow outgoing >/dev/null
ufw allow ssh           # 22  — acceso SSH
ufw allow 80/tcp        # HTTP (Traefik)
ufw allow 2376/tcp      # Docker daemon remoto (opcional, solo si usas contexto remoto)
ufw allow 2377/tcp      # Swarm cluster management
ufw allow 7946/tcp      # Swarm node communication
ufw allow 7946/udp
ufw allow 4789/udp      # Overlay network traffic
ufw --force enable >/dev/null
info "Firewall activo. Reglas:"
ufw status numbered

# ── 5. Usuario para el GitHub Actions runner ──────────────────────────────────
if id "$RUNNER_USER" &>/dev/null; then
    info "Usuario '$RUNNER_USER' ya existe."
else
    info "Creando usuario '$RUNNER_USER'..."
    useradd -m -s /bin/bash "$RUNNER_USER"
fi
# Añadir al grupo docker para que pueda usar docker sin sudo
usermod -aG docker "$RUNNER_USER"

# ── 6. GitHub Actions Runner ──────────────────────────────────────────────────
RUNNER_DIR="/home/$RUNNER_USER/actions-runner"

if [ -f "$RUNNER_DIR/run.sh" ]; then
    warning "Runner ya instalado en $RUNNER_DIR. Saltando."
else
    info "Descargando GitHub Actions runner..."
    mkdir -p "$RUNNER_DIR"
    cd "$RUNNER_DIR"

    # Obtener la última versión del runner
    RUNNER_VERSION=$(curl -s https://api.github.com/repos/actions/runner/releases/latest \
        | jq -r '.tag_name' | sed 's/v//')
    RUNNER_ARCH="linux-x64"

    curl -fsSL \
        "https://github.com/actions/runner/releases/download/v${RUNNER_VERSION}/actions-runner-${RUNNER_ARCH}-${RUNNER_VERSION}.tar.gz" \
        -o runner.tar.gz
    tar xzf runner.tar.gz
    rm runner.tar.gz

    chown -R "$RUNNER_USER:$RUNNER_USER" "$RUNNER_DIR"

    echo ""
    echo "═══════════════════════════════════════════════════════════════════"
    warning "PASO MANUAL REQUERIDO — Configurar el runner:"
    echo ""
    echo "  1. Ve a GitHub → https://github.com/$GITHUB_REPO/settings/actions/runners/new"
    echo "  2. Copia el token de registro que aparece ahí"
    echo "  3. Ejecuta como usuario '$RUNNER_USER':"
    echo ""
    echo "     sudo -u $RUNNER_USER bash -c 'cd $RUNNER_DIR && ./config.sh \\"
    echo "       --url https://github.com/$GITHUB_REPO \\"
    echo "       --token TU_TOKEN_AQUI \\"
    echo "       --name servidor-nuevo \\"
    echo "       --labels self-hosted,linux,x64 \\"
    echo "       --unattended'"
    echo ""
    echo "  4. Instalar y arrancar el servicio systemd:"
    echo ""
    echo "     cd $RUNNER_DIR && sudo ./svc.sh install $RUNNER_USER"
    echo "     sudo ./svc.sh start"
    echo "═══════════════════════════════════════════════════════════════════"
fi

# ── 7. Resumen final ──────────────────────────────────────────────────────────
echo ""
info "Setup completado. Resumen:"
echo "  Docker:    $(docker --version)"
echo "  Swarm:     $(docker info --format '{{.Swarm.LocalNodeState}}')"
echo "  Firewall:  activo"
echo "  Runner dir: $RUNNER_DIR"
echo ""
info "Siguiente paso: configura el runner de GitHub Actions (ver instrucciones arriba)."
info "Luego haz un push a main y el CI/CD desplegará automáticamente."
