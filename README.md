# Public_ConsultorIA

Copia pública (saneada) del código y las configuraciones de una **plataforma de
auditoría de seguridad asistida por IA** — proyecto de TFM.

Un orquestador local dirige un agente ofensivo (bucle ReAct sobre un LLM
Qwen3-14B servido con vLLM) con un revisor adversarial (*Critic*) y un generador
de informes, sobre una infraestructura de 3 servidores (backend/web, datos+SIEM,
pagos) endurecida con CrowdSec (IPS), Wazuh (HIDS/SIEM), Suricata (IDS) y Zabbix.

> ⚠️ **Repositorio saneado.** Todas las IPs, puertos sensibles, claves,
> contraseñas y tokens se han redactado o sustituido por valores ficticios. No
> contiene credenciales reales ni datos de clientes.

## Estructura

| Carpeta | Contenido |
|---|---|
| `orquestador/` | Código del orquestador IA: bucle ReAct, Critic, Reporter, OSINT/Intel, scheduler, memoria, cliente del LLM. |
| `orquestador_infra/` | Definiciones de la infra del orquestador (vLLM, contenedor Kali del agente, Redis, MinIO, memoria pgvector). |
| `orquestador_sistema/` | Capa de sistema del orquestador (units, agentes CrowdSec/Wazuh, hardening SSH/UFW). |
| `repo_Proyecto/` | Aplicación: API (FastAPI), Admin, Frontend, migraciones SQL, stacks Docker, configs de monitorización. |
| `vps1/` | Servidor backend/web: stack Swarm, túnel, CrowdSec, **Suricata (IDS)**, runner CI, hardening OS. |
| `vps3/` | Servidor de datos + **SIEM/IDS/IPS**: Wazuh (manager + reglas), CrowdSec (LAPI), Zabbix. |
| `vps4/` | Servidor de pagos: stack BTCPay, monitorización, CrowdSec/Wazuh. |

## Dónde mirar

- **Prompts de la IA:**
  - Agente Red (ReAct): `orquestador/tools/react_loop.py:26` (`SYSTEM_REACT`),
    `:111` (`_build_osint_toolbox`, comandos OSINT), `:130`
    (`_construir_prompt_inicial`, prompt por fase).
  - Critic: `orquestador/tools/critic.py:67` (`SYSTEM_CRITIC`).
  - Informes: `orquestador/utils/reporting.py:24` (`SYSTEM_TECNICO`) y `:51`
    (`SYSTEM_EJECUTIVO`).
  - Dossier OSINT: `orquestador/utils/intel.py:46` (`SYSTEM_DESTILADOR`).
  - Fases por tipo de auditoría: `orquestador/phases/plantillas.py:1`
    (`FASES_POR_TIPO`).
- **Flujo agente ↔ API del LLM:**
  - Cliente HTTP a vLLM: `orquestador/utils/model_client.py:44` (`_ask_qwen3`,
    el `POST`) y `:13` (`QWEN3_URL`, endpoint).
  - Bucle ReAct (Thought/Action/Observation): `orquestador/tools/react_loop.py`.
  - Ejecución con guard de scope (iptables OUTPUT en el contenedor Kali):
    `orquestador/tools/runner.py` y `orquestador/tools/scope_guard.py:1`.
- **Configuración IDS/IPS/SIEM:**
  - **SIEM/HIDS (Wazuh):** `vps3/srv/monitoring/ossec.conf` (manager; integraciones
    de notificación en `:141` Discord y `:149` Telegram),
    `vps3/var/lib/docker/volumes/monitoring_wazuh_etc/_data/` (rules/, decoders/),
    reglas propias en `orquestador/wazuh_rules/local_rules_critic.xml`.
  - **IDS (Suricata):** `vps1/etc/suricata/suricata.yaml` (config),
    `vps1/etc/suricata/rules/` (rulesets), `vps1/etc/suricata/threshold.config`,
    y el notifier de alertas a Discord `vps1/opt/suricata-discord.sh`.
  - **IPS (CrowdSec):** `vps{1,3,4}/etc/crowdsec/` — LAPI central en VPS3,
    agents+bouncers en los demás (`config.yaml.local`, `profiles.yaml`,
    `scenarios/`, `acquis.d/`).
  - **Monitorización (Zabbix):** `vps*/etc/zabbix/zabbix_agent2.conf`.
