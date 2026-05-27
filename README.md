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

## Cómo el agente ejecuta comandos (modelo → contenedor Kali)

Punto clave de diseño: **el LLM no se conecta al contenedor.** El modelo solo
genera texto (`Thought:` + `Action:`); una capa Python determinista parsea esa
acción, opcionalmente la veta, y la ejecuta. El modelo nunca tiene acceso de red
ni al host — solo produce texto.

Flujo de una iteración del bucle ReAct:

1. **Inferencia.** El bucle pide la siguiente acción al LLM (Qwen3 servido por
   vLLM, endpoint OpenAI-compatible): cliente en
   `orquestador/utils/model_client.py:13` (`QWEN3_URL`) y `:60` (el `POST`),
   invocado desde `orquestador/tools/react_loop.py:264`
   (`await ask_whiterabbit_chat(...)`).
2. **Parseo.** Se extrae el comando del texto del modelo con una regex:
   `orquestador/tools/react_loop.py:24` (`RE_ACTION`) → `:270`
   (`_parsear_respuesta`).
3. **Revisión (opcional).** Un *Critic* adversarial puede **vetar** la acción
   antes de ejecutarla: `orquestador/tools/react_loop.py:284-309`.
4. **Ejecución en el contenedor Kali (`pentest-tools`).** Aquí el orquestador
   "se conecta" al contenedor, vía **`docker exec`** (no SSH, no socket del
   modelo): `orquestador/tools/react_loop.py:313`
   (`await ejecutar_comando(...)`) → `orquestador/tools/runner.py:47`
   (`ejecutar_comando`), con la llamada concreta en **`runner.py:68-69`**:
   `asyncio.create_subprocess_exec("docker", "exec", <container>, "sh", "-c", comando)`.
   El contenedor vivo se resuelve en `runner.py:23` (`_container_name`, vía
   `docker ps` por label de servicio Swarm).
5. **Observación.** La salida real (stdout/stderr/returncode) se formatea
   (`react_loop.py:314`, `_formatear_observation`) y vuelve al modelo como
   `Observation:` para la siguiente iteración (`:329`).

**Aislamiento del contenedor** (`orquestador/tools/runner.py:3-6`): es efímero
por engagement; el confinamiento descansa en (a) cgroups del contenedor,
(b) filtrado de egress con iptables según el scope autorizado
(`orquestador/tools/scope_guard.py`), y (c) destrucción/recreación del
contenedor al cerrar el engagement (`runner.py:94`, `reiniciar_container`).
