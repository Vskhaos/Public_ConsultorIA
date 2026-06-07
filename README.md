# Public_ConsultorIA

Copia pública (saneada) del código y las configuraciones de una **plataforma de
auditoría de seguridad asistida por IA** — proyecto de TFM.

Un orquestador local dirige un agente ofensivo (bucle ReAct sobre un LLM
Qwen3-14B servido con vLLM) con un revisor adversarial (*Critic*) y un generador
de informes, sobre una infraestructura de 3 servidores (backend/web, datos+SIEM,
pagos) endurecida con CrowdSec (IPS), Wazuh (HIDS/SIEM) y Zabbix.

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
| `vps1/` | Servidor backend/web: stack Swarm, túnel, CrowdSec, runner CI, hardening OS. |
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

## Preguntas frecuentes

### ¿Qué es `ask_whiterabbit_chat`?

Es la variante **multi-turn** del cliente del LLM: en lugar de recibir
`prompt + system` y construir los `messages` por dentro (one-shot), acepta una
`list[messages]` ya armada con todo el historial y la delega en `_ask_qwen3`.
Es la única firma del cliente que soporta una conversación con historial
acumulado, por eso la usan los dos sitios que lo necesitan:

- **Bucle ReAct** (Thought/Action/Observation iterativo):
  `orquestador/tools/react_loop.py:264`
  (`await ask_whiterabbit_chat(messages, max_tokens=400)`).
- **Critic adversarial**: `orquestador/tools/critic.py:257`
  (`await ask_whiterabbit_chat(messages, max_tokens=200, temperature=0.1)`).

Definición: `orquestador/utils/model_client.py:78`. Para llamadas one-shot el
archivo expone otras dos firmas: `ask_whiterabbit(prompt, system=None)` en
`:69` (genérica) y `ask_deepseek(prompt, system=None)` en `:83` (alias legacy
que además fuerza `enable_thinking=True`, usado por el destilador OSINT en
`orquestador/utils/intel.py`). Todas terminan en el mismo `_ask_qwen3`
(`model_client.py:44`).

### ¿Cómo se mete el modelo en la imagen del contenedor?

**No se mete.** No construimos imagen propia: usamos la imagen oficial de
vLLM tal cual y vLLM descarga el modelo desde Hugging Face Hub en el primer
arranque, cacheándolo en un bind mount del host para que sobreviva a
redeploys. Todo en `orquestador_infra/qwen3/docker-compose.yml`:

- **Imagen base** (`:14`):
  `vllm/vllm-openai:latest@sha256:70a098…` — pública, sin modificar.
  Está pineada al SHA porque `:latest` cambia en Docker Hub y un
  `stack deploy` que resolviera un digest nuevo intentaba pull, fallaba por
  disco lleno y dejaba el servicio en 0/1 réplicas (comentario `:10-13`).
- **Quién descarga el modelo y con qué flags** (`command:`, líneas 25-34):
  - `--model Qwen/Qwen3-14B-AWQ` → repo HF; al no encontrarlo en disco,
    vLLM hace `snapshot_download` desde HF Hub.
  - `--quantization awq_marlin` → kernel AWQ Q4 (~9.3 GB en GPU).
  - `--max-model-len 16384` → contexto.
  - `--gpu-memory-utilization 0.92` → fracción de VRAM reservada.
  - `--enable-prefix-caching` → reuso de KV-cache entre prompts repetidos.
  - `--enable-auto-tool-choice` + `--tool-call-parser hermes` → tool-calling
    estilo OpenAI.
  - `--reasoning-parser qwen3` → parsea el `<think>` del thinking-mode.
  - `--served-model-name qwen3` → alias que usan los clientes
    (`model="qwen3"` en `model_client.py:44-65`).
- **Dónde aterriza el modelo** (`volumes:`, `:24`):
  bind mount `…/qwen3/hf_cache:/root/.cache/huggingface` (eligimos `/home`
  por espacio libre). Solo se descarga la primera vez.
- **Autenticación HF**: token montado como swarm secret externo
  `model_hub_token` en `/root/.cache/huggingface/token`, modo `0400`
  (`:40-43` + declaración `:60-62`). Descarga acelerada con
  `HF_HUB_ENABLE_HF_TRANSFER=1` (`:39`).
- **GPU**: `NVIDIA_VISIBLE_DEVICES=0` (`:37`). La variante 30B-A3B-Thinking
  pesaba 15.7 GB y daba OOM en GPU de 16 GB; por eso la 14B-AWQ
  (comentario `:4-6`).
- **Puerto**: `mode: host` mapea el `8000` del container directo al `:8003`
  del host, bypaseando el ingress de swarm (`:16-22`).

Resumen: **un único `docker stack deploy` con este compose** y vLLM se
encarga del resto (pull de imagen, pull del modelo, carga en GPU, API
OpenAI-compatible en `:8003`).

### ¿La inferencia sale fuera del contenedor (API remota tipo OpenAI/Anthropic)?

**No.** La inferencia es **100% local en el contenedor**, sobre la GPU del
host. Lo único que sale a internet es la descarga inicial del modelo desde
HF Hub (one-shot, primer arranque). En operación normal no hay tráfico
saliente para inferir.

Evidencias en `orquestador_infra/qwen3/docker-compose.yml`:

- vLLM corre dentro del container y consume GPU local:
  `NVIDIA_VISIBLE_DEVICES=0` (`:37`), `--gpu-memory-utilization 0.92`
  (`:29`), `--quantization awq_marlin` (`:27`) ejecuta kernels CUDA *ahí*.
- No hay ningún env tipo `OPENAI_API_BASE`, `OPENAI_API_KEY`, `*_ENDPOINT`
  apuntando fuera (revisado el yml completo).
- El cliente HTTP del orquestador apunta al propio servicio, no a un SaaS:
  `orquestador/utils/model_client.py:13` →
  `QWEN3_URL = "http://0.0.0.0:8003/v1/chat/completions"` (desde el host;
  desde la red overlay del swarm es `qwen3:8000`). Ese es **el único
  endpoint** al que llama `_ask_qwen3` (`:44-65`, ver el `POST` en `:60`).

Encaja con el principio de diseño del proyecto: el agente IA NO depende de
APIs de terceros y la inferencia es soberana (cero telemetría a la nube).
