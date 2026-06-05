# Orquestador — flujo cronológico

Esta carpeta contiene el código del **orquestador IA**: el proceso Python que
recibe peticiones de auditoría, las programa, lanza el agente ofensivo (bucle
ReAct sobre Qwen3-14B-AWQ), captura la evidencia y entrega el informe.

Es una aplicación **FastAPI** servida por uvicorn (`server.py:1`), corriendo como
unidad systemd en el host del orquestador. No tiene autenticación: solo escucha
en `127.0.0.1:8000`; nadie de fuera puede tocarlo (lo invoca su propio
`auto_poller` o pruebas locales).

> Si solo quieres un mapa visual del flujo, mira primero el README de raíz del
> repo (sección "Cómo el agente ejecuta comandos") y el FAQ del LLM. Este
> documento entra al detalle de cada función que se ejecuta cuando llega un
> engagement.

---

## Mapa rápido de la carpeta

| Archivo | Rol |
|---|---|
| `server.py` | Entrada FastAPI. Endpoints `/schedule`, `/preload`, `/engagement`, `/dossier`, `/jobs`, `/health`. Sube informes a MinIO y notifica al backend cuando terminan. |
| `models/engagement.py` | Pydantic + dataclasses (`Hallazgo`, `Tarea`, `Engagement`). Tipos de request. |
| `phases/plantillas.py` | `FASES_POR_TIPO`: pesos, `min_iter`/`max_iter` y extras de prompt por cada tipo de auditoría (`pentesting_externo`, `pentesting_interno`, `auditoria_web`, …). |
| `tools/react_loop.py` | El **bucle ReAct** (Thought / Action / Observation). Núcleo del agente. |
| `tools/critic.py` | Revisor adversarial opcional. Puede vetar una acción del Red antes de ejecutarla. |
| `tools/runner.py` | Ejecuta los comandos vía `docker exec` al contenedor `pentest-tools` (Kali). |
| `tools/scope_guard.py` | Configura iptables OUTPUT en el contenedor Kali para que solo salga tráfico al scope autorizado. |
| `utils/scheduler.py` | APScheduler con 3 jobs por engagement (preload, start, cleanup). |
| `utils/auto_poller.py` | Cada N minutos pregunta al backend si hay engagements `pendiente` y los programa. |
| `utils/vpn.py` | Levanta y baja WireGuard (interfaz `eng_<ref>`) cuando el engagement requiere acceso a una red interna del cliente. |
| `utils/intel.py` | Genera el dossier OSINT con el LLM (`SYSTEM_DESTILADOR`). |
| `utils/memory_store.py` | Cliente pgvector. Indexa hallazgos y los recupera por similitud para inyectarlos al prompt. |
| `utils/reporting.py` | Genera el informe técnico y el ejecutivo a partir de la evidencia acumulada. |
| `utils/model_client.py` | HTTP a vLLM (`/v1/chat/completions`). Tres wrappers: one-shot, multi-turn y multi-turn-con-thinking. |
| `utils/state_manager.py` | Estado in-memory del engagement (hallazgos, tareas, dossier TTL). |
| `scripts/index_historicos.py` | Mantenimiento: re-indexa engagements antiguos en pgvector. |

---

## Línea de tiempo de un engagement

Asumimos un engagement de tipo `pentesting_interno` que entra a las **T** y
dura 2 h. Para cada momento citamos el archivo y la función exacta.

```
   T-∞                 T-20m          T          T+5..10s         T+~2h         T+~2h+5m
    │                    │            │              │               │              │
arranca           preload starts   start       primer Thought/   informes        cleanup
orchestrator     (WG + dossier)   engagement   Action/Observation  subidos      (WG down)
```

### T-∞ — Arranque del proceso orquestador

`server.py:156` declara un **lifespan** de FastAPI. En la subida, antes de
servir peticiones, hace:

1. `utils.scheduler.start()` (`utils/scheduler.py:46`) — crea un
   `AsyncIOScheduler` (`_build_scheduler`, `:37`) con `MemoryJobStore` por
   defecto y, si hay Redis, con `RedisJobStore` para sobrevivir reinicios.
2. `utils.memory_store.init()` (`utils/memory_store.py:77`) — abre el pool
   `asyncpg` a `pentest_memory` (pgvector), carga el modelo de embeddings
   `intfloat/multilingual-e5-small` (384 dim, `:39`) y verifica que las tablas
   y el índice HNSW existen.
3. Si `AUTO_POLL_ENABLED=true`, se programa el **auto-poller** como job
   recurrente (cada `AUTO_POLL_INTERVAL_MIN` minutos, `utils/auto_poller.py:35`).

A partir de ahí, `lifespan` cede el control a uvicorn y el server queda en
espera.

---

### Fase 0 — Cómo llega la petición

Hay **dos caminos** para que un engagement entre al orquestador. Ambos
terminan en la misma función: `utils.scheduler.schedule_engagement`.

**Camino A — auto-poller (producción).** Cada 5 min (por defecto)
`utils.auto_poller.poll_once` (`:249`) se ejecuta:

1. Login contra el backend FastAPI principal (`utils/auto_poller.py:121`,
   `_login`), guarda cookie de sesión.
2. Pide los eventos próximos al backend (`/api/admin/audits/upcoming` u
   homólogo) con la auth interna `INTERNAL_AUTH_TOKEN`.
3. Por cada evento `pendiente`:
   - `_parse_event_start` (`:155`) calcula `inicio_at` en UTC a partir de
     `fecha_inicial`, `horario_preferido` y el TZ local (`Europe/Madrid`).
   - `_duration_minutes` (`:194`) traduce `duracion` (`"2h"`, `"90m"`, …) a
     minutos.
   - `_map_tipo` (`:69`) mapea `scope` → `tipo_auditoria` (p. ej.
     `pentest_int` → `pentesting_interno`).
   - `_build_objetivo` (`:96`) y `_build_scope_extra` (`:110`) componen
     `objetivo` y `scope_extra` desde campos legacy + nuevos.
   - `_build_datos_inline` (`:235`) empaqueta todo lo que el LLM usará luego
     para destilar dossier.
   - Se llama a `scheduler.schedule_engagement(ref, inicio_at, tipo,
     objetivo, tiempo_min, datos_inline, scope_extra)` (`utils/scheduler.py:138`).

**Camino B — `POST /schedule` directo (demos, smoke tests).** Cualquier
cliente local manda un `ScheduleRequest` (`models/engagement.py`) a
`server.schedule` (`server.py:229`). Se valida que `inicio_at >= now+30s` y
se pasa también a `scheduler.schedule_engagement`. Útil para saltarse el
formulario admin y el ciclo de polling cuando estamos depurando.

En cualquiera de los dos casos, `schedule_engagement` registra **tres jobs**
en APScheduler con IDs `preload:<ref>`, `start:<ref>` y `cleanup:<ref>`:

```text
preload  at  inicio_at - PRELOAD_LEAD_MIN(20 min)
start    at  inicio_at
cleanup  at  inicio_at + tiempo_min + CLEANUP_MARGIN_MIN(5 min)
```

Si `preload_at` ya es pasado (porque pediste el engagement con menos de 20 min
de antelación), `schedule_engagement` fuerza `preload_at = now + 1s` para que
el preload corra "inmediatamente". El `start_job` espera siempre a su hora,
para no romper SLAs con el cliente.

---

### T-20 min — Preload (`utils.scheduler._preload_job`, `utils/scheduler.py:71`)

Fase ofuscada para el cliente. El objetivo es llegar a T con la VPN levantada
(si aplica) y el dossier ya destilado y cacheado, de modo que el primer
prompt del modelo en T+0 no se quede esperando red.

Pasos exactos:

1. `utils.intel.preload_dossier(ref, datos_inline, system_base_wr)`
   (`utils/intel.py:142`):
   - `_comprobar_artefactos_cliente(ref)` (`:79`) consulta MinIO
     (`audit-files/<ref>/`) para ver qué subió el cliente: dossier propio,
     credenciales preautorizadas, fichero WireGuard.
   - Si hay `wg_config.conf`, lo descarga a un bytes en memoria y delega a
     `utils.vpn.levantar_wg(ref)` (`utils/vpn.py:127`):
     - `_escribir_config(ref, contenido)` (`:94`) usa el helper setuid
       `/usr/local/sbin/orchestrator-wg-helper` para escribir
       `/etc/wireguard/eng_<ref-short>.conf` con permisos 600 root
       (el orquestador no es root; el helper sí).
     - `wg-quick up eng_<ref-short>` levanta la interfaz.
     - `_ultimo_handshake(ref)` (`:113`) verifica que el peer respondió en
       menos de `HANDSHAKE_MAX_AGE_S` (30 s); si no, la VPN se considera
       muerta y `preload` aborta antes de generar dossier inútil.
     - `set_vpn_state(ref, "up")` deja la marca con TTL `VPN_TTL_SEG`
       (48 h) por si el engagement se relanza dentro de ese plazo.
   - `_destilar_dossier(datos_inline, artefactos)` (`utils/intel.py:101`):
     llama a `model_client.ask_deepseek(prompt, system=SYSTEM_DESTILADOR)`
     (`utils/intel.py:46`, `utils/model_client.py:83`). El LLM lee todo lo
     que aportó el cliente + lo que se sabe del objetivo y devuelve un
     **dossier técnico** en markdown: empresa/sector, scope, vectores
     prioritarios, restricciones, hipótesis. Este texto se guarda en
     `state_manager.set_dossier(ref, dossier)` (`utils/state_manager.py:60`)
     con TTL 30 min.
   - `_warmup_whiterabbit(dossier_texto, system_base)` (`:128`) hace un
     primer turno corto contra Qwen3 con el dossier como contexto, para
     pre-cargar el caché de prefijos de vLLM (`--enable-prefix-caching`) —
     la primera iteración real del ReAct ya no paga el coste de tokenizar
     el system + dossier desde cero.

2. `memory_store.upsert_chunk(ref, "OSINT", dossier_texto, …)`
   (`utils/memory_store.py:136`): el dossier se segmenta y se sube como
   chunks con embedding en la tabla `pentest_memory`. Esto es lo que
   permite a `react_loop` recuperar "lo más relevante del dossier" por
   similitud en cada fase posterior (no se mete el dossier entero en el
   prompt de cada iteración).

Al final del preload, el sistema ya tiene: VPN viva + dossier en memoria +
caché de Qwen3 caliente + chunks indexados.

---

### T+0 — Start (`utils.scheduler._start_job`, `utils/scheduler.py:82`)

Arranque del engagement. Esta función:

1. Lee el dossier de `state_manager.get_dossier(ref)` (vivo gracias al TTL
   de 30 min que cubre los 20 min de preload + margen).
2. Llama a `tools.react_loop.ejecutar_react(ref, tipo, objetivo,
   tiempo_min, dossier, scope_extra)` (`tools/react_loop.py:204`).

Y delega TODA la lógica del engagement ahí.

#### Dentro de `ejecutar_react` (`tools/react_loop.py:204`)

Primero prepara el "campo de juego":

1. `scope_guard.aplicar_scope([objetivo] + scope_extra)`
   (`tools/scope_guard.py:99`):
   - Resuelve hostnames a IPs (`_resolver_async`, `:73`).
   - Construye una whitelist y aplica reglas iptables OUTPUT dentro del
     contenedor `pentest-tools` con `docker exec`. Solo deja salir tráfico
     a: scope autorizado + repos APT (`REPOS_APT`, `:21`) + APIs OSINT
     públicas (`OSINT_PUBLIC_APIS`, `:44`). El resto se DROP-ea.
2. Calcula las fases del engagement leyendo `FASES_POR_TIPO[tipo]` en
   `phases/plantillas.py:1`. Cada fase es una tupla
   `(nombre, peso, min_iter, max_iter, system_extra)`. El `peso` se usa
   para repartir el `tiempo_min` total → `budget_seg` por fase.

Entonces entra en el bucle por fase. Para cada fase:

3. `memory_store.retrieve(query=phase, ref, k=3)`
   (`utils/memory_store.py:179`): embebe la query, hace búsqueda kNN en
   pgvector y devuelve los 3 findings más cercanos (priorizando los de
   este engagement, luego los históricos del mismo objetivo).
4. `_construir_prompt_inicial(...)` (`tools/react_loop.py:130`) compone:
   - `SYSTEM_REACT` (`:26`) — el system prompt del Red (rúbrica de
     explotación, formato Thought/Action, restricciones).
   - + fase, objetivo, budget, dossier resumido, findings de memoria.
   - + toolbox específico de la fase: para OSINT
     `_build_osint_toolbox(objetivo)` (`:111`), que injecta una lista
     comentada de comandos sugeridos (subfinder, theHarvester, dig, crt.sh,
     etc.) ya con `<objetivo>` substituido.
5. Para cada iteración `i in 1..max_iter`:
   - `await model_client.ask_whiterabbit_chat(messages, max_tokens=400)`
     (`utils/model_client.py:78`) — multi-turn con el historial completo.
   - `_parsear_respuesta(texto)` (`tools/react_loop.py:175`) extrae
     `(thought, action)` aplicando los regex `RE_THOUGHT` (`:23`) y
     `RE_ACTION` (`:24`).
   - Si la action está vacía o el modelo intentó cerrar la fase con
     "Final answer", el bucle rompe.
   - **(opcional) revisión del Critic**: si `CRITIC_ENABLED` (`tools/
     critic.py:32`) está activo y `critic.critic_should_run(i, action)`
     (`:100`) dice que sí (por defecto cada `CRITIC_EVERY_N=3` iters o si
     la action contiene un patrón "hito" como `msfconsole`,
     `rm -rf`, `iptables`, etc., `_HITO_PATTERNS`, `:38`):
     - `critic.evaluar_action(action, history, dossier)` (`:216`) hace
       un nuevo chat completion con `SYSTEM_CRITIC` (`:67`) y parsea el
       JSON de verdict (`_parsear_verdict`, `:162`).
     - Si el verdict es `block`, la action se descarta, el modelo recibe
       como `Observation:` el razonamiento del critic, y se reintenta.
   - `runner.ejecutar_comando(action, timeout=…)` (`tools/runner.py:47`):
     - Resuelve el container ID con `_container_name()` (`:23`) buscando
       en Swarm por label.
     - Lanza `docker exec <id> sh -c "<action>"` con
       `asyncio.create_subprocess_exec`.
     - Captura stdout/stderr/returncode.
     - `_truncar(salida, MAX_OUTPUT_CHARS=6000)` (`:39`) recorta la
       salida para que entre en el contexto del modelo.
   - `_formatear_observation(res)` (`tools/react_loop.py:189`) construye
     la string `Observation:` y la trunca a `MAX_OBSERVATION_CHARS=1500`
     (`:22`) — el modelo no recibe nunca la salida completa, sólo el
     resumen que cabe en su ventana.
   - Se añade el par `{assistant: Thought+Action, user: Observation}` al
     historial y se vuelve al paso `await ask_whiterabbit_chat`.
6. Cuando el bucle de la fase termina (por `max_iter`, por `budget`, por
   "Final answer" o por timeout duro):
   - `memory_store.upsert_chunk(ref, fase, evidencia, …)` indexa lo
     encontrado para futuras fases y para futuros engagements (sirve como
     "memoria" persistente del agente).
   - Se loguea `[<ref-short>] <fase>: <n> iter, stop=<motivo>,
     evidencia=<n> comandos`. Esa línea es lo único visible en
     `journalctl -u orchestrator`.

Cuando se acaban todas las fases, `ejecutar_react` devuelve el historial
estructurado: lista de `(fase, [iteraciones])` con todas las observaciones
acumuladas.

#### De vuelta en `_start_job` (`utils/scheduler.py:82`)

Con la salida del ReAct en la mano:

7. `reporting.generar_informe_tecnico(ref, datos, fases_evidencia)`
   (`utils/reporting.py:101`):
   - Para cada fase: `_analizar_fase(fase, evidencia)` (`:80`) llama al
     LLM con `SYSTEM_TECNICO` (`:24`) y la evidencia truncada
     (`_truncar_evidencia`, `:71`). Devuelve markdown estructurado:
     comando + salida resumida + análisis + hallazgo + severidad.
   - Concatena todas las fases en un único `.md` con cabecera (datos del
     engagement, dossier) y tabla de severidades final.
8. `reporting.generar_informe_ejecutivo(ref, datos, técnico_md)`
   (`:143`): un único chat completion con `SYSTEM_EJECUTIVO` (`:51`) que
   re-escribe el técnico en lenguaje de negocio (sin jerga, foco en
   riesgo + acción).
9. `server.subir_informes_a_minio(ref, informes)` (`server.py:97`):
   `_subir_md` (`:85`) hace **dual-write** a MinIO local y MinIO remoto
   (VPS de datos). Si el local falla, `_guardar_local` (`:49`) vuelca a
   `informes_local/<ref>/`.
10. `server.marcar_completada_backend(ref)` (`:126`) hace un POST con
    `INTERNAL_AUTH_TOKEN` al backend FastAPI principal
    (`/api/admin/audits/<ref>/uploaded`) para que el panel del cliente
    pase a "completada" y muestre los botones de descarga.

---

### T+dur+5 min — Cleanup (`utils.scheduler._cleanup_job`, `utils/scheduler.py:113`)

Se ejecuta haya terminado bien o mal el engagement:

1. `vpn.bajar_wg(ref)` (`utils/vpn.py:161`) cierra la interfaz WireGuard y
   `_wipe_config(ref)` (`:170`) borra `eng_<ref-short>.conf`.
2. `scope_guard.limpiar_scope()` (`tools/scope_guard.py:141`) elimina las
   reglas iptables OUTPUT del contenedor Kali (vuelve a su estado por
   defecto = sin egress libre).
3. `runner.reiniciar_container()` (`tools/runner.py:94`) hace
   `docker service update --force pentest_pentest-tools`, lo que destruye
   y recrea el container. Garantiza que el siguiente engagement empieza
   con un Kali estéril (sin procesos colgados, sin loot residual, sin
   ficheros temporales del engagement anterior).
4. `state_manager.eliminar_engagement(ref)` (`utils/state_manager.py:49`)
   limpia la entrada en memoria.

---

## Cómo se relaciona todo con el LLM

El único punto del orquestador que habla con vLLM es **`utils/model_client.py`**.
Tres wrappers según el patrón de uso:

- `ask_whiterabbit(prompt, system=None)` (`:69`) — one-shot, lo usa el
  reporter (cada análisis de fase es independiente).
- `ask_whiterabbit_chat(messages, max_tokens, temperature)` (`:78`) —
  multi-turn, lo usan `react_loop` y `critic` (necesitan historial).
- `ask_deepseek(prompt, system)` (`:83`) — one-shot pero fuerza
  `enable_thinking=True`. Lo usa `intel.py` para destilar el dossier
  (un razonamiento profundo único por engagement).

Los tres delegan en `_ask_qwen3(messages, max_tokens, temperature,
enable_thinking)` (`:44`) que hace el POST `httpx` a `QWEN3_URL`
(`http://0.0.0.0:8003/v1/chat/completions`) — API OpenAI-compatible. No hay
ningún otro fichero que llame al LLM.

---

## Persistencia y memoria

| Qué se guarda | Dónde | Quién lo escribe | Cuándo |
|---|---|---|---|
| Dossier OSINT del engagement | RAM (`state_manager`) con TTL 30 min | `intel.preload_dossier` | Preload |
| Chunks indexados (dossier + hallazgos por fase) | pgvector tabla `pentest_memory` | `memory_store.upsert_chunk` | Preload + fin de cada fase |
| Informe técnico (.md) | MinIO local + remoto: `audit-files/<ref>/informe_tecnico.md` | `server.subir_informes_a_minio` | Fin del engagement |
| Informe ejecutivo (.md) | MinIO local + remoto: `audit-files/<ref>/informe_ejecutivo.md` | `server.subir_informes_a_minio` | Fin del engagement |
| Marca de completitud | Backend FastAPI (`/api/admin/audits/<ref>/uploaded`) | `server.marcar_completada_backend` | Inmediatamente tras subir informes |
| Trazas del proceso (stdout/stderr del orquestador) | journald del host | logger.info() en cada módulo | En tiempo real |

El contenedor `pentest-tools` (Kali) **no monta volúmenes**: cualquier
fichero que el agente cree dentro se pierde al `reiniciar_container` del
cleanup. La persistencia es responsabilidad del orquestador.

---

## Endpoints HTTP del orquestador

Todos sin auth, en `127.0.0.1:8000`:

| Método | Path | Función | Cuándo se usa |
|---|---|---|---|
| GET | `/health` | `server.health` (`:208`) | Probes de monitorización |
| POST | `/engagement` | `server.launch_engagement` (`:213`) | Modo síncrono, sin preload — solo para tests directos del bucle ReAct |
| POST | `/schedule` | `server.schedule` (`:229`) | Programar engagement futuro (camino normal) |
| POST | `/preload` | `server.preload` (`:247`) | Forzar preload independientemente del schedule |
| GET | `/dossier/{ref}` | `server.ver_dossier` (`:257`) | Recuperar el dossier ya destilado (debug) |
| GET | `/jobs` | `server.listar_jobs` (`:266`) | Listar jobs APScheduler vivos |
| DELETE | `/schedule/{ref}` | `server.cancelar` (`:271`) | Cancelar un engagement programado (no aborta uno en curso) |

---

## Ejecución como systemd unit

El proceso real corre como `orchestrator.service`:

```
ExecStartPre  =  sops -d secrets.enc.json > /run/orchestrator/env (modo 600)
ExecStart     =  /home/.../venv/bin/uvicorn server:app --host 0.0.0.0 --port 8000
EnvironmentFile = /run/orchestrator/env
```

Los secrets (claves de MinIO, token interno del backend, flags
`CRITIC_ENABLED`, credenciales del auto-poller…) viven cifrados en
`secrets.enc.json` (SOPS + age) y se descifran a un tmpfs solo legible por el
usuario del servicio antes del arranque. El proceso uvicorn nunca ve el
fichero cifrado; lee los envs ya descifrados desde `/run/orchestrator/env`.
