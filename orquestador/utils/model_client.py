"""
model_client.py — cliente HTTP del vLLM local.

Tras la migración 2026-05-11: un solo modelo unificado (Qwen3-14B-AWQ) que
reemplaza a DeepSeek-R1-Distill-Qwen-1.5B + WhiteRabbitNeo-2.5-Qwen-2.5-Coder-7B.
Mantenemos las APIs `ask_deepseek()` y `ask_whiterabbit()` como aliases para no
romper los callers existentes (intel.py, reporting.py, orquestador.py).
"""
import httpx
import re

# Endpoint único — Qwen3-14B-AWQ vía vLLM en el orchestrator host (mode: host).
QWEN3_URL   = "http://0.0.0.0:8003/v1/chat/completions"
QWEN3_MODEL = "qwen3"

# Aliases legacy. Apuntan al mismo backend pero las dejamos para que el resto
# del código no requiera refactor inmediato.
WHITERABBIT_URL   = QWEN3_URL
DEEPSEEK_URL      = QWEN3_URL
WHITERABBIT_MODEL = QWEN3_MODEL
DEEPSEEK_MODEL    = QWEN3_MODEL


def limpiar_respuesta(texto: str) -> str:
    # Decodifica markers BPE de Qwen tokenizer que vLLM emite crudos en eager mode:
    # 'Ġ' (U+0120) = espacio leading, 'Ċ' (U+010A) = newline.
    if "Ġ" in texto or "Ċ" in texto:
        texto = texto.replace("Ġ", " ").replace("Ċ", "\n")
    # Workaround mojibake: vLLM en algunos casos emite UTF-8 codepoint-a-codepoint
    # como si fuera Latin-1 ("¡" -> "Â¡", "qué" -> "quÃ©", emoji -> "ðŁĺĬ").
    if any(c in texto for c in ("Â", "ðŁ", "Ã©", "Ã¡", "Ã³", "Ã±")):
        try:
            texto = texto.encode("latin-1").decode("utf-8")
        except (UnicodeEncodeError, UnicodeDecodeError):
            pass
    # Quita reasoning trace de Qwen3 thinking mode (puede venir abierto sin cierre
    # si se corta por longitud, o solo con el cierre).
    texto = re.sub(r'<think>.*?</think>', '', texto, flags=re.DOTALL)
    texto = re.sub(r'^.*?</think>\s*', '', texto, flags=re.DOTALL)
    texto = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f]', '', texto)
    return texto.strip()


async def _ask_qwen3(
    messages: list,
    max_tokens: int = 1024,
    temperature: float = 0.3,
    enable_thinking: bool = False,
) -> str:
    """Llamada base a Qwen3. enable_thinking=True activa <think>...</think> en el
    chat template (útil para razonamientos complejos; cuesta tokens extra)."""
    payload = {
        "model": QWEN3_MODEL,
        "messages": messages,
        "max_tokens": max_tokens,
        "temperature": temperature,
        "chat_template_kwargs": {"enable_thinking": enable_thinking},
    }
    async with httpx.AsyncClient(timeout=180.0) as client:
        response = await client.post(QWEN3_URL, json=payload)
        data = response.json()
        if "choices" not in data:
            raise RuntimeError(f"vLLM error: {data.get('object', 'sin object')} | {str(data)[:300]}")
        return limpiar_respuesta(data["choices"][0]["message"]["content"])


# ── APIs públicas (mantienen los nombres legacy) ──────────────────────────────

async def ask_whiterabbit(prompt: str, system: str = None) -> str:
    """Alias legacy. Ahora apunta a Qwen3-14B (thinking off)."""
    messages = []
    if system:
        messages.append({"role": "system", "content": system})
    messages.append({"role": "user", "content": prompt})
    return await _ask_qwen3(messages, max_tokens=512, temperature=0.3)


async def ask_whiterabbit_chat(messages: list, max_tokens: int = 512, temperature: float = 0.3) -> str:
    """Variante con historial completo para bucles ReAct multi-turn."""
    return await _ask_qwen3(messages, max_tokens=max_tokens, temperature=temperature)


async def ask_deepseek(prompt: str, system: str = None) -> str:
    """Alias legacy. Ahora apunta a Qwen3-14B. Mantenemos el thinking ON aquí
    porque DeepSeek-R1 lo hacía y los callers que lo invocan suelen necesitar
    razonamiento profundo (intel.py para distilar dossier)."""
    messages = []
    if system:
        messages.append({"role": "system", "content": system})
    messages.append({"role": "user", "content": prompt})
    return await _ask_qwen3(messages, max_tokens=1024, temperature=0.3, enable_thinking=True)
