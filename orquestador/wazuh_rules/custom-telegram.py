#!/usr/bin/env python3
"""
Wazuh custom integration → Telegram (HTML format, robusto frente a chars especiales).

Invocación de Wazuh:
  custom-telegram <alert_json_file> <chat_id> <bot_endpoint>
"""
from __future__ import annotations
import html
import json
import sys
import urllib.request
import urllib.error

_EMOJI_BY_BUCKET = {"low": "🟢", "medium": "🟡", "high": "🟠", "critical": "🔴"}


def severity_bucket(level: int) -> str:
    if level >= 13: return "critical"
    if level >= 10: return "high"
    if level >= 7:  return "medium"
    return "low"


def h(s: str) -> str:
    """HTML escape para Telegram parse_mode=HTML."""
    return html.escape(str(s), quote=False)


def format_alert(alert: dict) -> str:
    rule = alert.get("rule", {}) or {}
    agent = alert.get("agent", {}) or {}
    level = int(rule.get("level", 0))
    bucket = severity_bucket(level)
    emoji = _EMOJI_BY_BUCKET[bucket]

    desc = h(rule.get("description", "(sin descripción)"))
    rule_id = h(rule.get("id", "?"))
    agent_name = h(agent.get("name", "?"))
    location = h(alert.get("location", "?"))
    groups = ", ".join(rule.get("groups", []) or [])
    ts = h(alert.get("timestamp", "?"))
    full_log = h((alert.get("full_log") or "")[:1500])

    parts = [
        f"{emoji} <b>{desc}</b>",
        f"<code>rule={rule_id} lvl={level} bucket={bucket}</code>",
        f"<b>Agent:</b> <code>{agent_name}</code>",
        f"<b>Location:</b> <code>{location}</code>",
    ]
    if groups:
        parts.append(f"<b>Groups:</b> {h(groups)}")
    if full_log:
        parts.append(f"<b>Log:</b>\n<pre>{full_log}</pre>")
    parts.append(f"<i>ts: {ts}</i>")
    return "\n".join(parts)[:4000]


def main() -> int:
    if len(sys.argv) < 4:
        print("usage: custom-telegram <alert.json> <chat_id> <bot_endpoint>",
              file=sys.stderr)
        return 2

    alert_path = sys.argv[1]
    chat_id = sys.argv[2]
    endpoint = sys.argv[3]

    try:
        with open(alert_path, "r", encoding="utf-8") as fh:
            alert = json.load(fh)
    except Exception as exc:
        print(f"error reading alert: {exc}", file=sys.stderr)
        return 1

    text = format_alert(alert)
    payload = {
        "chat_id": chat_id,
        "text": text,
        "parse_mode": "HTML",
        "disable_web_page_preview": True,
    }
    req = urllib.request.Request(
        endpoint,
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "User-Agent": "wazuh-custom-telegram/1.1",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            if 200 <= resp.status < 300:
                return 0
            print(f"telegram HTTP {resp.status}", file=sys.stderr)
            return 1
    except urllib.error.HTTPError as exc:
        body_txt = exc.read().decode("utf-8", errors="replace")[:300]
        print(f"telegram error {exc.code}: {body_txt}", file=sys.stderr)
        return 1
    except Exception as exc:
        print(f"telegram send failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
