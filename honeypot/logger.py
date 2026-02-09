"""Logging helpers for the honeypot."""

import json
import logging
import os
import threading
from datetime import datetime, timezone
import requests

LOG_DIR = "/app/logs"
TEXT_LOG = os.path.join(LOG_DIR, "honeypot.log")
JSONL_LOG = os.path.join(LOG_DIR, "events.jsonl")

_lock = threading.Lock()


def _ts() -> str:
    return datetime.now(timezone.utc).isoformat()


def create_logger() -> logging.Logger:
    os.makedirs(LOG_DIR, exist_ok=True)

    logger = logging.getLogger("Honeypot")
    logger.setLevel(logging.INFO)

    if not logger.handlers:
        fmt = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")

        fh = logging.FileHandler(TEXT_LOG)
        fh.setFormatter(fmt)
        logger.addHandler(fh)

        sh = logging.StreamHandler()
        sh.setFormatter(fmt)
        logger.addHandler(sh)

    return logger


def log_event(event: dict) -> None:
    event = {"timestamp": _ts(), **event}
    line = json.dumps(event, ensure_ascii=False)

    with _lock:
        with open(JSONL_LOG, "a", encoding="utf-8") as f:
            f.write(line + "\n")


def alert(logger: logging.Logger, reason: str, **fields) -> None:
    logger.warning("ALERT: %s | %s", reason, fields)
    log_event({"event": "alert", "reason": reason, **fields})
    send_webhook(f"Honeypot alert: {reason} | {fields}")


DISCORD_WEBHOOK_URL = os.getenv("DISCORD_WEBHOOK_URL")


def send_webhook(message: str):
    if not DISCORD_WEBHOOK_URL:
        return
    try:
        requests.post(
            DISCORD_WEBHOOK_URL,
            json={"content": message},
            timeout=5,
        )
    except Exception:
        pass
