"""Structured JSON logging for Zuultimate."""

import contextvars
import json
import logging
import sys
from datetime import datetime, timezone

# Context variable for per-request correlation ID
request_id_var: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "request_id", default=None
)


class JSONFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        log_data = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        req_id = request_id_var.get()
        if req_id:
            log_data["request_id"] = req_id
        if record.exc_info and record.exc_info[1]:
            log_data["exception"] = str(record.exc_info[1])
        return json.dumps(log_data)


def get_logger(name: str) -> logging.Logger:
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(JSONFormatter())
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
    return logger
