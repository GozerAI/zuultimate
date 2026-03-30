"""Sparse fieldsets for API responses.

Item #71: Sparse fieldsets for API responses.

Implements JSON:API-style sparse fieldsets via a ``fields`` query parameter.
Responses are filtered to include only the requested fields, reducing payload
size and serialization cost.
"""

from __future__ import annotations

from typing import Any

from fastapi import Query, Request
from fastapi.responses import JSONResponse


def parse_fields(fields_param: str | None) -> set[str] | None:
    """Parse a comma-separated ``fields`` query parameter.

    Returns None if no filtering requested (return all fields).
    Returns a set of field names if filtering is active.
    """
    if not fields_param:
        return None
    parts = {f.strip() for f in fields_param.split(",") if f.strip()}
    return parts or None


def filter_dict(data: dict[str, Any], fields: set[str] | None) -> dict[str, Any]:
    """Filter a dictionary to include only the specified fields.

    Always preserves ``id`` if present.  Returns the full dict if fields is None.
    """
    if fields is None:
        return data
    # Always include id for resource identification
    allowed = fields | {"id"}
    return {k: v for k, v in data.items() if k in allowed}


def filter_response(
    data: dict[str, Any] | list[dict[str, Any]],
    fields: set[str] | None,
) -> dict[str, Any] | list[dict[str, Any]]:
    """Apply sparse fieldset filtering to a single dict or list of dicts."""
    if fields is None:
        return data
    if isinstance(data, list):
        return [filter_dict(item, fields) for item in data]
    return filter_dict(data, fields)


class SparseFieldsetMiddleware:
    """Utility class for applying sparse fieldsets in route handlers.

    Usage in a route handler::

        @router.get("/users")
        async def list_users(fields: str | None = Query(None)):
            users = await service.list_users()
            return SparseFieldsetMiddleware.apply(users, fields)
    """

    @staticmethod
    def apply(
        data: dict[str, Any] | list[dict[str, Any]],
        fields_param: str | None,
    ) -> dict[str, Any] | list[dict[str, Any]]:
        fields = parse_fields(fields_param)
        return filter_response(data, fields)
