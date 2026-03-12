"""Pagination utilities for list endpoints."""

import math

from zuultimate.common.schemas import Pagination


def paginate_list(items: list, page: int = 1, page_size: int = 50) -> dict:
    """Paginate an in-memory list. Returns dict with 'items' and 'pagination'."""
    page = max(1, page)
    page_size = max(1, min(page_size, 200))
    total = len(items)
    total_pages = math.ceil(total / page_size) if total > 0 else 0
    start = (page - 1) * page_size
    end = start + page_size
    return {
        "items": items[start:end],
        "pagination": Pagination(
            page=page,
            page_size=page_size,
            total=total,
            total_pages=total_pages,
        ),
    }
