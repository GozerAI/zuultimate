"""Unit tests for zuultimate.common.pagination."""

from zuultimate.common.pagination import paginate_list


def test_paginate_basic():
    items = list(range(10))
    result = paginate_list(items, page=1, page_size=5)
    assert result["items"] == [0, 1, 2, 3, 4]
    assert result["pagination"].total == 10
    assert result["pagination"].total_pages == 2
    assert result["pagination"].page == 1


def test_paginate_second_page():
    items = list(range(10))
    result = paginate_list(items, page=2, page_size=5)
    assert result["items"] == [5, 6, 7, 8, 9]


def test_paginate_empty():
    result = paginate_list([], page=1, page_size=10)
    assert result["items"] == []
    assert result["pagination"].total == 0
    assert result["pagination"].total_pages == 0


def test_paginate_beyond_last_page():
    items = list(range(5))
    result = paginate_list(items, page=100, page_size=10)
    assert result["items"] == []
    assert result["pagination"].total == 5


def test_paginate_clamps_page_size():
    items = list(range(5))
    result = paginate_list(items, page=1, page_size=999)
    assert result["pagination"].page_size == 200


def test_paginate_default_params():
    items = list(range(3))
    result = paginate_list(items)
    assert result["items"] == [0, 1, 2]
    assert result["pagination"].page == 1
    assert result["pagination"].page_size == 50
