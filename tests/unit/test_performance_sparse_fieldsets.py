"""Tests for sparse fieldsets for API responses."""

import pytest

from zuultimate.performance.sparse_fieldsets import (
    SparseFieldsetMiddleware,
    filter_dict,
    filter_response,
    parse_fields,
)


class TestParseFields:
    """Item #71: Sparse fieldsets for API responses."""

    def test_none_input(self):
        assert parse_fields(None) is None

    def test_empty_string(self):
        assert parse_fields("") is None

    def test_single_field(self):
        assert parse_fields("name") == {"name"}

    def test_multiple_fields(self):
        assert parse_fields("name,email,status") == {"name", "email", "status"}

    def test_whitespace_handling(self):
        assert parse_fields("name , email , status") == {"name", "email", "status"}

    def test_trailing_comma(self):
        result = parse_fields("name,email,")
        assert result == {"name", "email"}


class TestFilterDict:
    def test_no_filter(self):
        data = {"id": "1", "name": "test", "email": "a@b.c"}
        assert filter_dict(data, None) == data

    def test_filter_fields(self):
        data = {"id": "1", "name": "test", "email": "a@b.c"}
        result = filter_dict(data, {"name"})
        assert result == {"id": "1", "name": "test"}

    def test_id_always_preserved(self):
        data = {"id": "1", "name": "test", "email": "a@b.c"}
        result = filter_dict(data, {"email"})
        assert "id" in result

    def test_missing_field_ignored(self):
        data = {"id": "1", "name": "test"}
        result = filter_dict(data, {"name", "nonexistent"})
        assert result == {"id": "1", "name": "test"}


class TestFilterResponse:
    def test_filter_single_dict(self):
        data = {"id": "1", "name": "test", "extra": "x"}
        result = filter_response(data, {"name"})
        assert result == {"id": "1", "name": "test"}

    def test_filter_list(self):
        data = [
            {"id": "1", "name": "a", "extra": "x"},
            {"id": "2", "name": "b", "extra": "y"},
        ]
        result = filter_response(data, {"name"})
        assert result == [
            {"id": "1", "name": "a"},
            {"id": "2", "name": "b"},
        ]

    def test_no_filter_passthrough(self):
        data = {"id": "1", "name": "test"}
        assert filter_response(data, None) is data


class TestSparseFieldsetMiddleware:
    def test_apply_with_fields(self):
        data = [{"id": "1", "name": "a", "email": "x"}]
        result = SparseFieldsetMiddleware.apply(data, "name")
        assert result == [{"id": "1", "name": "a"}]

    def test_apply_without_fields(self):
        data = {"id": "1", "name": "a"}
        result = SparseFieldsetMiddleware.apply(data, None)
        assert result == data
