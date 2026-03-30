"""Tests for session store with lazy deserialization."""

import json

import pytest

from zuultimate.performance.session_store import LazySession, LazySessionStore


class TestLazySession:
    """Item #51: Session store with lazy deserialization."""

    def test_deferred_parsing(self):
        raw = json.dumps({"user_id": "u1", "exp": 999})
        session = LazySession(raw)
        assert session.is_deserialized is False
        assert session["user_id"] == "u1"
        assert session.is_deserialized is True

    def test_get_with_default(self):
        session = LazySession(json.dumps({"a": 1}))
        assert session.get("a") == 1
        assert session.get("missing", "default") == "default"

    def test_contains(self):
        session = LazySession(json.dumps({"key": "val"}))
        assert "key" in session
        assert "missing" not in session

    def test_to_dict(self):
        data = {"x": 1, "y": 2}
        session = LazySession(json.dumps(data))
        assert session.to_dict() == data

    def test_raw_access(self):
        raw = '{"a":1}'
        session = LazySession(raw)
        assert session.raw == raw

    def test_repr_before_parse(self):
        session = LazySession('{"a":1}')
        assert "bytes" in repr(session)

    def test_repr_after_parse(self):
        session = LazySession('{"a":1}')
        session.to_dict()
        assert "a" in repr(session)


class TestLazySessionStore:
    def test_put_and_get(self):
        store = LazySessionStore()
        raw = json.dumps({"user_id": "u1", "jti": "j1"})
        store.put("j1", raw)
        session = store.get("j1")
        assert session is not None
        assert session["user_id"] == "u1"

    def test_miss_returns_none(self):
        store = LazySessionStore()
        assert store.get("missing") is None

    def test_lazy_not_parsed_until_access(self):
        store = LazySessionStore()
        store.put("j1", json.dumps({"a": 1}))
        session = store.get("j1")
        assert session is not None
        assert session.is_deserialized is False

    def test_invalidate(self):
        store = LazySessionStore()
        store.put("j1", json.dumps({"a": 1}))
        assert store.invalidate("j1") is True
        assert store.get("j1") is None

    def test_stats(self):
        store = LazySessionStore()
        stats = store.stats
        assert "hits" in stats
        assert "misses" in stats
