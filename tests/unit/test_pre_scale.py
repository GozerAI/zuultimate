"""Tests for the pre-scale script."""

import sys
import os

import pytest

# Add scripts dir to path so we can import pre_scale
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "scripts"))

from pre_scale import calculate_pod_count, generate_commands, RPS_PER_POD, SAFETY_MARGIN


# ── calculate_pod_count ──


def test_calculate_pod_count_basic():
    """Pod count for 800 RPS should be ceil(800/800 * 1.5) = 2."""
    assert calculate_pod_count(800) == 2


def test_calculate_pod_count_high_rps():
    """Pod count for 50000 RPS with safety margin."""
    expected = 94  # ceil(50000 / 800 * 1.5) = ceil(93.75) = 94
    assert calculate_pod_count(50000) == expected


def test_calculate_pod_count_low_rps():
    """Pod count for 100 RPS should be at least 1."""
    result = calculate_pod_count(100)
    assert result >= 1


def test_calculate_pod_count_includes_safety_margin():
    """Pod count should be higher than raw RPS/RPS_PER_POD due to safety margin."""
    from math import ceil

    target_rps = 10000
    raw = ceil(target_rps / RPS_PER_POD)
    with_margin = calculate_pod_count(target_rps)
    assert with_margin > raw


# ── generate_commands ──


def test_generate_commands_includes_deployment_name():
    """Generated commands should reference the deployment name."""
    commands = generate_commands(
        deployment="zuultimate-auth",
        namespace="zuultimate",
        pod_count=50,
        duration_hours=4.0,
        event_name="Test Event",
    )
    assert len(commands) == 3
    for cmd in commands:
        assert "zuultimate-auth" in cmd


def test_generate_commands_revert_time():
    """Generated revert command should schedule a scale-down."""
    commands = generate_commands(
        deployment="zuultimate-auth",
        namespace="zuultimate",
        pod_count=50,
        duration_hours=2.0,
        event_name="Game Day",
    )
    # The last command should contain the revert (at command)
    revert_cmd = commands[-1]
    assert "--replicas=10" in revert_cmd
    assert "at" in revert_cmd
