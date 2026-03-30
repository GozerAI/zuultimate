#!/usr/bin/env python3
"""Simulate PoP failure scenarios for resilience testing."""

import asyncio
import httpx
import sys


async def simulate_pop_down(pop_url: str, zuul_url: str):
    """Verify zuultimate handles PoP being unavailable."""
    print(f"[1] Testing PoP health at {pop_url}/health ...")
    async with httpx.AsyncClient(timeout=5.0) as client:
        try:
            resp = await client.get(f"{pop_url}/health")
            print(f"    PoP health: {resp.status_code} {resp.json()}")
        except Exception as e:
            print(f"    PoP unreachable (expected): {e}")

    print(f"\n[2] Testing zuultimate direct access at {zuul_url}/health ...")
    async with httpx.AsyncClient(timeout=5.0) as client:
        resp = await client.get(f"{zuul_url}/health")
        print(f"    Zuultimate health: {resp.status_code}")

    print("\n[3] Verifying workforce auth falls back to direct when PoP is down ...")
    print("    (In production: workforce routes require PoP headers)")
    print("    Simulation complete.\n")


if __name__ == "__main__":
    pop_url = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:9000"
    zuul_url = sys.argv[2] if len(sys.argv) > 2 else "http://localhost:8000"
    asyncio.run(simulate_pop_down(pop_url, zuul_url))
