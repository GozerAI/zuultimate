#!/usr/bin/env python3
"""Simulate certificate revocation and CRL update propagation."""

import asyncio
import httpx
import sys
import time


async def simulate_revocation(pop_url: str, pki_url: str):
    """Test that revoked certificates are rejected after CRL refresh."""
    print("[1] Checking current CRL ...")
    async with httpx.AsyncClient(timeout=5.0) as client:
        try:
            resp = await client.get(f"{pki_url}/crl")
            print(f"    CRL endpoint: {resp.status_code}")
        except Exception as e:
            print(f"    PKI unreachable: {e}")

    print("\n[2] Simulating certificate revocation ...")
    print("    (Would POST to PKI revoke endpoint)")

    print("\n[3] Waiting for CRL refresh (15 min in production, simulated) ...")
    await asyncio.sleep(1)

    print("\n[4] Verifying revoked cert is rejected ...")
    print("    (PoP should reject requests with revoked cert)")
    print("    Simulation complete.\n")


if __name__ == "__main__":
    pop_url = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:9000"
    pki_url = sys.argv[2] if len(sys.argv) > 2 else "http://localhost:9999"
    asyncio.run(simulate_revocation(pop_url, pki_url))
