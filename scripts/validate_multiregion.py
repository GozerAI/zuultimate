#!/usr/bin/env python3
"""Validate multi-region deployment: JWKS federation, 307 routing, sovereignty."""

import asyncio
import sys

import httpx


async def validate(us_url: str, eu_url: str):
    print("=== Multi-Region Validation ===\n")

    async with httpx.AsyncClient(timeout=10.0, follow_redirects=False) as client:
        # 1. Health checks
        print("[1] Health checks")
        for name, url in [("US", us_url), ("EU", eu_url)]:
            try:
                resp = await client.get(f"{url}/health")
                print(f"    {name}: {resp.status_code} — {resp.json().get('status', 'unknown')}")
            except Exception as e:
                print(f"    {name}: UNREACHABLE — {e}")

        # 2. JWKS endpoints
        print("\n[2] JWKS endpoints")
        for name, url in [("US", us_url), ("EU", eu_url)]:
            try:
                resp = await client.get(f"{url}/.well-known/jwks.json")
                keys = resp.json().get("keys", [])
                print(f"    {name}: {len(keys)} key(s) — kids: {[k['kid'] for k in keys]}")
            except Exception as e:
                print(f"    {name}: ERROR — {e}")

        # 3. Cross-region JWKS validation
        print("\n[3] Cross-region JWKS validation")
        try:
            us_keys = (await client.get(f"{us_url}/.well-known/jwks.json")).json().get("keys", [])
            eu_keys = (await client.get(f"{eu_url}/.well-known/jwks.json")).json().get("keys", [])
            us_kids = {k["kid"] for k in us_keys}
            eu_kids = {k["kid"] for k in eu_keys}
            if us_kids and eu_kids:
                print(f"    US kids: {us_kids}")
                print(f"    EU kids: {eu_kids}")
                print(f"    Keys are {'shared' if us_kids == eu_kids else 'independent'} (expected: independent)")
            else:
                print("    Skipped — no keys found")
        except Exception as e:
            print(f"    ERROR — {e}")

        # 4. Region routing (307 redirect)
        print("\n[4] Region routing")
        print("    Register user on US instance...")
        try:
            reg = await client.post(f"{us_url}/v1/identity/register", json={
                "email": "test-multiregion@test.com",
                "username": "testmr",
                "password": "TestPass123",
            })
            print(f"    Register: {reg.status_code}")

            login = await client.post(f"{us_url}/v1/identity/login", json={
                "username": "testmr",
                "password": "TestPass123",
            })
            print(f"    Login: {login.status_code}")
            if login.status_code == 200:
                token = login.json()["access_token"]
                # Try accessing EU with US token — should get 307 if tenant routing is set
                headers = {"Authorization": f"Bearer {token}"}
                eu_resp = await client.get(f"{eu_url}/v1/identity/me", headers=headers)
                print(f"    EU access with US token: {eu_resp.status_code}")
        except Exception as e:
            print(f"    ERROR — {e}")

    print("\n=== Validation complete ===")


if __name__ == "__main__":
    us = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8000"
    eu = sys.argv[2] if len(sys.argv) > 2 else "http://localhost:8001"
    asyncio.run(validate(us, eu))
