"""Seeds the sandbox with a demo tenant and test credentials.

Usage: python scripts/seed_sandbox.py
"""

import asyncio
import httpx

BASE_URL = "http://localhost:8000"

async def seed():
    async with httpx.AsyncClient(timeout=10.0) as client:
        # Wait for zuultimate to be ready
        for _ in range(30):
            try:
                resp = await client.get(f"{BASE_URL}/health/ready")
                if resp.status_code == 200:
                    break
            except httpx.ConnectError:
                pass
            await asyncio.sleep(1)

        # Provision demo tenant
        resp = await client.post(
            f"{BASE_URL}/v1/tenants/provision",
            json={
                "name": "Demo Corp",
                "slug": "demo-corp",
                "owner_email": "admin@demo.local",
                "owner_username": "demo-admin",
                "owner_password": "DemoPass123!",
                "plan": "pro",
            },
            headers={"X-Service-Token": "sandbox-service-token"},
        )

        if resp.status_code == 200:
            data = resp.json()
            print("Sandbox seeded successfully!")
            print(f"  Tenant ID:  {data['tenant_id']}")
            print(f"  User ID:    {data['user_id']}")
            print(f"  API Key:    {data['api_key']}")
            print(f"  Plan:       {data['plan']}")
            print(f"  Login:      demo-admin / DemoPass123!")
            print(f"  API Docs:   http://localhost:8080")
        else:
            print(f"Seed failed: {resp.status_code} {resp.text}")

if __name__ == "__main__":
    asyncio.run(seed())
