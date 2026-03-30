"""Exports the OpenAPI 3.1 spec from the FastAPI application."""

import json
import yaml
from zuultimate.app import create_app


def export():
    app = create_app()
    spec = app.openapi()

    # Add x-stability and x-required-scopes extensions to each endpoint
    for path, methods in spec.get("paths", {}).items():
        for method, details in methods.items():
            if isinstance(details, dict):
                # Default all endpoints to stable
                details["x-stability"] = "stable"

                # Mark new Phase 1-3 endpoints as beta
                if any(
                    segment in path
                    for segment in [
                        "/consent/",
                        "/privacy/",
                        "/risk/",
                        "/introspect",
                        "/passkey/",
                        "/legacy-login",
                    ]
                ):
                    details["x-stability"] = "beta"

                # Mark auth-required endpoints
                if details.get("security"):
                    details["x-required-scopes"] = ["identity:read"]
                    if method in ("post", "put", "delete"):
                        details["x-required-scopes"] = ["identity:write"]

    # Write YAML
    with open("docs/api/openapi.yaml", "w") as f:
        yaml.dump(spec, f, default_flow_style=False, sort_keys=False, allow_unicode=True)

    # Write JSON
    with open("docs/api/openapi.json", "w") as f:
        json.dump(spec, f, indent=2)

    print(f"Exported {len(spec.get('paths', {}))} paths to docs/api/openapi.yaml")


if __name__ == "__main__":
    export()
