#!/usr/bin/env bash
# export_public.sh - Creates a clean public export of Zuultimate for GozerAI/zuultimate.
# Usage: bash scripts/export_public.sh [target_dir]
#
# Strips proprietary Pro/Enterprise modules and internal infrastructure,
# leaving only community-tier code + license gate stubs.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TARGET="${1:-${REPO_ROOT}/../zuultimate-public-export}"

echo "=== Zuultimate Public Export ==="
echo "Source: ${REPO_ROOT}"
echo "Target: ${TARGET}"

# Clean target
rm -rf "${TARGET}"
mkdir -p "${TARGET}"

# Use git archive to get a clean copy (respects .gitignore, excludes .git)
cd "${REPO_ROOT}"
git archive HEAD | tar -x -C "${TARGET}"

# ===== STRIP PROPRIETARY MODULES =====

# Pro tier
rm -rf "${TARGET}/src/zuultimate/ai_security/"
rm -rf "${TARGET}/src/zuultimate/backup_resilience/"

# Enterprise tier
rm -rf "${TARGET}/src/zuultimate/access/"
rm -rf "${TARGET}/src/zuultimate/csuite_plugin/"
rm -rf "${TARGET}/src/zuultimate/crm/"
rm -rf "${TARGET}/src/zuultimate/pos/"

# ===== STRIP TESTS FOR PROPRIETARY MODULES =====

# Unit tests - Pro
rm -f "${TARGET}/tests/unit/test_ai_gateway.py"
rm -f "${TARGET}/tests/unit/test_injection_detector.py"
rm -f "${TARGET}/tests/unit/test_tool_guard.py"
rm -f "${TARGET}/tests/unit/test_red_team.py"
rm -f "${TARGET}/tests/unit/test_compliance.py"
rm -f "${TARGET}/tests/unit/test_fraud_scoring.py"
rm -f "${TARGET}/tests/unit/test_backup_service.py"
rm -f "${TARGET}/tests/unit/test_audit_log.py"
rm -f "${TARGET}/tests/unit/test_audit_retention.py"
rm -f "${TARGET}/tests/unit/test_audit_store.py"

# Unit tests - Enterprise
rm -f "${TARGET}/tests/unit/test_access_enforcement.py"
rm -f "${TARGET}/tests/unit/test_access_service.py"
rm -f "${TARGET}/tests/unit/test_csuite_plugin.py"
rm -f "${TARGET}/tests/unit/test_crm_adapters.py"
rm -f "${TARGET}/tests/unit/test_crm_service.py"
rm -f "${TARGET}/tests/unit/test_pos_service.py"
rm -f "${TARGET}/tests/unit/test_settlement.py"
rm -f "${TARGET}/tests/unit/test_sso_service.py"

# Integration tests - Pro
rm -f "${TARGET}/tests/integration/test_ai_security_router.py"
rm -f "${TARGET}/tests/integration/test_backup_router.py"
rm -f "${TARGET}/tests/integration/test_retention_router.py"

# Integration tests - Enterprise
rm -f "${TARGET}/tests/integration/test_access_router.py"
rm -f "${TARGET}/tests/integration/test_crm_router.py"
rm -f "${TARGET}/tests/integration/test_pos_router.py"
rm -f "${TARGET}/tests/integration/test_sso_router.py"

# ===== CREATE STUB __init__.py FOR STRIPPED PACKAGES =====

STUB_CONTENT=$(cat << 'STUBEOF'
"""This module requires a commercial license.

Visit https://gozerai.com/pricing for Pro and Enterprise tier details.
Set VINZY_LICENSE_KEY to unlock licensed features.
"""

raise ImportError(
    f"{__name__} requires a commercial license. "
    "Visit https://gozerai.com/pricing for details."
)
STUBEOF
)

for pkg in ai_security backup_resilience access csuite_plugin crm pos; do
    mkdir -p "${TARGET}/src/zuultimate/${pkg}"
    echo "${STUB_CONTENT}" > "${TARGET}/src/zuultimate/${pkg}/__init__.py"
done

# ===== PATCH app.py - remove stripped router imports and model imports =====

sed -i '/import zuultimate\.access\.models/d' "${TARGET}/src/zuultimate/app.py"
sed -i '/import zuultimate\.pos\.models/d' "${TARGET}/src/zuultimate/app.py"
sed -i '/import zuultimate\.crm\.models/d' "${TARGET}/src/zuultimate/app.py"
sed -i '/import zuultimate\.backup_resilience\.models/d' "${TARGET}/src/zuultimate/app.py"
sed -i '/import zuultimate\.ai_security\.models/d' "${TARGET}/src/zuultimate/app.py"

sed -i '/from zuultimate\.ai_security\.router/d' "${TARGET}/src/zuultimate/app.py"
sed -i '/from zuultimate\.access\.router/d' "${TARGET}/src/zuultimate/app.py"
sed -i '/from zuultimate\.pos\.router/d' "${TARGET}/src/zuultimate/app.py"
sed -i '/from zuultimate\.crm\.router/d' "${TARGET}/src/zuultimate/app.py"
sed -i '/from zuultimate\.backup_resilience\.router/d' "${TARGET}/src/zuultimate/app.py"
sed -i '/from zuultimate\.identity\.sso_router/d' "${TARGET}/src/zuultimate/app.py"

sed -i '/v1\.include_router(ai_router)/d' "${TARGET}/src/zuultimate/app.py"
sed -i '/v1\.include_router(access_router)/d' "${TARGET}/src/zuultimate/app.py"
sed -i '/v1\.include_router(pos_router)/d' "${TARGET}/src/zuultimate/app.py"
sed -i '/v1\.include_router(crm_router)/d' "${TARGET}/src/zuultimate/app.py"
sed -i '/v1\.include_router(backup_router)/d' "${TARGET}/src/zuultimate/app.py"
sed -i '/v1\.include_router(sso_router)/d' "${TARGET}/src/zuultimate/app.py"

# ===== PATCH conftest.py - remove stripped module model imports =====

sed -i '/import zuultimate\.pos\.models/d' "${TARGET}/tests/conftest.py"
sed -i '/import zuultimate\.crm\.models/d' "${TARGET}/tests/conftest.py"
sed -i '/import zuultimate\.backup_resilience\.models/d' "${TARGET}/tests/conftest.py"
sed -i '/import zuultimate\.ai_security\.models/d' "${TARGET}/tests/conftest.py"
sed -i '/crm_db_url=/d' "${TARGET}/tests/conftest.py"

# ===== UPDATE docs/pricing - replace chrisarseno links with GozerAI =====

if [ -f "${TARGET}/docs/pricing/index.html" ]; then
    sed -i 's|github.com/chrisarseno/zuultimate|github.com/GozerAI/zuultimate|g' "${TARGET}/docs/pricing/index.html"
fi

# ===== UPDATE pyproject.toml - update URLs =====

sed -i 's|chrisarseno/zuultimate|GozerAI/zuultimate|g' "${TARGET}/pyproject.toml"

# ===== UPDATE README =====
# README is generated by a companion Python script to avoid heredoc issues
python3 "$(dirname "$0")/write_readme.py" "${TARGET}/README.md" zuultimate

echo ""
echo "=== Export complete: ${TARGET} ==="
echo ""
echo "Community-tier modules included:"
echo "  identity, vault, plugins, common, webhooks"
echo ""
echo "Stripped (Pro/Enterprise/Private):"
echo "  ai_security, backup_resilience, access, csuite_plugin, crm, pos"
