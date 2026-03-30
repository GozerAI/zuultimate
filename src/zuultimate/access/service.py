"""Access control service -- policy evaluation, RBAC."""

import fnmatch

from sqlalchemy import select

from zuultimate.access.models import AuditEntry, Policy, Role, RoleAssignment
from zuultimate.common.database import DatabaseManager
from zuultimate.common.exceptions import NotFoundError, ValidationError

_DB_KEY = "identity"


class AccessService:
    def __init__(self, db: DatabaseManager):
        self.db = db

    async def check_access(self, user_id: str, resource: str, action: str) -> dict:
        async with self.db.get_session(_DB_KEY) as session:
            # Get user's role IDs
            result = await session.execute(
                select(RoleAssignment.role_id).where(RoleAssignment.user_id == user_id)
            )
            role_ids = [row[0] for row in result.all()]

            # Collect matching policies: global (no role_id) + role-scoped
            stmt = select(Policy).where(Policy.role_id.is_(None))
            result = await session.execute(stmt)
            policies = list(result.scalars().all())

            if role_ids:
                stmt = select(Policy).where(Policy.role_id.in_(role_ids))
                result = await session.execute(stmt)
                policies.extend(result.scalars().all())

            # Filter to policies matching resource + action patterns
            matching = [
                p for p in policies
                if fnmatch.fnmatch(resource, p.resource_pattern)
                and fnmatch.fnmatch(action, p.action_pattern)
            ]

            # Sort by priority descending (higher priority evaluated first)
            matching.sort(key=lambda p: p.priority, reverse=True)

            # Deny-first evaluation
            allowed = False
            reason = "No matching policy (default deny)"
            for policy in matching:
                if policy.effect == "deny":
                    allowed = False
                    reason = f"Denied by policy '{policy.name}'"
                    break
                if policy.effect == "allow":
                    allowed = True
                    reason = f"Allowed by policy '{policy.name}'"
                    break

            # Write audit entry
            audit = AuditEntry(
                user_id=user_id,
                action=action,
                resource=resource,
                result="allow" if allowed else "deny",
                detail=reason,
            )
            session.add(audit)

        return {"allowed": allowed, "reason": reason}

    async def create_policy(
        self,
        name: str,
        effect: str,
        resource_pattern: str,
        action_pattern: str,
        priority: int = 0,
        role_id: str | None = None,
    ) -> dict:
        if effect not in ("allow", "deny"):
            raise ValidationError(f"Effect must be 'allow' or 'deny', got '{effect}'")

        async with self.db.get_session(_DB_KEY) as session:
            policy = Policy(
                name=name,
                effect=effect,
                resource_pattern=resource_pattern,
                action_pattern=action_pattern,
                priority=priority,
                role_id=role_id,
            )
            session.add(policy)
            await session.flush()

        return {
            "id": policy.id,
            "name": policy.name,
            "effect": policy.effect,
            "resource_pattern": policy.resource_pattern,
            "action_pattern": policy.action_pattern,
            "priority": policy.priority,
            "role_id": policy.role_id,
        }

    async def assign_role(
        self, role_id: str, user_id: str, assigned_by: str | None = None
    ) -> dict:
        async with self.db.get_session(_DB_KEY) as session:
            # Verify role exists
            result = await session.execute(
                select(Role).where(Role.id == role_id)
            )
            if result.scalar_one_or_none() is None:
                raise NotFoundError("Role not found")

            # Check duplicate assignment
            result = await session.execute(
                select(RoleAssignment).where(
                    RoleAssignment.role_id == role_id,
                    RoleAssignment.user_id == user_id,
                )
            )
            if result.scalar_one_or_none() is not None:
                raise ValidationError("User already assigned to this role")

            assignment = RoleAssignment(
                role_id=role_id,
                user_id=user_id,
                assigned_by=assigned_by,
            )
            session.add(assignment)
            await session.flush()

        return {
            "id": assignment.id,
            "role_id": assignment.role_id,
            "user_id": assignment.user_id,
            "assigned_by": assignment.assigned_by,
        }
