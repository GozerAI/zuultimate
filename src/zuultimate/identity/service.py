"""Identity service -- registration, login, logout, token refresh."""

import hashlib
import os
from datetime import datetime, timedelta, timezone

from sqlalchemy import delete as sa_delete, select

from zuultimate.common.config import ZuulSettings
from zuultimate.common.database import DatabaseManager
from zuultimate.common.exceptions import AuthenticationError, NotFoundError, ValidationError
from zuultimate.common.security import create_jwt, decode_jwt, hash_password, verify_password
from zuultimate.identity.models import Credential, EmailVerificationToken, User, UserSession
from zuultimate.identity.mfa_service import MFAService
from zuultimate.identity.schemas import TokenResponse, UserResponse

_DB_KEY = "identity"


class IdentityService:
    def __init__(self, db: DatabaseManager, settings: ZuulSettings):
        self.db = db
        self.settings = settings

    def _make_token_pair(self, user: User) -> tuple[str, str]:
        """Create access + refresh token pair."""
        base_claims = {
            "sub": user.id,
            "username": user.username,
            "tenant_id": user.tenant_id,
        }
        access = create_jwt(
            {**base_claims, "type": "access"},
            self.settings.secret_key,
            expires_minutes=self.settings.access_token_expire_minutes,
        )
        refresh = create_jwt(
            {**base_claims, "type": "refresh"},
            self.settings.secret_key,
            expires_minutes=self.settings.refresh_token_expire_days * 24 * 60,
        )
        return access, refresh

    async def issue_tokens_for_user(self, user_id: str) -> dict:
        """Look up an active user by ID and issue a new token pair with session."""
        async with self.db.get_session(_DB_KEY) as session:
            result = await session.execute(
                select(User).where(User.id == user_id, User.is_active == True)
            )
            user = result.scalar_one_or_none()
            if user is None:
                raise NotFoundError("User not found")

            access_token, refresh_token = self._make_token_pair(user)

            user_session = UserSession(
                user_id=user.id,
                access_token_hash=hashlib.sha256(access_token.encode()).hexdigest(),
                refresh_token_hash=hashlib.sha256(refresh_token.encode()).hexdigest(),
            )
            session.add(user_session)

        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
        }

    async def register(
        self, email: str, username: str, password: str, display_name: str = ""
    ) -> dict:
        async with self.db.get_session(_DB_KEY) as session:
            # Check duplicate email/username with generic error
            existing = await session.execute(
                select(User).where(User.email == email)
            )
            if existing.scalar_one_or_none() is not None:
                raise ValidationError("Email or username already in use")

            existing = await session.execute(
                select(User).where(User.username == username)
            )
            if existing.scalar_one_or_none() is not None:
                raise ValidationError("Email or username already in use")

            user = User(
                email=email,
                username=username,
                display_name=display_name or username,
            )
            session.add(user)
            await session.flush()

            credential = Credential(
                user_id=user.id,
                credential_type="password",
                hashed_value=hash_password(password),
            )
            session.add(credential)

        return UserResponse(
            id=user.id,
            email=user.email,
            username=user.username,
            display_name=user.display_name,
            is_active=user.is_active,
            is_verified=user.is_verified,
            tenant_id=user.tenant_id,
        ).model_dump()

    async def login(self, username: str, password: str) -> dict:
        async with self.db.get_session(_DB_KEY) as session:
            result = await session.execute(
                select(User).where(User.username == username, User.is_active == True)
            )
            user = result.scalar_one_or_none()
            if user is None:
                # Constant-time: always verify against a dummy hash
                verify_password("dummy", hash_password("dummy"))
                raise AuthenticationError("Invalid credentials")

            result = await session.execute(
                select(Credential).where(
                    Credential.user_id == user.id,
                    Credential.credential_type == "password",
                )
            )
            cred = result.scalar_one_or_none()
            if cred is None or not verify_password(password, cred.hashed_value):
                raise AuthenticationError("Invalid credentials")

            # Check if MFA is enabled
            mfa_svc = MFAService(self.db, self.settings)
            if await mfa_svc.has_active_mfa(user.id):
                mfa_token = mfa_svc.create_mfa_token(user.id, user.username)
                return {
                    "mfa_required": True,
                    "mfa_token": mfa_token,
                }

            access_token, refresh_token = self._make_token_pair(user)

            user_session = UserSession(
                user_id=user.id,
                access_token_hash=hashlib.sha256(access_token.encode()).hexdigest(),
                refresh_token_hash=hashlib.sha256(refresh_token.encode()).hexdigest(),
            )
            session.add(user_session)

        return TokenResponse(
            access_token=access_token,
            refresh_token=refresh_token,
            expires_in=self.settings.access_token_expire_minutes * 60,
        ).model_dump()

    async def get_user(self, user_id: str) -> dict:
        async with self.db.get_session(_DB_KEY) as session:
            result = await session.execute(
                select(User).where(User.id == user_id, User.is_active == True)
            )
            user = result.scalar_one_or_none()
            if user is None:
                raise NotFoundError("User not found")

        return UserResponse(
            id=user.id,
            email=user.email,
            username=user.username,
            display_name=user.display_name,
            is_active=user.is_active,
            is_verified=user.is_verified,
            tenant_id=user.tenant_id,
        ).model_dump()

    async def refresh_token(self, refresh_token: str) -> dict:
        try:
            payload = decode_jwt(refresh_token, self.settings.secret_key)
        except Exception:
            raise AuthenticationError("Invalid or expired refresh token")

        if payload.get("type") != "refresh":
            raise AuthenticationError("Invalid token type")

        user_id = payload.get("sub")
        if not user_id:
            raise AuthenticationError("Invalid token payload")

        token_hash = hashlib.sha256(refresh_token.encode()).hexdigest()

        async with self.db.get_session(_DB_KEY) as session:
            # Verify refresh token exists in DB
            result = await session.execute(
                select(UserSession).where(UserSession.refresh_token_hash == token_hash)
            )
            old_session = result.scalar_one_or_none()
            if old_session is None:
                raise AuthenticationError("Session not found or revoked")

            # Verify user still active
            result = await session.execute(
                select(User).where(User.id == user_id, User.is_active == True)
            )
            user = result.scalar_one_or_none()
            if user is None:
                raise AuthenticationError("User no longer active")

            # Rotate: delete old session, create new one
            await session.execute(
                sa_delete(UserSession).where(UserSession.id == old_session.id)
            )

            new_access, new_refresh = self._make_token_pair(user)
            new_session = UserSession(
                user_id=user.id,
                access_token_hash=hashlib.sha256(new_access.encode()).hexdigest(),
                refresh_token_hash=hashlib.sha256(new_refresh.encode()).hexdigest(),
            )
            session.add(new_session)

        return TokenResponse(
            access_token=new_access,
            refresh_token=new_refresh,
            expires_in=self.settings.access_token_expire_minutes * 60,
        ).model_dump()

    async def logout(self, access_token: str) -> None:
        token_hash = hashlib.sha256(access_token.encode()).hexdigest()
        async with self.db.get_session(_DB_KEY) as session:
            await session.execute(
                sa_delete(UserSession).where(
                    UserSession.access_token_hash == token_hash
                )
            )

    # ── Email verification ──

    async def create_verification_token(self, user_id: str) -> dict:
        """Create a verification token for the user's email."""
        async with self.db.get_session(_DB_KEY) as session:
            result = await session.execute(
                select(User).where(User.id == user_id, User.is_active == True)
            )
            user = result.scalar_one_or_none()
            if user is None:
                raise NotFoundError("User not found")
            if user.is_verified:
                raise ValidationError("Email already verified")

            # Invalidate existing unused tokens
            existing = await session.execute(
                select(EmailVerificationToken).where(
                    EmailVerificationToken.user_id == user_id,
                    EmailVerificationToken.used == False,
                )
            )
            for tok in existing.scalars().all():
                tok.used = True

            raw_token = os.urandom(32).hex()
            token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
            expires_at = datetime.now(timezone.utc) + timedelta(hours=24)

            record = EmailVerificationToken(
                user_id=user_id,
                token_hash=token_hash,
                expires_at=expires_at,
            )
            session.add(record)

        return {
            "user_id": user_id,
            "email": user.email,
            "token": raw_token,
            "expires_at": expires_at.isoformat(),
        }

    async def verify_email(self, token: str) -> dict:
        """Verify a user's email using the verification token."""
        token_hash = hashlib.sha256(token.encode()).hexdigest()

        async with self.db.get_session(_DB_KEY) as session:
            result = await session.execute(
                select(EmailVerificationToken).where(
                    EmailVerificationToken.token_hash == token_hash,
                    EmailVerificationToken.used == False,
                )
            )
            record = result.scalar_one_or_none()
            if record is None:
                raise ValidationError("Invalid or expired verification token")

            if record.expires_at.replace(tzinfo=timezone.utc) < datetime.now(timezone.utc):
                record.used = True
                raise ValidationError("Verification token has expired")

            # Mark token as used
            record.used = True

            # Set user as verified
            user_result = await session.execute(
                select(User).where(User.id == record.user_id)
            )
            user = user_result.scalar_one_or_none()
            if user is None:
                raise NotFoundError("User not found")

            user.is_verified = True

        return {
            "user_id": user.id,
            "email": user.email,
            "verified": True,
        }
