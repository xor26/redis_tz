from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum


class Role(StrEnum):
    USER = "user"
    ADMIN = "admin"


class TokenType(StrEnum):
    ACCESS = "access"
    REFRESH = "refresh"


@dataclass(slots=True)
class User:
    id: int | None
    username: str
    password_hash: str
    roles: set[Role] = field(default_factory=lambda: {Role.USER})

    def has_role(self, role: Role) -> bool:
        return role in self.roles

    def grant_role(self, role: Role) -> None:
        self.roles.add(role)

    def revoke_role(self, role: Role) -> None:
        self.roles.discard(role)

    def ensure_has_role(self, role: Role) -> None:
        if not self.has_role(role):
            raise ValueError(f"Missing role: {role}")


@dataclass(slots=True)
class Token:
    jti: str
    user_id: int
    token_type: TokenType
    expires_at: datetime
    created_at: datetime = field(default_factory=lambda: datetime.now(tz=UTC))
    revoked_at: datetime | None = None
    replaced_by_jti: str | None = None
    user_agent: str | None = None
    ip: str | None = None

    @property
    def is_revoked(self) -> bool:
        return self.revoked_at is not None

    @property
    def is_expired(self) -> bool:
        return datetime.now(tz=UTC) >= self.expires_at

    @property
    def is_active(self) -> bool:
        return self.revoked_at is None and datetime.now(tz=UTC) < self.expires_at

    def revoke(self, replaced_by_jti: str | None = None) -> None:
        if self.is_revoked:
            raise ValueError("Token already revoked")

        self.revoked_at = datetime.now(tz=UTC)
        self.replaced_by_jti = replaced_by_jti

    def ensure_active(self) -> None:
        if self.is_revoked:
            raise ValueError("Token revoked")

        if self.is_expired:
            raise ValueError("Token expired")

    def ensure_refresh(self) -> None:
        if self.token_type != TokenType.REFRESH:
            raise ValueError("Not a refresh token")

    def ensure_not_replaced(self) -> None:
        if self.replaced_by_jti is not None:
            raise ValueError("Token already rotated (possible replay)")