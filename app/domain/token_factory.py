import uuid
from datetime import datetime, timedelta, UTC

from app.domain.models import Token, TokenType


class TokenFactory:

    def __init__(self, access_ttl_min: int, refresh_ttl_days: int):
        self.access_ttl = timedelta(minutes=access_ttl_min)
        self.refresh_ttl = timedelta(days=refresh_ttl_days)

    def issue_pair(self, user_id: int, *, ip=None, user_agent=None):
        now = datetime.now(tz=UTC)

        access = Token(
            jti=str(uuid.uuid4()),
            user_id=user_id,
            token_type=TokenType.ACCESS,
            expires_at=now + self.access_ttl,
            ip=ip,
            user_agent=user_agent,
        )

        refresh = Token(
            jti=str(uuid.uuid4()),
            user_id=user_id,
            token_type=TokenType.REFRESH,
            expires_at=now + self.refresh_ttl,
            ip=ip,
            user_agent=user_agent,
        )

        return access, refresh