from datetime import datetime, UTC
import json

from app.domain.models import Token, TokenType


class RedisTokenRepository:

    def __init__(self, redis):
        self.redis = redis

    def _token_key(self, jti: str) -> str:
        return f"token:{jti}"

    def _blacklist_key(self, jti: str) -> str:
        return f"blacklist:{jti}"

    def _user_tokens_key(self, user_id: int) -> str:
        return f"user_tokens:{user_id}"

    def _serialize(self, token: Token) -> str:
        return json.dumps({
            "jti": token.jti,
            "user_id": token.user_id,
            "token_type": token.token_type.value,
            "expires_at": token.expires_at.isoformat(),
            "created_at": token.created_at.isoformat(),
            "revoked_at": token.revoked_at.isoformat() if token.revoked_at else None,
            "replaced_by_jti": token.replaced_by_jti,
            "ip": token.ip,
            "user_agent": token.user_agent,
        })

    def _deserialize(self, raw: str) -> Token:
        data = json.loads(raw)
        return Token(
            jti=data["jti"],
            user_id=data["user_id"],
            token_type=TokenType(data["token_type"]),
            expires_at=datetime.fromisoformat(data["expires_at"]),
            created_at=datetime.fromisoformat(data["created_at"]),
            revoked_at=datetime.fromisoformat(data["revoked_at"]) if data["revoked_at"] else None,
            replaced_by_jti=data["replaced_by_jti"],
            ip=data["ip"],
            user_agent=data["user_agent"],
        )


    async def get(self, jti: str) -> Token | None:
        raw = await self.redis.get(self._token_key(jti))
        if not raw:
            return None
        return self._deserialize(raw)

    async def save(self, token: Token) -> None:
        key = self._token_key(token.jti)

        ttl = int((token.expires_at - datetime.now(UTC)).total_seconds())
        if ttl <= 0:
            return

        await self.redis.set(key, self._serialize(token), ex=ttl)

        await self.redis.sadd(self._user_tokens_key(token.user_id), token.jti)

    async def blacklist(self, jti: str, ttl: int) -> None:
        if ttl <= 0:
            return
        await self.redis.set(self._blacklist_key(jti), "1", ex=ttl)

    async def is_blacklisted(self, jti: str) -> bool:
        return await self.redis.exists(self._blacklist_key(jti)) == 1

    async def revoke_all_for_user(self, user_id: int) -> None:
        key = self._user_tokens_key(user_id)
        jti_list = await self.redis.smembers(key)

        now = datetime.now(UTC)

        for jti in jti_list:
            jti = jti.decode() if isinstance(jti, bytes) else jti
            token = await self.get(jti)
            if not token:
                continue

            if not token.is_revoked:
                token.revoked_at = now
                await self.save(token)

            ttl = int((token.expires_at - now).total_seconds())
            if ttl > 0:
                await self.blacklist(token.jti, ttl)