from datetime import datetime, UTC
from app.domain.services import TokenService, ReplayAttackDetected
from app.domain.token_factory import TokenFactory


class AuthError(Exception):
    pass


class InvalidCredentials(AuthError):
    pass


class InvalidToken(AuthError):
    pass


class AuthService:

    def __init__(
            self,
            user_repo,
            token_repo,
            jwt_provider,
            token_factory: TokenFactory,
            token_service: TokenService,
    ):
        self.user_repo = user_repo
        self.token_repo = token_repo
        self.jwt = jwt_provider
        self.factory = token_factory
        self.tokens = token_service

    async def login(self, username: str, password: str, *, ip=None, user_agent=None):
        user = await self.user_repo.get_by_credentials(username, password)
        if not user:
            raise InvalidCredentials()

        access, refresh = self.factory.issue_pair(
            user.id, ip=ip, user_agent=user_agent
        )
        await self.token_repo.save(refresh)

        return {
            "access_token": self.jwt.encode(access),
            "refresh_token": self.jwt.encode(refresh),
        }

    async def refresh(self, raw_refresh: str):
        try:
            payload = self.jwt.decode(raw_refresh)
        except Exception:
            raise InvalidToken("Invalid JWT")

        jti = payload.get("jti")
        if not jti:
            raise InvalidToken("Missing jti")

        # достаём токен из хранилища
        token = await self.token_repo.get(jti)
        if not token:
            raise InvalidToken("Unknown token")

        # валидация
        try:
            self.tokens.validate_refresh(token)
        except ReplayAttackDetected:
            # компрометация
            await self.token_repo.revoke_all_for_user(token.user_id)
            raise
        except Exception as e:
            raise InvalidToken(str(e))

        # новая пара
        new_access, new_refresh = self.factory.issue_pair(
            token.user_id,
            ip=token.ip,
            user_agent=token.user_agent,
        )

        # ротация
        self.tokens.rotate(token, new_refresh)

        #сохраняем
        await self.token_repo.save(token)
        await self.token_repo.save(new_refresh)

        #blacklist старого
        ttl = int((token.expires_at - datetime.now(UTC)).total_seconds())
        if ttl > 0:
            await self.token_repo.blacklist(token.jti, ttl)

        return {
            "access_token": self.jwt.encode(new_access),
            "refresh_token": self.jwt.encode(new_refresh),
        }

    async def logout(self, raw_token: str):
        try:
            payload = self.jwt.decode(raw_token)
        except Exception:
            raise InvalidToken()

        jti = payload.get("jti")
        exp = payload.get("exp")
        if not jti or not exp:
            raise InvalidToken()

        ttl = exp - int(datetime.now(UTC).timestamp())
        if ttl > 0:
            await self.token_repo.blacklist(jti, ttl)

    async def validate_access(self, raw_access: str) -> dict:
        try:
            payload = self.jwt.decode(raw_access)
        except Exception:
            raise InvalidToken()

        jti = payload.get("jti")
        if not jti:
            raise InvalidToken()

        if await self.token_repo.is_blacklisted(jti):
            raise InvalidToken("Token revoked")

        return payload
