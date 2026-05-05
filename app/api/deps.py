import os
from fastapi import Depends, HTTPException
from fastapi.security import HTTPBearer
from redis.asyncio import Redis

from app.domain.models import Role
from app.infrastructure.redis_repo import RedisTokenRepository
from app.infrastructure.jwt_provider import JWTProvider
from app.infrastructure.user_repo import InMemoryUserRepo

from app.domain.token_factory import TokenFactory
from app.domain.services import TokenService
from app.application.auth_service import AuthService, InvalidToken

redis = Redis(
    host=os.getenv("REDIS_HOST", "localhost"),
    port=int(os.getenv("REDIS_PORT", 6379)),
    decode_responses=True,
)
token_repo = RedisTokenRepository(redis)
user_repo = InMemoryUserRepo()

jwt_provider = JWTProvider(secret="secret")

factory = TokenFactory(access_ttl_min=15, refresh_ttl_days=7)
token_service = TokenService()

auth_service = AuthService(
    user_repo=user_repo,
    token_repo=token_repo,
    jwt_provider=jwt_provider,
    token_factory=factory,
    token_service=token_service,
)

security = HTTPBearer()


async def get_current_user(token=Depends(security)):
    try:
        payload = await auth_service.validate_access(token.credentials)
        return payload["sub"]
    except InvalidToken:
        raise HTTPException(status_code=401, detail="Unauthorized")

async def require_admin(user_id=Depends(get_current_user)):
    user = await user_repo.get_by_id(user_id)
    if not user:
        raise HTTPException(status_code=401, detail="User not found")

    if not user.has_role(Role.ADMIN):
        raise HTTPException(status_code=403, detail="Forbidden")

    return user_id