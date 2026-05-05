from abc import ABC, abstractmethod
from app.domain.models import Token, User


class UserRepository(ABC):
    @abstractmethod
    async def get_by_credentials(self, username: str, password: str) -> User | None: ...

    @abstractmethod
    async def get_by_id(self, user_id: int) -> User | None: ...


class TokenRepository(ABC):
    @abstractmethod
    async def get(self, jti: str) -> Token | None: ...

    @abstractmethod
    async def save(self, token: Token) -> None: ...

    @abstractmethod
    async def blacklist(self, jti: str, ttl: int) -> None: ...

    @abstractmethod
    async def revoke_all_for_user(self, user_id: int) -> None: ...
