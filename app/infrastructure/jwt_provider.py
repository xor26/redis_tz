import jwt

from app.domain.models import Token


class JWTProvider:

    def __init__(self, secret: str, algorithm: str = "HS256"):
        self.secret = secret
        self.algorithm = algorithm

    def encode(self, token: Token) -> str:
        payload = {
            "sub": str(token.user_id),
            "jti": token.jti,
            "type": token.token_type.value,
            "exp": int(token.expires_at.timestamp()),
        }
        return jwt.encode(payload, self.secret, algorithm=self.algorithm)

    def decode(self, raw: str) -> dict:
        return jwt.decode(
            raw,
            self.secret,
            algorithms=[self.algorithm],
        )