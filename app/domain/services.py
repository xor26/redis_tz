from app.domain.models import Token


class ReplayAttackDetected(Exception):
    pass


class TokenService:

    def validate_refresh(self, token: Token) -> None:
        token.ensure_refresh()
        token.ensure_active()

        if token.replaced_by_jti is not None:
            raise ReplayAttackDetected("Refresh token reuse detected")

    def rotate(self, token: Token, new_refresh: Token) -> None:
        self.validate_refresh(token)

        token.revoke(replaced_by_jti=new_refresh.jti)