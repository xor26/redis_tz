from app.domain.models import User, Role


class InMemoryUserRepo:

    def __init__(self):
        self.users = {
            "admin": User(
                id=1,
                username="admin",
                password_hash="x",  # todo заменить на нолрмальный hash
                roles={Role.USER, Role.ADMIN}
            ),
            "user": User(
                id=2,
                username="user",
                password_hash="z",
                roles={Role.USER}
            ),
        }

    async def get_by_credentials(self, username, password):
        u = self.users.get(username)
        if not u or u.password_hash != self.hash_password(password):
            return None

        return u

    async def get_by_id(self, user_id):
        for u in self.users.values():
            if u.id == int(user_id):
                return u

        return None

    def hash_password(self, password):
        if password == "admin":
            return "x"
        return "z"
