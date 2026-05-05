# RedisTZ

## Описание

Это реализация тестового задания из `Description.pdf`, который реализует аутентификацию и авторизацию на `JWT` с использованием `Redis` для хранения и контроля токенов.:
- login/refresh/logout на JWT;
- white/black list токенов через Redis;
- защита от повторного использования refresh-токена (replay detection);
- ролевая модель (`user` и `admin`) с доступом к общему и admin-only контенту;
- упаковка решения в контейнер (`Dockerfile`, `docker-compose.yml`).

## Стек

- Python 3.12
- FastAPI + Uvicorn
- Redis 7
- PyJWT
- Docker / Docker Compose

## Запуск
```bash
docker compose up --build
```

## Использование API

### Демо-пользователи

- `admin / admin` — роль `admin`
- `user / user` — роль `user`

### Основные эндпоинты

- `POST /auth/login` — получить `access_token` и `refresh_token`
- `POST /auth/refresh` — обновить пару токенов
- `POST /auth/logout` — отозвать токен (добавление в blacklist)
- `GET /content/all` — контент для авторизованного пользователя
- `GET /content/admin` — контент только для роли `admin`

## Postman: импорт коллекции `RedisTZ.postman_collection.json`

1. Откройте Postman.
2. Нажмите **Import**.
3. Перетащите файл `RedisTZ.postman_collection.json` из корня проекта или выберите его через **Upload Files**.
4. Нажмите **Import** для завершения.
5. Запустите запрос `login_admin` или `login_not_admin` — тест-скрипт в коллекции автоматически сохранит `access_token` и `refresh_token` в переменные окружения Postman.
6. После этого запускайте `content` / `content_admin` с заголовком:
   - `Authorization: Bearer {{access_token}}`

Если API запущен на другом хосте/порту, обновите URL запросов в коллекции (по умолчанию там `http://0.0.0.0:8000`).
