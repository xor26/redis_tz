from fastapi import FastAPI
from app.api.routes.auth import router as auth_router
from app.api.routes.content import router as content_router

app = FastAPI()

app.include_router(auth_router, prefix="/auth")
app.include_router(content_router, prefix="/content")