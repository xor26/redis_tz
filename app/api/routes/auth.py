from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from app.api.deps import auth_service, get_current_user
from app.application.auth_service import (
    InvalidCredentials,
    InvalidToken,
    ReplayAttackDetected,
)

router = APIRouter()


class LoginRequest(BaseModel):
    username: str
    password: str


class RefreshRequest(BaseModel):
    refresh_token: str


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str


@router.post("/login", response_model=TokenResponse)
async def login(data: LoginRequest):
    try:
        return await auth_service.login(data.username, data.password)
    except InvalidCredentials:
        raise HTTPException(status_code=401, detail="Invalid credentials")


@router.post("/refresh", response_model=TokenResponse)
async def refresh(data: RefreshRequest):
    try:
        return await auth_service.refresh(data.refresh_token)
    except ReplayAttackDetected:
        raise HTTPException(status_code=401, detail="Token reuse detected")
    except InvalidToken:
        raise HTTPException(status_code=401, detail="Invalid token")


@router.post("/logout")
async def logout(token: str):
    try:
        await auth_service.logout(token)
        return {"status": "ok"}
    except InvalidToken:
        raise HTTPException(status_code=401, detail="Invalid token")
