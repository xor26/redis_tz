from fastapi import APIRouter, Depends
from app.api.deps import get_current_user, require_admin

router = APIRouter()


@router.get("/all")
async def content(user_id=Depends(get_current_user)):
    return {"content": "some_content_for_everyone"}


@router.get("/admin")
async def admin_content(user_id=Depends(require_admin)):
    return {"content": "secret_admin_content"}