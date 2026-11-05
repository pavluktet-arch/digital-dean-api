from pathlib import Path
from fastapi import APIRouter, Depends, HTTPException, status, Response, Path as APIPath

try:
    from app.db.connection import DEFAULT_DB_PATH
except ImportError:
    DEFAULT_DB_PATH = Path("var/digital-dean.sqlite3")

from app.schemas.user_account import UserCreate, UserPublic, LoginRequest
from app.repositories.user_repository import UserRepository, UserConflict, UserReferenced
from app.api.account_validation import SensitiveRoute

router = APIRouter(prefix="/api/v1", tags=["accounts"], route_class=SensitiveRoute)

def get_user_repository() -> UserRepository:
    return UserRepository(str(DEFAULT_DB_PATH))

@router.post("/users", response_model=UserPublic, status_code=status.HTTP_201_CREATED)
def register_user(
    user_data: UserCreate,
    repo: UserRepository = Depends(get_user_repository)
):
    try:
        return repo.register_user(user_data)
    except UserConflict as e:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(e))
    except Exception as e:
        if isinstance(e, HTTPException):
            raise
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="database unavailable")

@router.delete("/users/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_user(
    user_id: int = APIPath(..., ge=1, le=9223372036854775807),
    repo: UserRepository = Depends(get_user_repository)
):
    try:
        deleted = repo.delete_user(user_id)
        if not deleted:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="user not found")
        return Response(status_code=status.HTTP_204_NO_CONTENT)
    except UserReferenced as e:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(e))
    except Exception as e:
        if isinstance(e, HTTPException):
            raise
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="database unavailable")

@router.patch("/users/{user_id}/block", response_model=UserPublic)
def block_user(
    user_id: int = APIPath(..., ge=1, le=9223372036854775807),
    repo: UserRepository = Depends(get_user_repository)
):
    try:
        user = repo.block_user(user_id)
        if not user:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="user not found")
        return user
    except Exception as e:
        if isinstance(e, HTTPException):
            raise
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="database unavailable")

@router.post("/auth/login", response_model=bool)
def login(
    credentials: LoginRequest,
    repo: UserRepository = Depends(get_user_repository)
):
    try:
        return repo.authenticate_user(credentials.login, credentials.password)
    except Exception as e:
        if isinstance(e, HTTPException):
            raise
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="database unavailable")