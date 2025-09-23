from typing import Annotated

from fastapi import (
    APIRouter,
    Depends,
    Cookie,
    Header,
    status
)

from src.users.schemas import CreateUserRequest, UserResponse
from src.auth.router import decode_jwt
from src.common.database import blocked_token_db, session_db, user_db
from src.users.errors import EmailAlreadyExistsException, InvalidSessionException, BadAuthorizationHeaderException, UnauthenticatedException
from passlib.hash import bcrypt

import time

user_router = APIRouter(prefix="/users", tags=["users"])

user_cnt = 0
@user_router.post("/", status_code=status.HTTP_201_CREATED)
def create_user(request: CreateUserRequest) -> UserResponse:
    global user_cnt
    user_cnt += 1
    for user in user_db:
        if user["email"] == request.email:
            raise EmailAlreadyExistsException()
        
    user_db.append({
        "user_id": user_cnt,
        "email": request.email,
        "hashed_password": bcrypt.hash(request.password),
        "name": request.name,
        "phone_number": request.phone_number,
        "height": request.height,
        "bio": request.bio
    })
    return UserResponse(
        user_id = user_cnt,
        email = request.email,
        name = request.name,
        phone_number = request.phone_number,
        height = request.height,
        bio = request.bio
    )

@user_router.get("/me")
def get_user_info(sid: str  = Cookie(None), 
    authorization: str = Header(None)
) -> UserResponse:
    
    user_id = None
    if sid:
        session = session_db.get(sid)
        if session is None or session["expires_at"] < time.time():
            raise InvalidSessionException()
        user_id = session["user_id"]
    elif authorization:
        if not authorization.startswith("Bearer "):
            raise BadAuthorizationHeaderException()
        token = authorization.split(" ")[1]
        payload = decode_jwt(token)
        user_id = int(payload.get("sub"))
    if user_id is None:
        raise UnauthenticatedException()
    
    for user in user_db:
        if user["user_id"] == user_id:
            return UserResponse(user_id = user["user_id"], email = user["email"], name = user["name"],
                                phone_number = user["phone_number"], height = user["height"], bio = user["bio"])
            
    raise UnauthenticatedException()
        