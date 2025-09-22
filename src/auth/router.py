from fastapi import APIRouter, Depends, Cookie, Header, Response
from pydantic import BaseModel, EmailStr

from src.common.database import blocked_token_db, session_db, user_db
from passlib.hash import bcrypt

from jose import jwt, JWTError, ExpiredSignatureError
from datetime import datetime, timedelta
import os, time

from src.users.errors import InvalidAccountException, BadAuthorizationHeaderException, UnauthenticatedException, InvalidTokenException

auth_router = APIRouter(prefix="/auth", tags=["auth"])

SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-key")
ALGORITHM = "HS256"
SHORT_SESSION_LIFESPAN = 15
LONG_SESSION_LIFESPAN = 24 * 60

class Login_request(BaseModel):
    email: EmailStr
    password: str
    
def create_access_token(user_id: int):
    expire = datetime.utcnow() + timedelta(minutes=SHORT_SESSION_LIFESPAN)
    to_encode = {"sub": str(user_id), "exp": expire}
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def create_refresh_token(user_id: int):
    expire = datetime.utcnow() + timedelta(minutes=LONG_SESSION_LIFESPAN)
    to_encode = {"sub": str(user_id), "exp": expire}
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def decode_jwt(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except ExpiredSignatureError:
        raise InvalidTokenException()

@auth_router.post("/token")
def create_token(request: Login_request)-> dict:
    email = request.email
    password = request.password
    for user in user_db:
        if user["email"] == email:
            if bcrypt.verify(password, user["hashed_password"]):
                token = create_access_token(user["user_id"])
                refresh_token = create_refresh_token(user["user_id"])
                return {
                    "access_token": token,
                    "refresh_token": refresh_token
                }
    raise InvalidAccountException()

@auth_router.post("/token/refresh")
def refresh_token(authorization: str = Header(None))-> dict:
    if not authorization:
        raise UnauthenticatedException()
    if not authorization.startswith("Bearer "):
        raise BadAuthorizationHeaderException()
    token = authorization.split(" ")[1]
    if token in blocked_token_db:
        raise InvalidTokenException()
    
    payload = decode_jwt(token)
    user_id = payload.get("sub")
    exp = payload.get("exp")
    blocked_token_db[token] = exp
    
    new_token = create_access_token(user_id)
    new_refresh_token = create_refresh_token(user_id)
    
    return {
        "access_token": new_token,
        "refresh_token": new_refresh_token
    }

@auth_router.delete("/token")
def delete_token(authorization: str = Header(None)):
    if not authorization:
        raise UnauthenticatedException()
    if not authorization.startswith("Bearer "):
        raise BadAuthorizationHeaderException()
    token = authorization.split(" ")[1]
    if token in blocked_token_db:
        raise InvalidTokenException()
    
    payload = decode_jwt(token)
    user_id = int(payload.get("sub"))
    exp = payload.get("exp")
    blocked_token_db[token] = exp
    
    return {
        Response(status_code = 204)
    }

@auth_router.post("/session")
def create_session(request: Login_request, response: Response):
    email = request.email
    password = request.password
    for user in user_db:
        if user["email"] == email:
            if bcrypt.verify(password, user["hashed_password"]):
                session_id = os.urandom(16).hex()
                session_db[session_id] = {
                    "user_id": user["user_id"],
                    "expired at": time.time() + LONG_SESSION_LIFESPAN * 60
                }
                response.set_cookie(
                    key="sid",
                    value=sid,
                    httponly=True,
                    max_age=LONG_SESSION_LIFESPAN * 60,
                )
                return {
                    Response(status_code = 200)
                }
    raise InvalidAccountException()

@auth_router.delete("/session")
def delete_session(sid: str = Cookie(None), response: Response = None):
    if sid:
        response.delete_cookie(key="sid")
        if sid in session_db:
            del session_db[sid]
    return {
        Response(status_code = 204)
    }