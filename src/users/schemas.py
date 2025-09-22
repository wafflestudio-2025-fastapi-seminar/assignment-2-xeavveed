import re

from pydantic import BaseModel, field_validator, EmailStr
from fastapi import HTTPException

from users.errors import InvalidPasswordException, InvalidPhonenumberException, BioTooLongException

class CreateUserRequest(BaseModel):
    email: EmailStr
    password: str
    name: str
    phone_number: str
    height: float
    bio: str | None = None

    @field_validator('password', mode='after')
    def validate_password(cls, v):
        if len(v) < 8 or len(v) > 20:
            raise InvalidPasswordException()
        return v
    
    @field_validator('phone_number', mode='after')
    def validate_phone_number(cls, v):
        pattern = re.compile(r'^010-\d{4}-\d{4}$')
        if not pattern.fullmatch(v):
            raise InvalidPhonenumberException()
        return v

    @field_validator('bio', mode='after')
    def validate_bio(cls, v):
        if v is not None and len(v) > 500:
            raise BioTooLongException()
        return v

class UserResponse(BaseModel):
    user_id: int
    email: EmailStr
    name: str
    phone_number: str
    height: float
    bio: str | None = None