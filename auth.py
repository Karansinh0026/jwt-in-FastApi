from datetime import timedelta,datetime
from typing import Annotated
from fastapi import HTTPException,Depends,APIRouter
from pydantic import BaseModel
from sqlalchemy.orm import Session
from starlette import status
from datebase import localSession
from db_models import User
from passlib.context import CryptContext
from fastapi.security import OAuth2PasswordRequestForm,OAuth2PasswordBearer
from jose import JWTError,jwt


router = APIRouter(
    prefix="/auth",
    tags=['auth']
)

secret_key="3V6y6BvSgYl85oHrzr7EOZPHHL6XmRmrGIlMB0O5OVy"
algorithm="HS256"
access_token_expire_minutes = 30
refresh_token_expire_days = 7

pwd_context = CryptContext(schemes=["bcrypt"],deprecated="auto")

def hash_password(passowrd :str):
    return pwd_context.hash(passowrd)

def verify_password(password:str,hashed_password:str):
    return pwd_context.verify(password,hashed_password)

def create_access_token(data : dict,expires_delta : timedelta = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta if expires_delta else timedelta(minutes=access_token_expire_minutes))
    to_encode.update({'exp':expire})
    encoded_jwt = jwt.encode(to_encode,secret_key,algorithm=algorithm)
    return encoded_jwt

def create_refresh_token(data : dict,expires_delta : timedelta = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta if expires_delta else timedelta(days=refresh_token_expire_minutes))
    to_encode.update({'exp':expire})
    encoded_jwt = jwt.encode(to_encode,secret_key,algorithm=algorithm)
    return encoded_jwt

def decode_jwt_token(token:str):
    
    try:
        payload = jwt.decode(token,secret_key,algorithms=algorithm)
        return payload
    except JWTError:
        return None