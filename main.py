from pydantic import BaseModel
from fastapi import FastAPI,Depends,HTTPException,Response,Request
from typing import Annotated
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from datebase import localSession
import db_models
from datetime import datetime,timedelta
from jose import JWTError
from datebase import engine
from auth import create_refresh_token, hash_password,verify_password,decode_jwt_token,create_access_token,access_token_expire_minutes,refresh_token_expire_days

app=FastAPI()

db_models.Base.metadata.create_all(bind = engine)

def get_db():
    db= localSession()
    try:
        yield db
    finally:
        db.close()

dp_dependency = Annotated[Session,Depends(get_db)]


class User(BaseModel):
    username : str
    password : str

@app.post("/signup")
def signup(user : User, db : dp_dependency):
    exist = db.query(db_models.User).filter(db_models.User.username == user.username).first()
    if exist:
        raise HTTPException(status_code=400,detail={"User already exists"})
    hash_pass = hash_password(user.password)
    new__user = db_models.User(username=user.username,hashed_password=hash_pass)
    db.add(new__user)
    db.commit()
    return {"msg":"User created successfully"}

@app.post("/login")
def login(user: User,db:dp_dependency,response:Response):
    exist= db.query(db_models.User).filter(db_models.User.username == user.username).first()
    if(not exist or not verify_password(user.password,exist.hashed_password)):
        raise HTTPException(status_code=401, detail="Invalid Credentials")
    access_token = create_access_token(data = {"_id":exist.id})
    expires_at = datetime.utcnow() + timedelta(days=refresh_token_expire_days)
    refresh_token = create_refresh_token(data = {"_id":exist.id})

    db_token = db_models.RefreshToken(
        token=refresh_token,
        user_id=exist.id,
        expires_at=expires_at
    )

    db.add(db_token)
    db.commit()

    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,
        secure=True,
        samesite="Lax",
        max_age=access_token_expire_minutes * 60
    )
    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        httponly=True,
        secure=True,
        samesite="Lax",
        max_age=7 * 24 * 60 * 60
    )

    return {"message":"login Successfull"}

def current_user(request:Request,db : dp_dependency):
    token = request.cookies.get("access_token")
    if not token:
        raise HTTPException(status_code=401,detail="Token is invalid or Expired")
    try:
        payload = decode_jwt_token(token)
        user = db.query(db_models.User).filter(db_models.User.id == payload.get("_id")).first()
    except JWTError:
        raise HTTPException(status_code=401,detail="Invalid token")
    return user
@app.get("/profile")
def profile(user = Depends(current_user)):
    return f"{user.username}"


@app.get("/logout")
def logout(response : Response, db : dp_dependency):
    refresh_token = response.cookies.get("refresh_token")
    if refresh_token:
        token = db.query(db_models.RefreshToken)\
                  .filter(db_models.RefreshToken.token == refresh_token)\
                  .first()
        if token:
            token.is_revoked = True
            db.commit()

    response.delete_cookie("access_token")
    response.delete_cookie("refresh_token")

    return {"msg": "Logged out successfully"}


@app.post("/refresh")
def refresh_token(response : Response,request : Request,db : dp_dependency):
    token = request.cookies.get("refresh_token")
    if not token:
        raise HTTPException(status_code=401,detail="Token is invalid or Expired")
    
    payload = decode_jwt_token(token)
    token_in_db = db.query(db_models.RefreshToken)\
                .filter(
                    db_models.RefreshToken.token == refresh_token,
                    db_models.RefreshToken.is_revoked == False
                ).first()
    if not token_in_db:
        raise HTTPException(status_code=401, detail="Token revoked or invalid")
        
    if token_in_db.expires_at < datetime.utcnow():
        raise HTTPException(status_code=401, detail="Refresh token expired")
    
    new_access_token = create_access_token({"sub": payload["sub"]})

    return {"access_token": new_access_token}

def cleanup_expired_tokens(db: Session):
    db.query(db_models.RefreshToken)\
      .filter(db_models.RefreshToken.expires_at < datetime.utcnow())\
      .delete()
    db.commit()