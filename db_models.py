from sqlalchemy import String,Integer,Column,DateTime,Boolean,ForeignKey
from sqlalchemy.orm import declarative_base,relationship
from datetime import datetime,timedelta
Base = declarative_base()

class User(Base):

    __tablename__='users'

    id=Column(Integer,primary_key=True)
    username=Column(String,nullable=False,unique=True)
    hashed_password=Column(String,nullable=False)

class RefreshToken(Base):
    __tablename__ = "refresh_tokens"

    id = Column(Integer, primary_key=True)
    token = Column(String, nullable=False, unique=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)

    expires_at = Column(DateTime, nullable=False)
    is_revoked = Column(Boolean, default=False)

    created_at = Column(DateTime, default=datetime.utcnow)

    user=relationship("User")