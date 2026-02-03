from sqlalchemy.orm import declarative_base,sessionmaker
from sqlalchemy import create_engine

DB_url = "postgresql://postgres:Karan%40123@localhost:5432/jwt"

engine=create_engine(DB_url)

try:
    localSession = sessionmaker(bind=engine,autocommit=False)
except:
    print("COnnection error")
