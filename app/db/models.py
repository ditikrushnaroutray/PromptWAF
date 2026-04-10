from sqlalchemy import Column, Integer, String, Boolean
from app.db.session import Base, engine

class ApiKey(Base):
    __tablename__ = "api_keys"

    id = Column(Integer, primary_key=True, index=True)
    key_hash = Column(String, unique=True, index=True, nullable=False)
    owner_email = Column(String, index=True, nullable=False)
    is_active = Column(Boolean, default=True)

def init_db():
    Base.metadata.create_all(bind=engine)
    