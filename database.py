from sqlalchemy import create_engine, Column, Integer, String, UniqueConstraint
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

DATABASE_URL = "sqlite:///./remediated.db"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
Base = declarative_base()
SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)

class RemediatedVuln(Base):
    __tablename__ = "remediated"
    id = Column(Integer, primary_key=True, index=True)
    team = Column(String, index=True)
    cve_id = Column(String, index=True)
    __table_args__ = (UniqueConstraint('team', 'cve_id', name='_team_cve_uc'),)

def init_db():
    Base.metadata.create_all(bind=engine)