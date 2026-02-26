from datetime import datetime, timezone
from sqlalchemy import BigInteger, create_engine, Column, Integer, String, DateTime, ForeignKey
from sqlalchemy.orm import declarative_base, relationship, sessionmaker
import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Database connection configuration
# Note: Using psycopg2-binary to connect to PostgreSQL
DATABASE_URL = os.getenv("DATABASE_URL")

# Critical: Ensure DATABASE_URL is set before proceeding
if not DATABASE_URL:
    raise ValueError("No DATABASE_URL found in environment variables. Check your .env file.")

# Create the database engine and session manager
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Base class for all SQLAlchemy models
Base = declarative_base()

# ---------------------------------------------------------
# Database Models (Tables)
# ---------------------------------------------------------

class Agent(Base):
    """Stores metadata about monitored machines/endpoints."""
    __tablename__ = "agents"

    id = Column(Integer, primary_key=True, index=True)
    ip_address = Column(String, unique=True, index=True, nullable=False)
    name = Column(String, nullable=True) 
    mac_address = Column(String, nullable=True)

    # Establish one-to-many relationships
    traffic_logs = relationship("TrafficLog", back_populates="agent")
    alerts = relationship("BlacklistAlert", back_populates="agent")


class TrafficLog(Base):
    """Main storage for captured network packets. Heavily indexed for performance."""
    __tablename__ = "traffic_logs"

    id = Column(Integer, primary_key=True, index=True)
    
    # Foreign key linking back to the originating agent
    agent_id = Column(Integer, ForeignKey("agents.id"), index=True) 
    
    # CRITICAL: Descending index on timestamp to speed up dashboard timeframe filtering
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    direction = Column(String)
    
    # Indexed fields to optimize 'Top 10' aggregations (IPs, Countries, Softwares)
    destination_ip = Column(String, index=True) 
    port = Column(Integer)
    
    # BigInteger is used to prevent overflow on high-volume data transfers
    size_bytes = Column(BigInteger)
    
    country = Column(String, index=True) 
    software_name = Column(String, index=True) 

    # Link to parent Agent object
    agent = relationship("Agent", back_populates="traffic_logs")


class BlacklistAlert(Base):
    """Security-focused table to record specific policy violations."""
    __tablename__ = "blacklist_alerts"

    id = Column(Integer, primary_key=True, index=True)
    agent_id = Column(Integer, ForeignKey("agents.id"), nullable=False)
    
    destination_ip = Column(String, nullable=False)
    timestamp = Column(DateTime, default=datetime.now)

    # Link back to the compromised/monitoring agent
    agent = relationship("Agent", back_populates="alerts")

# ---------------------------------------------------------
# Schema Initialization
# ---------------------------------------------------------

if __name__ == "__main__":
    try:
        print("Starting the database connection...")
        
        # Mask credentials for safer console logging
        safe_url = DATABASE_URL.replace("root", "****")
        print(f"Connecting to: {safe_url}")
        
        # Trigger schema creation (DDL)
        Base.metadata.create_all(bind=engine)
        print("SUCCESS: Tables were created (or verified) successfully!")
        
        # Inspect existing schema to verify tables exist in PostgreSQL
        from sqlalchemy import inspect
        inspector = inspect(engine)
        tables = inspector.get_table_names()
        print(f"Tables currently in the database: {tables}")
        
    except Exception as e:
        print(f"ERROR: Something went wrong during DB init:\n{e}")