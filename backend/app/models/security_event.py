from datetime import datetime

from sqlalchemy import Column, Integer, String, DateTime, Text

from app.database import Base


class SecurityEvent(Base):
    __tablename__ = "security_events"

    id = Column(Integer, primary_key=True, index=True)

    timestamp = Column(DateTime, nullable=False)

    source_ip = Column(String(45), nullable=True)

    username = Column(String(100), nullable=True)

    message = Column(Text, nullable=False)

    source = Column(String(100), nullable=False)

    event_type = Column(String(100), nullable=False)

    severity = Column(String(50), nullable=False)

    description = Column(Text, nullable=True)

    created_at = Column(
        DateTime,
        default=datetime.utcnow,
        nullable=False,
    )