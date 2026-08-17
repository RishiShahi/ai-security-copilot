from fastapi import APIRouter, status

from app.schemas.security_event import SecurityEventCreate


router = APIRouter()


@router.post("/events", status_code=status.HTTP_201_CREATED)
async def create_security_event(event: SecurityEventCreate):
    return {
        "message": "Security event received",
        "event": event,
    }