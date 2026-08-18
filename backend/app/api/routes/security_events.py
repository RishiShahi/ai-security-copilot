from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.database import get_db
from app.schemas.security_event import (
    SecurityEventCreate,
    SecurityEventResponse,
)
from app.services.security_event_service import (
    create_security_event,
    get_security_events,
    get_security_event,
)


router = APIRouter()


@router.post(
    "/events",
    response_model=SecurityEventResponse,
)
def create_event(
    event_data: SecurityEventCreate,
    db: Session = Depends(get_db),
):
    return create_security_event(
        db=db,
        event_data=event_data,
    )

@router.get(
    "/events",
    response_model=list[SecurityEventResponse],
)
def get_events(
    db: Session = Depends(get_db),
):
    return get_security_events(db=db)

@router.get(
    "/events/{event_id}",
    response_model=SecurityEventResponse,
)
def get_event(
    event_id: int,
    db: Session = Depends(get_db),
):
    event = get_security_event(
        db=db,
        event_id=event_id,
    )

    if event is None:
        raise HTTPException(
            status_code=404,
            detail="Security event not found",
        )

    return event