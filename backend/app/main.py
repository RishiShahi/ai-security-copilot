from fastapi import FastAPI

from app.api.routes.health import router as health_router
from app.api.routes.security_events import router as security_events_router
from app.core.config import settings


app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description="Backend API for the AI Security Copilot platform",
)

app.include_router(
    health_router,
    prefix="/api",
)

app.include_router(
    security_events_router,
    prefix="/api/security",
)