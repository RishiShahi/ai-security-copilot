from fastapi import FastAPI

from app.api.routes.health import router as health_router
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