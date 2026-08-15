from fastapi import FastAPI


app = FastAPI(
    title="AI Security Copilot API",
    description="Backend API for the AI Security Copilot platform",
    version="0.1.0",
)


@app.get("/api/health")
async def health_check():
    return {
        "status": "healthy",
        "service": "ai-security-copilot-api",
    }