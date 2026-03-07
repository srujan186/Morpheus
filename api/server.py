"""
MORPHEUS API Server
====================
FastAPI application entry point.
Run with: uvicorn api.server:app --reload
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from api.routes import router


app = FastAPI(
    title="MORPHEUS Security Scanner",
    description="AI Agent Supply Chain Security Testing API",
    version="0.1.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

# ---------------------------------------------------------------------------
# CORS
# ---------------------------------------------------------------------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],          # Tighten in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# Routers
# ---------------------------------------------------------------------------
app.include_router(router, prefix="")


# ---------------------------------------------------------------------------
# Health check
# ---------------------------------------------------------------------------
@app.get("/health", tags=["health"])
async def health_check() -> dict:
    """
    Basic health check endpoint.

    Returns:
        status: "ok" when the server is running
    """
    return {"status": "ok", "service": "MORPHEUS"}
