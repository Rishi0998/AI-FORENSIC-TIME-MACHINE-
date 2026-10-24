"""
AI Digital Forensics Time Machine — Backend
FastAPI application entry point.
"""
import os
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from dotenv import load_dotenv

load_dotenv()

from database import init_db
from routes.api import router

# ── App Configuration ───────────────────────────────────────────────────────
app = FastAPI(
    title="AI Digital Forensics Time Machine",
    description="Analyze system/network logs and reconstruct cyber attacks into timelines, graphs, and human-readable explanations.",
    version="1.0.0",
)

# CORS — allow frontend dev server and all origins
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register API routes
app.include_router(router, prefix="/api")

# Determine frontend dist directory
frontend_dist = Path(__file__).parent.parent / "frontend" / "dist"
assets_dir = frontend_dist / "assets"

if assets_dir.exists():
    app.mount("/assets", StaticFiles(directory=str(assets_dir)), name="assets")


@app.on_event("startup")
def startup():
    """Initialize database on startup."""
    init_db()


@app.get("/api")
def root_api():
    return {
        "name": "AI Digital Forensics Time Machine",
        "version": "1.0.0",
        "docs": "/docs",
        "endpoints": [
            "POST /api/upload-logs",
            "POST /api/analyze-live-stream",
            "WS /api/ws/monitor",
            "GET /api/extract-local-logs",
            "GET /api/events?session_id=...",
            "GET /api/timeline?session_id=...",
            "GET /api/graph?session_id=...",
            "GET /api/analysis?session_id=...",
            "GET /api/replay?session_id=...",
        ]
    }


@app.get("/health")
@app.get("/api/health")
def health():
    return {"status": "healthy"}


@app.get("/{full_path:path}")
def catch_all(full_path: str):
    """Serve frontend index.html for SPA routes, or fallback to API info if index.html is missing."""
    index_file = frontend_dist / "index.html"
    if index_file.exists():
        return FileResponse(str(index_file))
    return JSONResponse({
        "name": "AI Digital Forensics Time Machine",
        "status": "running",
        "docs": "/docs"
    })
