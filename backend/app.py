"""FastAPI wrapper — serves the chat UI + agent endpoints."""
import os
import uuid
import time as _time
from collections import defaultdict
import time
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel
from agent import DomoAppDBAgent
from security_auditor.auditor_routes import auditor_router

SERVER_START_TIME = str(int(time.time()))

app = FastAPI(title="Domo AppDB Agent API", version="1.0.0")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
FRONTEND_DIST = os.path.abspath(os.path.join(BASE_DIR, "..", "frontend", "dist"))

app.include_router(auditor_router)

if os.path.exists(os.path.join(FRONTEND_DIST, "assets")):
    app.mount("/assets", StaticFiles(directory=os.path.join(FRONTEND_DIST, "assets")), name="assets")

sec_static = os.path.join(BASE_DIR, "security_auditor", "static")
if os.path.exists(sec_static):
    app.mount("/security-ui", StaticFiles(directory=sec_static), name="security-ui")

gen_static = os.path.join(BASE_DIR, "static")
if os.path.exists(gen_static):
    app.mount("/static", StaticFiles(directory=gen_static), name="static")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)













































































































































































































API_SECRET_KEY = os.getenv("API_SECRET_KEY", "")

@app.middleware("http")
async def verify_api_key(request: Request, call_next):
    if not API_SECRET_KEY:
        return await call_next(request)
    if request.url.path.startswith("/security") or request.url.path == "/":
        return await call_next(request)
    key = request.headers.get("X-API-Key", "")
    if key != API_SECRET_KEY:
        return JSONResponse(status_code=401, content={"detail": "Unauthorized — X-API-Key required"})
    return await call_next(request)


_rate_store: dict = defaultdict(list)

@app.middleware("http")
async def rate_limiter(request: Request, call_next):
    ip = request.client.host if request.client else "unknown"
    now = _time.time()
    _rate_store[ip] = [t for t in _rate_store[ip] if now - t < 60]
    if len(_rate_store[ip]) >= 10:
        return JSONResponse(status_code=429, content={"detail": "Rate limit exceeded. Max 10 requests/min."})
    _rate_store[ip].append(now)
    return await call_next(request)

sessions: dict[str, DomoAppDBAgent] = {}


class ChatRequest(BaseModel):
    message: str
    session_id: str | None = None


class ChatResponse(BaseModel):
    session_id: str
    reply: str


@app.get("/ping")
def ping():
    return {"started": SERVER_START_TIME}

@app.get("/")
def serve_ui():
    dist_index = os.path.join(FRONTEND_DIST, "index.html")
    if os.path.exists(dist_index):
        return FileResponse(dist_index)
    return FileResponse(os.path.join(BASE_DIR, "static", "index.html"))


@app.get("/auditor")
@app.get("/security")
def serve_auditor_ui():
    dist_index = os.path.join(FRONTEND_DIST, "index.html")
    if os.path.exists(dist_index):
        return FileResponse(dist_index)
    return FileResponse(os.path.join(BASE_DIR, "security_auditor", "static", "auditor.html"))


@app.get("/{file_path:path}")
def serve_static_or_spa(file_path: str):
    # Ignore API endpoints
    if file_path.startswith(("chat", "security", "auditor", "ping", "reset", "session", "docs", "openapi.json")):
        raise HTTPException(status_code=404, detail="Not Found")

    # 1. Check frontend/dist
    dist_file = os.path.join(FRONTEND_DIST, file_path)
    if os.path.isfile(dist_file):
        return FileResponse(dist_file)

    # 2. Check backend/static
    static_file = os.path.join(BASE_DIR, "static", file_path)
    if os.path.isfile(static_file):
        return FileResponse(static_file)

    # 3. Check backend/security_auditor/static
    sec_file = os.path.join(BASE_DIR, "security_auditor", "static", file_path)
    if os.path.isfile(sec_file):
        return FileResponse(sec_file)

    # 4. Fallback to dist index.html for SPA routes
    dist_index = os.path.join(FRONTEND_DIST, "index.html")
    if os.path.exists(dist_index):
        return FileResponse(dist_index)

    raise HTTPException(status_code=404, detail="Resource Not Found")



@app.post("/chat", response_model=ChatResponse)
def chat(req: ChatRequest):
    if not req.message.strip():
        raise HTTPException(status_code=400, detail="message cannot be empty")
    session_id = req.session_id or str(uuid.uuid4())
    agent = sessions.setdefault(session_id, DomoAppDBAgent())
    try:
        reply = agent.chat(req.message)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Agent error: {e}")
    return ChatResponse(session_id=session_id, reply=reply)


@app.post("/reset/{session_id}")
def reset(session_id: str):
    agent = sessions.get(session_id)
    if agent is None:
        raise HTTPException(status_code=404, detail="session not found")
    agent.reset()
    return {"status": "reset", "session_id": session_id}


@app.delete("/session/{session_id}")
def delete_session(session_id: str):
    if sessions.pop(session_id, None) is None:
        raise HTTPException(status_code=404, detail="session not found")
    return {"status": "deleted", "session_id": session_id}


if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8002))
    uvicorn.run("app:app", host="127.0.0.1", port=port, reload=True)




