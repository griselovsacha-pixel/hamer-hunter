from fastapi import FastAPI, Request, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from celery.result import AsyncResult
import redis.asyncio as aioredis
import json
from .tasks import run_full_scan

app = FastAPI(title="Hamer Hunter - Ultimate Bug Bounty Scanner")
app.mount("/static", StaticFiles(directory="app/static"), name="static")
templates = Jinja2Templates(directory="app/templates")

# Простое хранилище задач (для продакшена заменить на БД)
task_store = {}

@app.get("/")
async def index(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.post("/scan")
async def start_scan(url: str):
    if not url.startswith(("http://", "https://")):
        raise HTTPException(400, "URL must start with http:// or https://")
    task = run_full_scan.delay(url)
    task_store[task.id] = "running"
    return {"task_id": task.id}

@app.get("/scan/{task_id}")
async def get_status(task_id: str):
    task = AsyncResult(task_id, app=run_full_scan)
    if task.state == 'SUCCESS':
        return {"status": "completed", "results": task.result}
    elif task.state == 'FAILURE':
        return {"status": "failed", "error": str(task.info)}
    else:
        return {"status": "running"}

# WebSocket для live-результатов из прокси-сканера
@app.websocket("/ws/results")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    r = aioredis.from_url("redis://redis:6379/0")
    pubsub = r.pubsub()
    await pubsub.subscribe("scan_results")
    try:
        async for message in pubsub.listen():
            if message['type'] == 'message':
                await websocket.send_text(message['data'])
    except WebSocketDisconnect:
        pass
