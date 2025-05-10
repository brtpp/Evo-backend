from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from srb_engine import process_prompt

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

class Prompt(BaseModel):
    prompt: str
    user_id: str = "anon"
    tier: str = "free"
    behavior: dict = {}

@app.post("/infer")import json
from fastapi.responses import JSONResponse

@app.get("/metrics")
async def get_metrics():
    """
    Returns the raw performance_log.json so you can review
    all the click/conversion/time-on-page scores.
    """
    try:
        with open("performance_log.json", "r") as f:
            data = json.load(f)
    except FileNotFoundError:
        data = []  # no logs yet
    return JSONResponse(content=data)
async def infer_route(data: Prompt):
    return process_prompt(data.prompt, data.tier, data.behavior)
