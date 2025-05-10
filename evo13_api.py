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

@app.post("/infer")
async def infer_route(data: Prompt):
    return process_prompt(data.prompt, data.tier, data.behavior)
