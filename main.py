# main.py
from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from auth.routes import router as auth_router
from fastapi.templating import Jinja2Templates
import os
import secrets
from pathlib import Path
from starlette.middleware.sessions import SessionMiddleware
from dotenv import load_dotenv
from fastapi.responses import HTMLResponse
import logging
# Load environment variables from .env file
load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[
        logging.StreamHandler()
    ]
)

app = FastAPI()


# Mount static files
app.mount("/static", StaticFiles(directory="static"), name="static")


def get_session_key():
    key_file = Path("session_key.txt")
    if key_file.exists():
        with key_file.open("r") as f:
            secret_key = f.read()
    else:
        secret_key = secrets.token_hex(32)
        with key_file.open("w") as f:
            f.write(secret_key)
    return secret_key


session_secret_key = get_session_key()

# Add session middleware
# session_secret_key = os.getenv(
#     "SESSION_SECRET_KEY", "fcc3496c4b45209a72242055b3be3c5859955b77c639a157a8a7c18b07043063")
# if not session_secret_key:
#     raise ValueError("SESSION_SECRET_KEY environment variable is not set")

app.add_middleware(SessionMiddleware, secret_key=session_secret_key,
                   same_site="lax", https_only=False)

# Initialize templates
templates = Jinja2Templates(directory="templates")

# Include authentication routes
app.include_router(auth_router, prefix="/auth")


@app.get("/", response_class=HTMLResponse)
def read_root(request: Request):
    return templates.TemplateResponse("home.html", {"request": request})
