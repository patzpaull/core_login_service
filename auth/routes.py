# auth/routes.py
from fastapi import APIRouter, Request, Depends, HTTPException
from fastapi.responses import RedirectResponse, HTMLResponse
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from auth.keycloak import get_keycloak_client
from fastapi.templating import Jinja2Templates
import os
import secrets
import logging

from keycloak.exceptions import KeycloakAuthenticationError

router = APIRouter()
templates = Jinja2Templates(directory="templates")

# Determine Keycloak Server URL and Redirect URI
KEYCLOAK_SERVER_URL = os.getenv(
    "KEYCLOAK_SERVER_URL", "https://sso.schoolmate.co.tz/")
REDIRECT_URI = os.getenv(
    "REDIRECT_URI", "https://core.schoolmate.co.tz/auth/callback")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


# Configure logger
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
handler = logging.StreamHandler()
formatter = logging.Formatter(
    '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)


def get_realm_from_session(request: Request) -> str:
    realm = request.session.get('realm')
    if realm not in ["marketplace", "schoolmate"]:
        logger.error(f"Invalid realm found in session{realm}")
        raise HTTPException(status_code=400, detail="Invalid Realm")
    logger.debug(f"Realm retreived from session: {realm}")
    return realm


def verify_token(token: str = Depends(oauth2_scheme), request: Request = Depends()):
    realm = request.session.get('realm')
    if not realm:
        logger.error("Realm not found in session during token verification. ")
        raise HTTPException(status_code=400, detail="Invalid Realm")

    public_key = os.getenv(f"KEYCLOAK_PUBLIC_KEY_{realm.upper()}")
    if not public_key:
        # Ensure this is set
        logger.error(f"Public key for realm {realm} is not set.")
        raise HTTPException(status_code=500, detail="Internal Server Error.")

    credentials_exception = HTTPException(
        status_code=401,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, public_key, algorithms=["RS256"], audience=os.getenv(
            f"CLIENT_ID_{realm.upper()}"))  # Adjust audience as needed
        user_id: str = payload.get("sub")
        if user_id is None:
            logger.error("Token payload does not contain 'sub'")
            raise credentials_exception
        logger.debug(f"Token verified for user: {user_id}")
        return payload
    except JWTError as e:
        logger.error(f"JWT decode error:{e}")
        raise credentials_exception


# @router.get("/protected")
# async def protected_route(request: Request, user: dict = Depends(verify_token)):
#     logger.info(f"Protected route accessed by user: {user['sub']}")
#     return {"message": f"Hello, user {user['sub']}!"}


@router.get("/login/{app_name}", response_class=HTMLResponse)
async def login(request: Request, app_name: str, next: str = "http://localhost:8000"):
    if app_name not in ["marketplace", "schoolmate"]:
        logger.warning(f"Invalid application name attempted: {app_name}")
        return templates.TemplateResponse("error.html", {"request": request, "message": "Invalid application name."})

    realm = app_name
    if realm == "schoolmate":
        client_id = os.getenv("CLIENT_ID")
        client_secret = os.getenv("CLIENT_SECRET")
    elif realm == "marketplace":
        client_id = os.getenv("CLIENT_ID_SUB")
        client_secret = os.getenv("CLIENT_SECRET_SUB")
    else:
        logger.warning(f"Invalid realm: {realm}")
        return templates.TemplateResponse("error.html", {"request": request, "message": "Invalid application name."})

    keycloak = get_keycloak_client(realm, client_id, client_secret)

    # Generate a random state string
    state = secrets.token_urlsafe(16)
    request.session['state'] = state
    request.session['realm'] = realm
    request.session['next'] = next

    authorization_url = keycloak.auth_url(
        redirect_uri=REDIRECT_URI, state=state,
        scope="openid"
    )
    logger.info(f"Redirecting to keycloak for {realm} with state {state}")
    return RedirectResponse(url=authorization_url)


@router.get("/callback", response_class=HTMLResponse)
async def callback(request: Request, code: str = None, state: str = None, error: str = None):
    if error:
        logger.error(f"Callback received error: {error}")
        return templates.TemplateResponse("error.html", {"request": request, "message": f"Error: {error}"})

    # Retrieving state and realm from session
    session_state = request.session.get('state')
    realm = request.session.get('realm')
    next_url = request.session.get('next', 'http://localhost:3000')

    logger.info(f" Callback received with state:{
                state}, session_state:{session_state},realm: {realm}")

    if not session_state or not realm:
        logger.error("Session state or realm missing in callback")
        raise HTTPException(status_code=400, detail="Session state missing")

    if state != session_state:
        logger.error("State parameter mismatch in callback")
        raise HTTPException(status_code=400, detail="Invalid state parameter")

    if realm == "schoolmate":
        client_id = os.getenv("CLIENT_ID")
        client_secret = os.getenv("CLIENT_SECRET")
    elif realm == "marketplace":
        client_id = os.getenv("CLIENT_ID_SUB")
        client_secret = os.getenv("CLIENT_SECRET_SUB")
    else:
        logger.warning(f"Invalid realm: {realm}")
        return templates.TemplateResponse("error.html", {"request": request, "message": "Invalid application name."})

    keycloak = get_keycloak_client(realm, client_id, client_secret)
    try:
        token = keycloak.token(
            grant_type='authorization_code', code=code, redirect_uri=REDIRECT_URI)
        logger.info("Token exchange succesful")
    except KeycloakAuthenticationError as e:
        logger.error(f"Keycloak Authentication Error:{e}")
        return templates.TemplateResponse("error.html", {"request": request, "message": "Authentification Failed. Please try again", })

    redirect_url = f"{next_url}?access_token={
        token['access_token']}&id_token={token['id_token']}"
    logger.info(f"Redirecting to: {redirect_url}")

    # next_url = request.session.get('next', '/')
    # Clear 'next' from session
    request.session.pop('state', None)
    request.session.pop('realm', None)
    request.session.pop('next', None)

    response = RedirectResponse(url=redirect_url)
    # Set cookies with tokens
#     response.set_cookie(
#         key="access_token",
#         value=token['access_token'],
#         httponly=True,
#         secure=True,  # Set to True in production
#         samesite='lax'
#     )
#     response.set_cookie(
#         key="refresh_token",
#         value=token['refresh_token'],
#         httponly=True,
#         secure=True,  # Set to True in production
#         samesite='lax'
#     )

#   # Clear session state
#     request.session.pop('state', None)
#     request.session.pop('realm', None)

    # logger.info("Token set in cookies and redirected to dashboard")
    return response


@router.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request):
    # Optionally, you can verify tokens or fetch user information here
    return templates.TemplateResponse("dashboard.html", {"request": request})


@router.get("/logout", response_class=HTMLResponse)
async def logout(request: Request):
    response = RedirectResponse(url="/")
    response.delete_cookie("access_token")
    response.delete_cookie("id_token")
    response.delete_cookie("refresh_token")
    # Optionally, redirect to Keycloak’s logout endpoint
    # Example:
    # keycloak = get_keycloak_client(...)
    # logout_url = keycloak.logout_url(redirect_uri=REDIRECT_URI)
    # return RedirectResponse(url=logout_url)
    logger.info("User logged out and cookies cleared")
    return response
