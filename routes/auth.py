import base64
import hashlib
import json
import os
import secrets
import time
from pathlib import Path

import requests
from cryptography.fernet import Fernet, InvalidToken
from dotenv import load_dotenv
from fastapi import APIRouter, HTTPException
from fastapi.responses import RedirectResponse
from google.auth.transport.requests import Request
from google_auth_oauthlib.flow import Flow
from google.oauth2.credentials import Credentials


# ============================================================
# ENVIRONMENT
# ============================================================

load_dotenv()


# ============================================================
# ROUTER
# ============================================================

router = APIRouter(
    prefix="/auth",
    tags=["Authentication"],
)


# ============================================================
# GOOGLE CONFIGURATION
# ============================================================

GOOGLE_CLIENT_ID = os.getenv(
    "GOOGLE_CLIENT_ID"
)

GOOGLE_CLIENT_SECRET = os.getenv(
    "GOOGLE_CLIENT_SECRET"
)

GOOGLE_REDIRECT_URI = os.getenv(
    "GOOGLE_REDIRECT_URI",
    "http://127.0.0.1:8000/auth/google/callback",
)

FRONTEND_URL = os.getenv(
    "FRONTEND_URL",
    "http://localhost:3000",
).rstrip("/")


# ============================================================
# OAUTH STATE CONFIGURATION
# ============================================================

OAUTH_STATE_SECRET = os.getenv(
    "OAUTH_STATE_SECRET"
)

if not OAUTH_STATE_SECRET:
    raise RuntimeError(
        "OAUTH_STATE_SECRET is not configured."
    )


OAUTH_STATE_MAX_AGE = 600  # 10 minutes


# ============================================================
# OAUTH STATE ENCRYPTION
# ============================================================

def get_oauth_state_fernet() -> Fernet:
    """
    Derive a stable Fernet encryption key from OAUTH_STATE_SECRET.

    Fernet provides:
    - Encryption
    - Authentication
    - Integrity protection
    """

    key_material = hashlib.sha256(
        OAUTH_STATE_SECRET.encode("utf-8")
    ).digest()

    fernet_key = base64.urlsafe_b64encode(
        key_material
    )

    return Fernet(fernet_key)


def create_oauth_state(
    code_verifier: str,
) -> str:
    """
    Create a stateless encrypted OAuth state.

    The state contains:
    - issued-at timestamp
    - PKCE code verifier
    - random nonce

    No server-side session storage is required.
    """

    payload = {
        "iat": int(time.time()),
        "code_verifier": code_verifier,
        "nonce": secrets.token_urlsafe(32),
    }

    payload_bytes = json.dumps(
        payload,
        separators=(",", ":"),
    ).encode("utf-8")

    fernet = get_oauth_state_fernet()

    encrypted_state = fernet.encrypt(
        payload_bytes
    )

    return encrypted_state.decode("utf-8")


def verify_oauth_state(
    state: str,
) -> dict:
    """
    Decrypt and validate an OAuth state token.
    """

    if not state:
        raise HTTPException(
            status_code=400,
            detail="OAuth state is missing.",
        )

    try:
        fernet = get_oauth_state_fernet()

        decrypted = fernet.decrypt(
            state.encode("utf-8"),
            ttl=OAUTH_STATE_MAX_AGE,
        )

        payload = json.loads(
            decrypted.decode("utf-8")
        )

    except InvalidToken:
        raise HTTPException(
            status_code=400,
            detail="Invalid or expired OAuth state.",
        )

    except (ValueError, json.JSONDecodeError):
        raise HTTPException(
            status_code=400,
            detail="Malformed OAuth state.",
        )

    except Exception:
        raise HTTPException(
            status_code=400,
            detail="Unable to validate OAuth state.",
        )

    # --------------------------------------------------------
    # Validate payload
    # --------------------------------------------------------

    issued_at = payload.get("iat")
    code_verifier = payload.get("code_verifier")
    nonce = payload.get("nonce")

    if not issued_at:
        raise HTTPException(
            status_code=400,
            detail="OAuth state timestamp is missing.",
        )

    if not code_verifier:
        raise HTTPException(
            status_code=400,
            detail="OAuth code verifier is missing.",
        )

    if not nonce:
        raise HTTPException(
            status_code=400,
            detail="OAuth state nonce is missing.",
        )

    # --------------------------------------------------------
    # Additional expiration validation
    # --------------------------------------------------------

    current_time = int(time.time())

    if current_time - int(issued_at) > OAUTH_STATE_MAX_AGE:
        raise HTTPException(
            status_code=400,
            detail="OAuth state has expired.",
        )

    if int(issued_at) > current_time + 60:
        raise HTTPException(
            status_code=400,
            detail="OAuth state timestamp is invalid.",
        )

    return payload


# ============================================================
# GOOGLE SCOPES
# ============================================================

SCOPES = [
    "openid",
    "https://www.googleapis.com/auth/userinfo.email",
    "https://www.googleapis.com/auth/userinfo.profile",
    "https://www.googleapis.com/auth/gmail.readonly",
]


# ============================================================
# TOKEN STORAGE
# ============================================================

TOKEN_FILE = (
    Path(__file__).resolve().parent.parent
    / "token.json"
)


# ============================================================
# IN-MEMORY TOKEN CACHE
# ============================================================

google_tokens = {}


# ============================================================
# TOKEN FILE FUNCTIONS
# ============================================================

def save_google_token(
    token_data: dict,
):
    """
    Save Google OAuth credentials to token.json.

    Development/hackathon storage only.

    Production should use secure user-specific storage.
    """

    try:
        TOKEN_FILE.write_text(
            json.dumps(
                token_data,
                indent=2,
            ),
            encoding="utf-8",
        )

    except Exception as exc:
        raise RuntimeError(
            f"Unable to save Google token: {exc}"
        ) from exc


def load_google_token():
    """
    Load Google OAuth credentials from token.json.
    """

    if not TOKEN_FILE.exists():
        return None

    try:
        data = json.loads(
            TOKEN_FILE.read_text(
                encoding="utf-8",
            )
        )

        if not isinstance(data, dict):
            return None

        return data

    except Exception:
        return None


def delete_google_token():
    """
    Delete locally stored Google credentials.
    """

    google_tokens.pop(
        "default",
        None,
    )

    try:
        if TOKEN_FILE.exists():
            TOKEN_FILE.unlink()

    except Exception as exc:
        raise RuntimeError(
            f"Unable to delete Google token: {exc}"
        ) from exc


# ============================================================
# LOAD SAVED TOKEN
# ============================================================

_saved_token = load_google_token()

if _saved_token:
    google_tokens["default"] = _saved_token


# ============================================================
# GOOGLE FLOW
# ============================================================

def create_google_flow(
    code_verifier: str | None = None,
):
    """
    Create Google OAuth Flow.
    """

    if not GOOGLE_CLIENT_ID:
        raise RuntimeError(
            "GOOGLE_CLIENT_ID is not configured."
        )

    if not GOOGLE_CLIENT_SECRET:
        raise RuntimeError(
            "GOOGLE_CLIENT_SECRET is not configured."
        )

    client_config = {
        "web": {
            "client_id": GOOGLE_CLIENT_ID,
            "client_secret": GOOGLE_CLIENT_SECRET,
            "auth_uri": (
                "https://accounts.google.com/o/oauth2/auth"
            ),
            "token_uri": (
                "https://oauth2.googleapis.com/token"
            ),
            "redirect_uris": [
                GOOGLE_REDIRECT_URI
            ],
        }
    }

    flow = Flow.from_client_config(
        client_config,
        scopes=SCOPES,
        redirect_uri=GOOGLE_REDIRECT_URI,
        code_verifier=code_verifier,
    )

    return flow


# ============================================================
# TOKEN -> CREDENTIALS
# ============================================================

def token_data_to_credentials(
    token_data: dict,
) -> Credentials:
    """
    Convert stored token information into Google Credentials.
    """

    return Credentials(
        token=token_data.get("token"),
        refresh_token=token_data.get("refresh_token"),
        token_uri=token_data.get(
            "token_uri",
            "https://oauth2.googleapis.com/token",
        ),
        client_id=token_data.get(
            "client_id",
            GOOGLE_CLIENT_ID,
        ),
        client_secret=token_data.get(
            "client_secret",
            GOOGLE_CLIENT_SECRET,
        ),
        scopes=token_data.get(
            "scopes",
            SCOPES,
        ),
    )


# ============================================================
# REFRESH ACCESS TOKEN
# ============================================================

def refresh_google_credentials(
    credentials: Credentials,
) -> Credentials:
    """
    Refresh an expired Google access token.
    """

    if not credentials.refresh_token:
        raise RuntimeError(
            "Google access token expired and no refresh token "
            "is available. Please authenticate again."
        )

    try:
        credentials.refresh(
            Request()
        )

    except Exception as exc:
        raise RuntimeError(
            f"Google token refresh failed: {exc}"
        ) from exc

    token_data = {
        "token": credentials.token,
        "refresh_token": credentials.refresh_token,
        "token_uri": credentials.token_uri,
        "client_id": credentials.client_id,
        "client_secret": credentials.client_secret,
        "scopes": credentials.scopes,
    }

    google_tokens["default"] = token_data

    save_google_token(
        token_data
    )

    return credentials


# ============================================================
# GET VALID GOOGLE CREDENTIALS
# ============================================================

def get_google_credentials() -> Credentials:
    """
    Return valid Google OAuth credentials.
    """

    token_data = google_tokens.get(
        "default"
    )

    if not token_data:
        token_data = load_google_token()

        if token_data:
            google_tokens["default"] = token_data

    if not token_data:
        raise RuntimeError(
            "Google authentication required."
        )

    credentials = token_data_to_credentials(
        token_data
    )

    if credentials.expired:
        credentials = refresh_google_credentials(
            credentials
        )

    if not credentials.token:
        raise RuntimeError(
            "Google access token is unavailable."
        )

    return credentials


# ============================================================
# GOOGLE LOGIN
# ============================================================

@router.get("/google")
async def google_login():
    """
    Start Google OAuth authentication.

    PKCE verifier is embedded inside an encrypted,
    stateless OAuth state token.
    """

    try:

        # ----------------------------------------------------
        # Generate PKCE verifier
        # ----------------------------------------------------

        code_verifier = secrets.token_urlsafe(
            64
        )

        # ----------------------------------------------------
        # Create encrypted stateless OAuth state
        # ----------------------------------------------------

        state = create_oauth_state(
            code_verifier
        )

        # ----------------------------------------------------
        # Create Google OAuth flow
        # ----------------------------------------------------

        flow = create_google_flow(
            code_verifier=code_verifier
        )

        # ----------------------------------------------------
        # Generate authorization URL
        # ----------------------------------------------------

        authorization_url, _ = (
            flow.authorization_url(
                access_type="offline",
                include_granted_scopes="true",
                prompt="consent",
                state=state,
            )
        )

        # ----------------------------------------------------
        # Redirect user to Google
        # ----------------------------------------------------

        return RedirectResponse(
            url=authorization_url
        )

    except Exception as exc:

        raise HTTPException(
            status_code=500,
            detail=(
                f"Google login error: {exc}"
            ),
        )


# ============================================================
# GOOGLE CALLBACK
# ============================================================

@router.get("/google/callback")
async def google_callback(
    code: str,
    state: str,
):
    """
    Handle Google OAuth callback.

    The OAuth state is verified without relying on
    server-side memory.
    """

    try:

        # ----------------------------------------------------
        # Validate and decrypt OAuth state
        # ----------------------------------------------------

        state_payload = verify_oauth_state(
            state
        )

        # ----------------------------------------------------
        # Extract PKCE verifier
        # ----------------------------------------------------

        code_verifier = state_payload.get(
            "code_verifier"
        )

        if not code_verifier:
            raise HTTPException(
                status_code=400,
                detail=(
                    "OAuth code verifier is missing."
                ),
            )

        # ----------------------------------------------------
        # Recreate OAuth flow
        # ----------------------------------------------------

        flow = create_google_flow(
            code_verifier=code_verifier
        )

        # ----------------------------------------------------
        # Exchange authorization code
        # ----------------------------------------------------

        flow.fetch_token(
            code=code
        )

        credentials = flow.credentials

        if not credentials.token:
            raise HTTPException(
                status_code=400,
                detail=(
                    "Google did not return an access token."
                ),
            )

        # ----------------------------------------------------
        # Preserve refresh token
        # ----------------------------------------------------

        refresh_token = (
            credentials.refresh_token
        )

        old_token = google_tokens.get(
            "default"
        )

        if (
            not refresh_token
            and old_token
        ):
            refresh_token = old_token.get(
                "refresh_token"
            )

        # ----------------------------------------------------
        # Build persistent token data
        # ----------------------------------------------------

        token_data = {
            "token": credentials.token,
            "refresh_token": refresh_token,
            "token_uri": credentials.token_uri,
            "client_id": credentials.client_id,
            "client_secret": credentials.client_secret,
            "scopes": credentials.scopes,
        }

        # ----------------------------------------------------
        # Store Google credentials
        # ----------------------------------------------------

        google_tokens["default"] = token_data

        save_google_token(
            token_data
        )

        # ----------------------------------------------------
        # Redirect to Next.js session callback
        # ----------------------------------------------------

        session_callback_url = (
            f"{FRONTEND_URL}"
            "/api/auth/google/callback"
        )

        return RedirectResponse(
            url=session_callback_url,
            status_code=302,
        )

    except HTTPException:
        raise

    except Exception as exc:

        raise HTTPException(
            status_code=400,
            detail=(
                f"Google authentication failed: {exc}"
            ),
        )


# ============================================================
# AUTH STATUS
# ============================================================

@router.get("/status")
async def authentication_status():

    token_data = google_tokens.get(
        "default"
    )

    if not token_data:
        token_data = load_google_token()

        if token_data:
            google_tokens["default"] = token_data

    if not token_data:
        return {
            "authenticated": False,
            "user": None,
        }

    try:

        credentials = token_data_to_credentials(
            token_data
        )

        if credentials.expired:
            credentials = refresh_google_credentials(
                credentials
            )

        if not credentials.token:
            return {
                "authenticated": False,
                "user": None,
            }

        # ----------------------------------------------------
        # Fetch authenticated Google profile
        # ----------------------------------------------------

        response = requests.get(
            "https://www.googleapis.com/oauth2/v3/userinfo",
            headers={
                "Authorization": (
                    f"Bearer {credentials.token}"
                ),
            },
            timeout=10,
        )

        if not response.ok:
            return {
                "authenticated": False,
                "user": None,
                "error": (
                    "Unable to retrieve Google profile."
                ),
            }

        profile = response.json()

        # ----------------------------------------------------
        # Normalize Google user
        # ----------------------------------------------------

        user = {
            "id": profile.get("sub"),
            "name": profile.get("name"),
            "email": profile.get("email"),
            "picture": profile.get("picture"),
            "given_name": profile.get("given_name"),
            "family_name": profile.get("family_name"),
            "email_verified": profile.get(
                "email_verified",
                False,
            ),
            "role": "analyst",
        }

        # ----------------------------------------------------
        # Validate Google identity
        # ----------------------------------------------------

        if not user["id"]:
            return {
                "authenticated": False,
                "user": None,
                "error": (
                    "Google account ID was not returned."
                ),
            }

        return {
            "authenticated": True,
            "user": user,
            "scopes": credentials.scopes,
        }

    except Exception as exc:

        return {
            "authenticated": False,
            "user": None,
            "error": str(exc),
        }


# ============================================================
# LOGOUT / DISCONNECT
# ============================================================

@router.post("/logout")
async def google_logout():

    try:

        delete_google_token()

        return {
            "success": True,
            "message": (
                "Google authentication removed."
            ),
        }

    except Exception as exc:

        raise HTTPException(
            status_code=500,
            detail=(
                f"Unable to remove Google authentication: {exc}"
            ),
        )