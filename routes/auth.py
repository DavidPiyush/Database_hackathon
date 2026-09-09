import asyncio
import json
import os
import secrets
from pathlib import Path

from fastapi import APIRouter, HTTPException
from fastapi.responses import RedirectResponse
from dotenv import load_dotenv

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
# IN-MEMORY STATE
# ============================================================

google_tokens = {}

oauth_sessions = {}

# Prevent duplicate OAuth callbacks from exchanging the same one-time
# Google authorization code concurrently in the same process.
oauth_callback_lock = asyncio.Lock()


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
            "GOOGLE_CLIENT_ID is not configured in .env"
        )

    if not GOOGLE_CLIENT_SECRET:
        raise RuntimeError(
            "GOOGLE_CLIENT_SECRET is not configured in .env"
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

    try:

        # ----------------------------------------------------
        # Generate PKCE verifier
        # ----------------------------------------------------

        code_verifier = secrets.token_urlsafe(
            64
        )

        flow = create_google_flow(
            code_verifier=code_verifier
        )

        # ----------------------------------------------------
        # Generate authorization URL
        # ----------------------------------------------------

        authorization_url, state = (
            flow.authorization_url(
                access_type="offline",
                include_granted_scopes="true",
                prompt="consent",
            )
        )

        # ----------------------------------------------------
        # Store state + verifier
        # ----------------------------------------------------

        oauth_sessions[state] = {
            "code_verifier": code_verifier,
        }

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

    session_callback_url = (
        f"{FRONTEND_URL}"
        "/api/auth/google/callback"
    )

    try:
        # Google authorization codes are single-use. A browser/proxy can
        # occasionally deliver the callback more than once. Serialize the
        # callback so the same code is not exchanged concurrently.
        async with oauth_callback_lock:
            session = oauth_sessions.get(state)

            if not session:
                # A duplicate callback can arrive after the first request has
                # already consumed the OAuth state. If a valid Google token
                # exists, the OAuth operation is already complete.
                try:
                    existing_credentials = get_google_credentials()
                    if existing_credentials.token:
                        return RedirectResponse(
                            url=session_callback_url,
                            status_code=302,
                        )
                except Exception:
                    pass

                raise HTTPException(
                    status_code=400,
                    detail="Invalid or expired OAuth state.",
                )

            code_verifier = session.get("code_verifier")

            if not code_verifier:
                oauth_sessions.pop(state, None)
                raise HTTPException(
                    status_code=400,
                    detail="OAuth code verifier is missing.",
                )

            flow = create_google_flow(
                code_verifier=code_verifier
            )

            try:
                flow.fetch_token(code=code)
            except Exception as exc:
                # Google authorization codes are one-time values. If another
                # callback already exchanged this code, do not exchange it
                # again; continue only when a valid token is already stored.
                if "invalid_grant" in str(exc).lower():
                    oauth_sessions.pop(state, None)
                    try:
                        existing_credentials = get_google_credentials()
                        if existing_credentials.token:
                            return RedirectResponse(
                                url=session_callback_url,
                                status_code=302,
                            )
                    except Exception:
                        pass

                raise

            credentials = flow.credentials

            if not credentials.token:
                oauth_sessions.pop(state, None)
                raise HTTPException(
                    status_code=400,
                    detail="Google did not return an access token.",
                )

            refresh_token = credentials.refresh_token
            old_token = google_tokens.get("default")

            if not refresh_token and old_token:
                refresh_token = old_token.get("refresh_token")

            token_data = {
                "token": credentials.token,
                "refresh_token": refresh_token,
                "token_uri": credentials.token_uri,
                "client_id": credentials.client_id,
                "client_secret": credentials.client_secret,
                "scopes": credentials.scopes,
            }

            google_tokens["default"] = token_data
            save_google_token(token_data)

            # Consume OAuth state after the successful exchange.
            oauth_sessions.pop(state, None)

            return RedirectResponse(
                url=session_callback_url,
                status_code=302,
            )

    except HTTPException:
        raise

    except Exception as exc:
        raise HTTPException(
            status_code=400,
            detail=f"Google authentication failed: {exc}",
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
            "has_access_token": False,
            "has_refresh_token": False,
        }

    try:

        credentials = token_data_to_credentials(
            token_data
        )

        if credentials.expired:

            credentials = refresh_google_credentials(
                credentials
            )

        return {
            "authenticated": bool(
                credentials.token
            ),
            "has_access_token": bool(
                credentials.token
            ),
            "has_refresh_token": bool(
                credentials.refresh_token
            ),
            "scopes": credentials.scopes,
        }

    except Exception as exc:

        return {
            "authenticated": False,
            "has_access_token": False,
            "has_refresh_token": bool(
                token_data.get(
                    "refresh_token"
                )
            ),
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