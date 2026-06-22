"""OIDC/OAuth2 login endpoints."""

import base64
import hashlib
import json
import logging
import re
import secrets
import time
from urllib.parse import urlencode

import requests as http_requests
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import RedirectResponse
from peewee import DoesNotExist

from frigate.api.auth import (
    allow_public,
    create_encoded_jwt,
    set_jwt_cookie,
)
from frigate.api.defs.tags import Tags
from frigate.config import AuthConfig
from frigate.models import User

logger = logging.getLogger(__name__)

router = APIRouter(tags=[Tags.auth])

# Module-level discovery document cache (valid for process lifetime).
_discovery_cache: dict[str, dict] = {}


def _get_discovery_doc(discovery_url: str) -> dict:
    if discovery_url not in _discovery_cache:
        resp = http_requests.get(discovery_url, timeout=10)
        resp.raise_for_status()
        _discovery_cache[discovery_url] = resp.json()
    return _discovery_cache[discovery_url]


def _get_redirect_uri(request: Request, oidc_config) -> str:
    if oidc_config.redirect_uri:
        return oidc_config.redirect_uri
    proto = request.headers.get("x-forwarded-proto") or request.url.scheme
    host = (
        request.headers.get("x-forwarded-host")
        or request.headers.get("host")
        or request.url.netloc
    )
    return f"{proto}://{host}/api/auth/oidc/callback"


def _decode_jwt_payload(token: str) -> dict:
    """Decode JWT payload without signature verification.

    Safe here because the token came directly from the token endpoint over TLS,
    not from an untrusted client.
    """
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return {}
        payload = parts[1]
        padding = 4 - len(payload) % 4
        if padding != 4:
            payload += "=" * padding
        return json.loads(base64.urlsafe_b64decode(payload))
    except Exception:
        return {}


def _sanitize_username(raw: str) -> str:
    """Convert arbitrary claim value to a valid Frigate username (max 30 chars)."""
    sanitized = re.sub(r"[^A-Za-z0-9._]", "_", raw)
    return sanitized[:30] or "oidc_user"


@router.get("/login/oidc", dependencies=[Depends(allow_public())])
def oidc_login(request: Request):
    """Redirect the browser to the OIDC provider's authorization endpoint."""
    auth_config: AuthConfig = request.app.frigate_config.auth
    oidc_config = auth_config.oidc

    if not oidc_config.enabled:
        raise HTTPException(status_code=404, detail="OIDC login is not enabled")

    try:
        discovery = _get_discovery_doc(oidc_config.discovery_url)
    except Exception as e:
        logger.error(f"Failed to fetch OIDC discovery document: {e}")
        raise HTTPException(status_code=502, detail="Failed to reach OIDC provider")

    auth_endpoint = discovery.get("authorization_endpoint")
    if not auth_endpoint:
        raise HTTPException(
            status_code=502, detail="OIDC discovery missing authorization_endpoint"
        )

    state = secrets.token_urlsafe(32)
    code_verifier = secrets.token_urlsafe(48)
    code_challenge = (
        base64.urlsafe_b64encode(
            hashlib.sha256(code_verifier.encode()).digest()
        )
        .rstrip(b"=")
        .decode()
    )

    redirect_uri = _get_redirect_uri(request, oidc_config)

    params = {
        "response_type": "code",
        "client_id": oidc_config.client_id,
        "redirect_uri": redirect_uri,
        "scope": " ".join(oidc_config.scopes),
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
    }

    auth_url = auth_endpoint + "?" + urlencode(params)
    response = RedirectResponse(auth_url, status_code=302)

    # Short-lived HTTP-only cookies carry state and PKCE verifier to the callback.
    cookie_opts = {"httponly": True, "samesite": "lax", "max_age": 300}
    response.set_cookie("oidc_state", state, **cookie_opts)
    response.set_cookie("oidc_pkce", code_verifier, **cookie_opts)
    return response


@router.get("/auth/oidc/callback", dependencies=[Depends(allow_public())])
def oidc_callback(request: Request, code: str = "", state: str = "", error: str = ""):
    """Handle the OAuth2 authorization code callback from the OIDC provider."""
    auth_config: AuthConfig = request.app.frigate_config.auth
    oidc_config = auth_config.oidc

    if not oidc_config.enabled:
        raise HTTPException(status_code=404, detail="OIDC login is not enabled")

    if error:
        logger.warning(f"OIDC provider returned error: {error}")
        return RedirectResponse("/login", status_code=302)

    # Validate state to prevent CSRF.
    cookie_state = request.cookies.get("oidc_state", "")
    if not cookie_state or not secrets.compare_digest(cookie_state, state):
        logger.warning("OIDC callback state mismatch — possible CSRF attempt")
        return RedirectResponse("/login", status_code=302)

    code_verifier = request.cookies.get("oidc_pkce", "")

    try:
        discovery = _get_discovery_doc(oidc_config.discovery_url)
    except Exception as e:
        logger.error(f"OIDC discovery fetch failed during callback: {e}")
        return RedirectResponse("/login", status_code=302)

    token_endpoint = discovery.get("token_endpoint")
    if not token_endpoint:
        logger.error("OIDC discovery missing token_endpoint")
        return RedirectResponse("/login", status_code=302)

    redirect_uri = _get_redirect_uri(request, oidc_config)

    token_data: dict = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri,
        "client_id": oidc_config.client_id,
        "client_secret": oidc_config.client_secret,
    }
    if code_verifier:
        token_data["code_verifier"] = code_verifier

    try:
        token_resp = http_requests.post(token_endpoint, data=token_data, timeout=10)
        token_resp.raise_for_status()
        tokens = token_resp.json()
    except Exception as e:
        logger.error(f"OIDC token exchange failed: {e}")
        return RedirectResponse("/login", status_code=302)

    # Extract user identity claims from the ID token or userinfo endpoint.
    userinfo: dict = {}
    id_token = tokens.get("id_token", "")
    if id_token:
        userinfo = _decode_jwt_payload(id_token)

    if "sub" not in userinfo:
        userinfo_endpoint = discovery.get("userinfo_endpoint")
        if userinfo_endpoint:
            try:
                ui_resp = http_requests.get(
                    userinfo_endpoint,
                    headers={"Authorization": f"Bearer {tokens.get('access_token', '')}"},
                    timeout=10,
                )
                ui_resp.raise_for_status()
                userinfo = ui_resp.json()
            except Exception as e:
                logger.error(f"OIDC userinfo request failed: {e}")
                return RedirectResponse("/login", status_code=302)

    sub = userinfo.get("sub")
    if not sub:
        logger.error("OIDC response contains no 'sub' claim")
        return RedirectResponse("/login", status_code=302)

    # Find existing user by oauth_sub, or auto-create on first login.
    user: User | None = None
    try:
        user = User.get(
            (User.oauth_provider == "oidc") & (User.oauth_sub == sub)
        )
    except DoesNotExist:
        pass

    if user is None:
        if not oidc_config.auto_create_users:
            logger.warning(
                f"OIDC user with sub={sub!r} not found and auto_create_users is disabled"
            )
            return RedirectResponse("/login", status_code=302)

        # Derive a username from claims; fall back to sanitized sub.
        raw_name = (
            userinfo.get("preferred_username")
            or (userinfo.get("email") or "").split("@")[0]
            or sub
        )
        username = _sanitize_username(raw_name)

        # Ensure uniqueness by appending a numeric suffix if needed.
        base_name = username
        suffix = 1
        while True:
            try:
                User.get_by_id(username)
                username = f"{base_name[:27]}_{suffix}"
                suffix += 1
            except DoesNotExist:
                break

        config_roles_set = set(request.app.frigate_config.auth.roles.keys())
        role = (
            oidc_config.default_role
            if oidc_config.default_role in config_roles_set
            else "viewer"
        )

        User.insert(
            {
                User.username: username,
                User.password_hash: "oauth",
                User.role: role,
                User.notification_tokens: [],
                User.oauth_provider: "oidc",
                User.oauth_sub: sub,
            }
        ).execute()
        logger.info(
            f"Auto-created OIDC user {username!r} with role {role!r} (sub={sub!r})"
        )

        try:
            user = User.get_by_id(username)
        except DoesNotExist:
            logger.error("Failed to retrieve newly created OIDC user")
            return RedirectResponse("/login", status_code=302)

    # Issue a Frigate JWT cookie and redirect to the app.
    config_roles_set = set(request.app.frigate_config.auth.roles.keys())
    role = user.role if user.role in config_roles_set else "viewer"

    JWT_COOKIE_NAME = auth_config.cookie_name
    JWT_COOKIE_SECURE = auth_config.cookie_secure
    JWT_SESSION_LENGTH = auth_config.session_length

    expiration = int(time.time()) + JWT_SESSION_LENGTH
    encoded_jwt = create_encoded_jwt(
        user.username, role, expiration, request.app.jwt_token
    )

    response = RedirectResponse("/", status_code=302)
    set_jwt_cookie(response, JWT_COOKIE_NAME, encoded_jwt, expiration, JWT_COOKIE_SECURE)
    response.delete_cookie("oidc_state")
    response.delete_cookie("oidc_pkce")
    return response


@router.get("/auth/oidc/config", dependencies=[Depends(allow_public())])
def oidc_config_endpoint(request: Request):
    """Return whether OIDC login is enabled (used by the login page)."""
    from fastapi.responses import JSONResponse

    oidc_config = request.app.frigate_config.auth.oidc
    return JSONResponse(content={"enabled": oidc_config.enabled})
