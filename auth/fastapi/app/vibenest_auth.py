from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets
import time
from dataclasses import dataclass
from urllib.parse import urlencode, urlsplit, urlunsplit

import httpx
import jwt
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import RedirectResponse


@dataclass(frozen=True)
class AuthSettings:
    issuer: str
    client_id: str
    client_secret: str | None
    redirect_uri: str

    @classmethod
    def from_env(cls, env: dict[str, str] | None = None) -> "AuthSettings":
        source = os.environ if env is None else env
        issuer = required(source, "VIBENEST_AUTH_ISSUER")
        redirect_uri = required(source, "VIBENEST_AUTH_REDIRECT_URI")
        if urlsplit(issuer).scheme != "https" or urlsplit(redirect_uri).scheme != "https":
            raise ValueError("OIDC issuer and callback must use HTTPS")
        return cls(
            issuer=issuer.rstrip("/") + "/",
            client_id=required(source, "VIBENEST_AUTH_CLIENT_ID"),
            client_secret=source.get("VIBENEST_AUTH_CLIENT_SECRET") or None,
            redirect_uri=redirect_uri,
        )


def create_auth_router(settings: AuthSettings, client: httpx.AsyncClient | None = None) -> APIRouter:
    router = APIRouter()

    async def metadata() -> dict:
        endpoint = settings.issuer + ".well-known/openid-configuration"
        transport = client or httpx.AsyncClient(timeout=10)
        try:
            response = await transport.get(endpoint)
            response.raise_for_status()
            document = response.json()
        finally:
            if client is None:
                await transport.aclose()
        if document.get("issuer") != settings.issuer:
            raise HTTPException(502, "OIDC discovery issuer mismatch")
        return document

    @router.get("/auth/vibenest/login")
    async def login(request: Request):
        document = await metadata()
        verifier = secrets.token_urlsafe(64)
        state = secrets.token_urlsafe(32)
        nonce = secrets.token_urlsafe(32)
        request.session["vibenest_oidc"] = {
            "verifier": verifier,
            "state": state,
            "nonce": nonce,
            "expires_at": int(time.time()) + 300,
        }
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
        query = urlencode({
            "client_id": settings.client_id,
            "redirect_uri": settings.redirect_uri,
            "response_type": "code",
            "scope": "openid profile email",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "state": state,
            "nonce": nonce,
        })
        return RedirectResponse(f"{document['authorization_endpoint']}?{query}", status_code=303)

    @router.get("/auth/vibenest/callback")
    async def callback(request: Request):
        pending = request.session.pop("vibenest_oidc", None)
        supplied_state = request.query_params.get("state")
        code = request.query_params.get("code")
        if (
            not pending
            or pending.get("expires_at", 0) < int(time.time())
            or not supplied_state
            or not hmac.compare_digest(pending.get("state", ""), supplied_state)
            or not code
        ):
            raise HTTPException(400, "Invalid or expired OIDC callback")
        document = await metadata()
        payload = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": settings.redirect_uri,
            "client_id": settings.client_id,
            "code_verifier": pending["verifier"],
        }
        if settings.client_secret:
            payload["client_secret"] = settings.client_secret
        transport = client or httpx.AsyncClient(timeout=10)
        try:
            token_response = await transport.post(document["token_endpoint"], data=payload)
            token_response.raise_for_status()
            token = token_response.json()
            jwks_response = await transport.get(document["jwks_uri"])
            jwks_response.raise_for_status()
            claims = jwt.decode(
                token["id_token"],
                jwt.PyJWKClient(document["jwks_uri"]).get_signing_key_from_jwt(token["id_token"]).key
                if client is None
                else signing_key(token["id_token"], jwks_response.json()),
                algorithms=["RS256", "ES256"],
                audience=settings.client_id,
                issuer=settings.issuer,
                options={"require": ["exp", "iat", "sub", "nonce"]},
            )
            if not hmac.compare_digest(str(claims.get("nonce", "")), pending["nonce"]):
                raise HTTPException(401, "OIDC nonce mismatch")
            profile = {}
            if token.get("access_token") and document.get("userinfo_endpoint"):
                userinfo = await transport.get(
                    document["userinfo_endpoint"],
                    headers={"Authorization": f"Bearer {token['access_token']}"},
                )
                userinfo.raise_for_status()
                profile = userinfo.json()
                if profile.get("sub") != claims["sub"]:
                    raise HTTPException(401, "UserInfo subject mismatch")
        finally:
            if client is None:
                await transport.aclose()
        request.session.clear()
        request.session["user"] = {"subject": claims["sub"], "email": profile.get("email", claims.get("email"))}
        request.session["csrf"] = secrets.token_urlsafe(32)
        origin = urlunsplit((*urlsplit(settings.redirect_uri)[:2], "/", "", ""))
        return RedirectResponse(origin, status_code=303)

    @router.post("/auth/logout")
    async def logout(request: Request):
        require_user(request)
        expected_origin = f"{urlsplit(settings.redirect_uri).scheme}://{urlsplit(settings.redirect_uri).netloc}"
        supplied = request.headers.get("x-csrf-token", "")
        if request.headers.get("origin") != expected_origin or not hmac.compare_digest(request.session.get("csrf", ""), supplied):
            raise HTTPException(403, "CSRF validation failed")
        request.session.clear()
        return RedirectResponse(expected_origin + "/", status_code=303)

    @router.get("/api/session")
    async def session(request: Request):
        user = require_user(request)
        return {"authenticated": True, "subject": user["subject"], "email": user.get("email"), "csrf": request.session["csrf"]}

    return router


def signing_key(encoded: str, jwks: dict):
    header = jwt.get_unverified_header(encoded)
    for candidate in jwks.get("keys", []):
        if candidate.get("kid") == header.get("kid"):
            return jwt.PyJWK.from_dict(candidate).key
    raise HTTPException(401, "No matching OIDC signing key")


def require_user(request: Request) -> dict:
    user = request.session.get("user")
    if not isinstance(user, dict) or not user.get("subject"):
        raise HTTPException(401, "Authentication required")
    return user


def callback_url_from_request(query: str, settings: AuthSettings) -> str:
    parsed = urlsplit(settings.redirect_uri)
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, query.lstrip("?"), ""))


def required(source, name: str) -> str:
    value = source.get(name, "").strip()
    if not value:
        raise ValueError(f"Missing {name}")
    return value
