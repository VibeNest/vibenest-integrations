import os

from fastapi import FastAPI
from fastapi.responses import HTMLResponse, PlainTextResponse
from starlette.middleware.sessions import SessionMiddleware

from .vibenest_auth import AuthSettings, create_auth_router


def create_app(env: dict[str, str] | None = None) -> FastAPI:
    source = os.environ if env is None else env
    secret = source.get("APP_SESSION_SECRET", "")
    if len(secret) < 32:
        raise ValueError("APP_SESSION_SECRET must contain at least 32 characters")
    app = FastAPI(title="VibeNest Auth reference")
    app.add_middleware(SessionMiddleware, secret_key=secret, https_only=True, same_site="lax", session_cookie="vibenest_app_session")
    app.include_router(create_auth_router(AuthSettings.from_env(source)))

    @app.get("/healthz", response_class=PlainTextResponse)
    async def healthz():
        return "Healthy"

    @app.get("/", response_class=HTMLResponse)
    async def index():
        return '<h1>VibeNest Auth reference</h1><a href="/auth/vibenest/login">Sign in with VibeNest</a>'

    return app


app = create_app()
