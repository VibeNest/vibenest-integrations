import os

from fastapi import FastAPI, Request
from starlette.middleware.sessions import SessionMiddleware

from vibenest_auth import AuthSettings, create_auth_router
from project_payments import PaymentSettings, PaymentStore, create_payment_router


async def authenticated_subject(request: Request) -> str | None:
    user = request.session.get("user")
    return user.get("subject") if isinstance(user, dict) else None


def create_app(env: dict[str, str] | None = None) -> FastAPI:
    source = os.environ if env is None else env
    session_secret = source.get("APP_SESSION_SECRET", "")
    if len(session_secret) < 32:
        raise ValueError("APP_SESSION_SECRET must contain at least 32 characters")
    auth_settings = AuthSettings.from_env(source)
    payment_settings = PaymentSettings.from_env(source)
    store = PaymentStore(payment_settings.store_path)
    app = FastAPI(title="VibeNest Auth and Project Payments reference")
    app.add_middleware(SessionMiddleware, secret_key=session_secret, https_only=True, same_site="lax", session_cookie="vibenest_app_session")
    app.include_router(create_auth_router(auth_settings))
    app.include_router(create_payment_router(payment_settings, store, authenticated_subject))
    app.state.project_payment_store = store
    return app


app = create_app()
