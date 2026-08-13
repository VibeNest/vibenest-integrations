import os

from fastapi import FastAPI, Request

from .project_payments import PaymentSettings, PaymentStore, create_payment_router


async def existing_application_identity(_request: Request) -> str | None:
    # Replace with the existing application's trusted server-side session adapter.
    return None


def create_app(env: dict[str, str] | None = None, identity_resolver=existing_application_identity) -> FastAPI:
    source = os.environ if env is None else env
    settings = PaymentSettings.from_env(source)
    store = PaymentStore(settings.store_path)
    app = FastAPI(title="VibeNest Project Payments reference")
    app.include_router(create_payment_router(settings, store, identity_resolver))
    app.state.project_payment_store = store
    return app


app = create_app()
