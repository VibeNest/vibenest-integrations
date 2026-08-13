import hashlib
import hmac
import json
import time

from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from app.project_payments import PaymentSettings, PaymentStore, create_payment_router


SECRET = "s" * 32
ENVIRONMENT = "sim_environment_reference"


def build(tmp_path):
    settings = PaymentSettings.from_env({
        "VIBENEST_PROJECT_PAYMENTS_ENABLED": "true",
        "VIBENEST_PROJECT_PAYMENTS_PROVIDER": "simulator",
        "VIBENEST_PROJECT_PAYMENTS_VERIFIER_ENABLED": "false",
        "VIBENEST_PROJECT_PAYMENTS_WEBHOOK_SECRET": SECRET,
        "VIBENEST_PROJECT_PAYMENTS_ENVIRONMENT_ID": ENVIRONMENT,
        "VIBENEST_PROJECT_PAYMENTS_MANIFEST_DIGEST": "d" * 64,
        "SOURCE_COMMIT": "c" * 40,
        "PROJECT_PAYMENT_FIXTURE_STORE": str(tmp_path / "payments.sqlite"),
    })
    store = PaymentStore(settings.store_path)

    async def identity(_request: Request):
        return "pairwise-subject"

    app = FastAPI()
    app.include_router(create_payment_router(settings, store, identity))
    return TestClient(app), store


def signature(body: bytes, timestamp: int) -> str:
    digest = hmac.new(SECRET.encode(), str(timestamp).encode() + b":" + body, hashlib.sha256).hexdigest()
    return f"ts={timestamp};h1={digest}"


def event():
    return {
        "event_id": "evt-fastapi-1",
        "event_type": "transaction.completed",
        "data": {
            "status": "completed",
            "customer_id": "sim_customer_" + hashlib.sha256(b"pairwise-subject").hexdigest()[:24],
            "items": [{"product_id": "pro", "price_id": "monthly", "quantity": 1}],
            "details": {"totals": {"total": "1500", "currency_code": "USD"}},
            "custom_data": {"vibenest_environment_id": ENVIRONMENT},
        },
    }


def test_checkout_uses_only_server_identity(tmp_path):
    client, _store = build(tmp_path)
    response = client.post("/api/project-payments/checkout", json={"priceKey": "monthly", "buyerKey": "attacker"})
    assert response.status_code == 400
    accepted = client.post("/api/project-payments/checkout", json={"priceKey": "monthly"})
    assert accepted.status_code == 200
    assert "pairwise-subject" not in accepted.text


def test_webhook_verifies_exact_body_and_is_idempotent(tmp_path):
    client, store = build(tmp_path)
    client.post("/api/project-payments/checkout", json={"priceKey": "monthly"})
    body = (json.dumps(event(), separators=(",", ":")) + "\n").encode()
    now = int(time.time())
    headers = {"Paddle-Signature": signature(body, now), "Content-Type": "application/json"}
    assert client.post("/webhooks/project-payments", content=body, headers=headers).status_code == 202
    assert client.post("/webhooks/project-payments", content=body, headers=headers).status_code == 202
    assert store.entitlement_quantity("pairwise-subject") == 1
    assert client.post("/webhooks/project-payments", content=body + b" ", headers=headers).status_code == 401
