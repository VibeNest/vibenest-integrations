from __future__ import annotations

import hashlib
import hmac
import json
import os
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Awaitable, Callable
from urllib.parse import quote

from fastapi import APIRouter, HTTPException, Request

MAX_WEBHOOK_BYTES = 128 * 1024
CATALOG = {
    "monthly": {"productKey": "pro", "currency": "USD", "unitAmount": 1500, "type": "recurring", "interval": "month"},
    "lifetime": {"productKey": "pro", "currency": "USD", "unitAmount": 9900, "type": "one_time", "interval": None},
}
IdentityResolver = Callable[[Request], Awaitable[str | None]]


@dataclass(frozen=True)
class PaymentSettings:
    enabled: bool
    provider: str
    verifier_enabled: bool
    webhook_secret: str
    environment_id: str
    manifest_digest: str
    source_commit: str
    store_path: str

    @classmethod
    def from_env(cls, env: dict[str, str] | None = None) -> "PaymentSettings":
        source = os.environ if env is None else env
        settings = cls(
            enabled=source.get("VIBENEST_PROJECT_PAYMENTS_ENABLED", "false").lower() == "true",
            provider=source.get("VIBENEST_PROJECT_PAYMENTS_PROVIDER", "disabled"),
            verifier_enabled=source.get("VIBENEST_PROJECT_PAYMENTS_VERIFIER_ENABLED", "false").lower() == "true",
            webhook_secret=source.get("VIBENEST_PROJECT_PAYMENTS_WEBHOOK_SECRET", ""),
            environment_id=source.get("VIBENEST_PROJECT_PAYMENTS_ENVIRONMENT_ID", ""),
            manifest_digest=source.get("VIBENEST_PROJECT_PAYMENTS_MANIFEST_DIGEST", ""),
            source_commit=source.get("SOURCE_COMMIT", ""),
            store_path=source.get("PROJECT_PAYMENT_FIXTURE_STORE", ".data/project-payments.sqlite"),
        )
        if settings.enabled and settings.provider != "simulator":
            raise ValueError("This reference permits only the simulator provider")
        if settings.enabled and len(settings.webhook_secret.encode()) < 32:
            raise ValueError("Webhook secret must contain at least 32 UTF-8 bytes")
        return settings


class PaymentStore:
    def __init__(self, path: str):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(path, check_same_thread=False)
        self.connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS customer_subjects(customer_id TEXT PRIMARY KEY, subject TEXT NOT NULL UNIQUE);
            CREATE TABLE IF NOT EXISTS webhook_inbox(event_id TEXT PRIMARY KEY, body_digest TEXT NOT NULL, received_at INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS entitlements(subject TEXT NOT NULL, entitlement TEXT NOT NULL, quantity INTEGER NOT NULL, PRIMARY KEY(subject, entitlement));
            """
        )

    def bind_customer(self, customer_id: str, subject: str) -> None:
        self.connection.execute("INSERT OR REPLACE INTO customer_subjects(customer_id, subject) VALUES (?, ?)", (customer_id, subject))
        self.connection.commit()

    def accept(self, event: dict, raw_body: bytes) -> bool:
        event_id = event.get("event_id")
        if not isinstance(event_id, str) or not event_id:
            raise ValueError("event_id is required")
        digest = hashlib.sha256(raw_body).hexdigest()
        try:
            self.connection.execute("INSERT INTO webhook_inbox(event_id, body_digest, received_at) VALUES (?, ?, ?)", (event_id, digest, int(time.time())))
        except sqlite3.IntegrityError:
            return False
        if event.get("event_type") == "transaction.completed":
            data = event.get("data") or {}
            environment = (data.get("custom_data") or {}).get("vibenest_environment_id")
            if environment is None:
                raise ValueError("environment binding is required")
            customer_id = data.get("customer_id")
            row = self.connection.execute("SELECT subject FROM customer_subjects WHERE customer_id = ?", (customer_id,)).fetchone()
            if row:
                self.connection.execute(
                    "INSERT INTO entitlements(subject, entitlement, quantity) VALUES (?, 'premium-access', 1) "
                    "ON CONFLICT(subject, entitlement) DO UPDATE SET quantity = excluded.quantity",
                    (row[0],),
                )
        self.connection.commit()
        return True

    def entitlement_quantity(self, subject: str) -> int:
        row = self.connection.execute("SELECT quantity FROM entitlements WHERE subject = ? AND entitlement = 'premium-access'", (subject,)).fetchone()
        return 0 if row is None else int(row[0])


def create_payment_router(settings: PaymentSettings, store: PaymentStore, resolve_identity: IdentityResolver) -> APIRouter:
    router = APIRouter()

    def ensure_enabled():
        if not settings.enabled or settings.provider != "simulator":
            raise HTTPException(404)

    async def subject(request: Request) -> str:
        value = await resolve_identity(request)
        if not value:
            raise HTTPException(401, "Authentication required")
        return value

    @router.get("/api/project-payments/prices")
    async def prices():
        ensure_enabled()
        return {"provider": "simulator", "prices": CATALOG}

    @router.post("/api/project-payments/checkout")
    async def checkout(request: Request):
        ensure_enabled()
        buyer = await subject(request)
        body = await request.json()
        if set(body) != {"priceKey"} or body["priceKey"] not in CATALOG:
            raise HTTPException(400, "Use one trusted catalog priceKey")
        customer_id = customer_id_for_subject(buyer)
        store.bind_customer(customer_id, buyer)
        return {"url": f"https://simulator.invalid/checkout/{quote(settings.environment_id)}/{quote(customer_id)}/{quote(body['priceKey'])}"}

    @router.post("/api/project-payments/portal")
    async def portal(request: Request):
        ensure_enabled()
        buyer = await subject(request)
        customer_id = customer_id_for_subject(buyer)
        store.bind_customer(customer_id, buyer)
        return {"url": f"https://simulator.invalid/portal/{quote(settings.environment_id)}/{quote(customer_id)}"}

    @router.post("/webhooks/project-payments", status_code=202)
    async def webhook(request: Request):
        ensure_enabled()
        if request.headers.get("content-encoding"):
            raise HTTPException(415, "Compressed webhooks are not accepted")
        raw_body = await request.body()
        if len(raw_body) > MAX_WEBHOOK_BYTES:
            raise HTTPException(413)
        verify_signature(raw_body, request.headers.get("paddle-signature", ""), settings.webhook_secret)
        try:
            event = json.loads(raw_body)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise HTTPException(400, "Webhook must be UTF-8 JSON") from error
        environment = ((event.get("data") or {}).get("custom_data") or {}).get("vibenest_environment_id")
        if environment != settings.environment_id:
            raise HTTPException(400, "Webhook environment mismatch")
        validate_event(event)
        store.accept(event, raw_body)
        return {"accepted": True}

    @router.get("/.well-known/vibenest/project-payments/verifier")
    async def verifier(request: Request):
        ensure_enabled()
        if not settings.verifier_enabled:
            raise HTTPException(404)
        supplied = request.headers.get("x-vibenest-simulator-secret", "")
        if not hmac.compare_digest(supplied, settings.webhook_secret):
            raise HTTPException(404)
        return {"provider": "simulator", "environmentId": settings.environment_id, "manifestDigest": settings.manifest_digest, "builtCommit": settings.source_commit}

    return router


def verify_signature(raw_body: bytes, header: str, secret: str, now: int | None = None) -> None:
    parts = dict(part.split("=", 1) for part in header.split(";") if "=" in part)
    try:
        timestamp = int(parts["ts"])
    except (KeyError, ValueError) as error:
        raise HTTPException(401, "Invalid webhook signature") from error
    if abs((int(time.time()) if now is None else now) - timestamp) > 300:
        raise HTTPException(401, "Expired webhook signature")
    expected = hmac.new(secret.encode(), str(timestamp).encode() + b":" + raw_body, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, parts.get("h1", "")):
        raise HTTPException(401, "Invalid webhook signature")


def customer_id_for_subject(subject: str) -> str:
    return "sim_customer_" + hashlib.sha256(subject.encode()).hexdigest()[:24]


def validate_event(event: dict) -> None:
    if event.get("event_type") != "transaction.completed":
        return
    data = event.get("data") or {}
    items = data.get("items")
    if data.get("status") != "completed" or not isinstance(items, list) or len(items) != 1:
        raise HTTPException(400, "Invalid completed transaction")
    item = items[0]
    price_key = item.get("price_id")
    price = CATALOG.get(price_key)
    totals = (data.get("details") or {}).get("totals") or {}
    if (
        price is None
        or item.get("product_id") != price["productKey"]
        or item.get("quantity") != 1
        or totals.get("total") != str(price["unitAmount"])
        or totals.get("currency_code") != price["currency"]
    ):
        raise HTTPException(400, "Transaction does not match the trusted catalog")
