import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import {
  DisabledProjectPaymentProvider,
  InvalidSimulatorEventError,
  InvalidSimulatorSignatureError,
  ProjectPaymentSqliteStore,
  SimulatorProjectPaymentProvider,
  acceptSignedEvent,
  buildVerifierPayload,
  computeRuntimeEvidenceScope,
  fixtureSessionCookie,
  openProjectPaymentRuntime,
  parseRuntimeCatalog,
  providerModes,
  requiredLifecycleEvidence,
  signEvent,
  verifyEventSignature
} from "../lib/project-payments.js";
import { POST as checkoutPost } from "../app/api/project-payments/checkout/route.js";
import { POST as portalPost } from "../app/api/project-payments/portal/route.js";
import { POST as pricesPost } from "../app/api/project-payments/prices/route.js";
import { POST as webhookPost } from "../app/api/project-payments/webhook/route.js";
import {
  GET as verifierGet,
  HEAD as verifierHead
} from "../app/.well-known/vibenest/project-payments/verifier/route.js";
import {
  GET as harnessGet,
  POST as harnessPost
} from "../app/.well-known/vibenest/project-payments/harness/route.js";

const environmentId = "sim_env_fixture";
const manifestDigest = "b".repeat(64);
const commitSha = "a".repeat(40);
const secret = "fixture-webhook-secret-32-bytes-minimum";

test("runtime catalog is canonical, environment-bound, complete, and provider ids stay server-only", () => {
  const projection = runtimeCatalogProjection();
  const catalog = parseRuntimeCatalog(encodeRuntimeCatalog(projection), {
    expectedEnvironmentId: environmentId,
    expectedManifestDigest: manifestDigest
  });
  assert.equal(catalog.products.pro.prices.monthly.providerPriceId, "sim_price_monthly_fixture");
  assert.deepEqual(catalog.products.pro.grants, [{ entitlement: "premium-access", quantity: 1 }]);
  const snakeGrant = structuredClone(projection);
  snakeGrant.products[0].grants = [{ entitlement: "team_exports", quantity: 3 }];
  assert.deepEqual(
    parseRuntimeCatalog(encodeRuntimeCatalog(snakeGrant), runtimeCatalogExpectation()).products.pro.grants,
    [{ entitlement: "team_exports", quantity: 3 }]
  );

  assert.throws(() => parseRuntimeCatalog(`${encodeRuntimeCatalog(projection)}\n`, runtimeCatalogExpectation()), /base64/);
  assert.throws(() => parseRuntimeCatalog(encodeRuntimeCatalog({ ...projection, environmentExternalId: "sim_env_other" }), runtimeCatalogExpectation()), /environment/);
  assert.throws(() => parseRuntimeCatalog(encodeRuntimeCatalog({ ...projection, manifestDigest: "c".repeat(64) }), runtimeCatalogExpectation()), /digest/);
  assert.throws(() => parseRuntimeCatalog(encodeRuntimeCatalog({
    ...projection,
    products: [{ ...projection.products[0], grants: [{ entitlement: "premium-access", quantity: 0 }] }]
  }), runtimeCatalogExpectation()), /quantity/);
  assert.throws(() => parseRuntimeCatalog(encodeRuntimeCatalog({
    ...projection,
    products: [{ ...projection.products[0], unexpected: true }]
  }), runtimeCatalogExpectation()), /unexpected/);
});

test("raw Buffer HMAC, strict gateway mapping, durable dedupe, and restart replay are fail-closed", async context => {
  const fixture = await temporaryDatabase(context, "raw");
  const receiver = new ProjectPaymentSqliteStore(fixture.databasePath, { instanceId: "raw-receiver" });
  context.after(() => receiver.close());
  const catalog = trustedCatalog();
  const provider = new SimulatorProjectPaymentProvider({ catalog, store: receiver });
  await provider.createCheckout({ buyerKey: "buyer-once", priceKey: "lifetime" });
  const occurredAt = new Date();
  const payload = transactionEvent({
    eventId: "sim_evt_raw",
    occurredAt: occurredAt.toISOString(),
    customerId: "buyer-once",
    priceKey: "lifetime"
  });
  const rawBody = Buffer.from(`${JSON.stringify(payload, null, 2)}\n`, "utf8");
  const timestamp = Math.floor(occurredAt.getTime() / 1_000);
  const signature = signEvent(rawBody, secret, timestamp);

  assert.equal(verifyEventSignature(rawBody, signature, secret, timestamp), true);
  assert.equal(verifyEventSignature(Buffer.concat([rawBody, Buffer.from(" ")]), signature, secret, timestamp), false);
  assert.equal((await deliver(receiver, payload, { rawBody, signature, timestamp, catalog })).inserted, true);
  assert.equal((await deliver(receiver, payload, { rawBody, signature, timestamp, catalog })).inserted, false);
  assert.equal(receiver.snapshot().events[0].delivery_count, 2);

  const tampered = Buffer.concat([rawBody, Buffer.from(" ")]);
  await assert.rejects(deliver(receiver, payload, { rawBody: tampered, signature, timestamp, catalog }), InvalidSimulatorSignatureError);
  const forged = structuredClone(payload);
  forged.event_id = "sim_evt_forged";
  forged.data.items[0].price_id = "sim_price_attacker";
  await assert.rejects(deliver(receiver, forged, { catalog }), InvalidSimulatorEventError);
  const buyerForged = structuredClone(payload);
  buyerForged.event_id = "sim_evt_buyer_forged";
  buyerForged.data.customer_id = "attacker";
  await assert.rejects(deliver(receiver, buyerForged, { catalog }), /not bound/);

  const recoveredRuntime = openProjectPaymentRuntime(enabledEnvironment({
    PROJECT_PAYMENT_DATABASE_PATH: fixture.databasePath
  }), { storeOptions: { instanceId: "raw-processor" } });
  const processor = recoveredRuntime.store;
  context.after(() => recoveredRuntime.close());
  context.after(() => rm(fixture.directory, { recursive: true, force: true }));
  assert.equal(processor.hasEntitlement("buyer-once", "premium-access"), true);
  assert.equal(processor.verificationStatus().restartReplayPassed, true);
  assert.equal(processor.snapshot().events[0].body_sha256, createHash("sha256").update(rawBody).digest("hex"));
});

test("conditional leases recover after expiration and local failures back off into dead-letter", async context => {
  const fixture = await temporaryDatabase(context, "leases");
  const receivedAt = new Date();
  const receiver = new ProjectPaymentSqliteStore(fixture.databasePath, {
    instanceId: "lease-receiver",
    leaseSeconds: 2,
    maxAttempts: 2,
    baseBackoffSeconds: 1
  });
  context.after(() => receiver.close());
  receiver.bindCustomer("buyer-lease", "buyer-lease");
  const payload = subscriptionEvent({
    eventId: "sim_evt_missing_prior",
    eventType: "subscription.updated",
    occurredAt: receivedAt.toISOString(),
    customerId: "buyer-lease",
    subscriptionId: "sim_sub_missing_prior",
    period: billingPeriod(receivedAt)
  });
  await deliver(receiver, payload);

  const workerA = new ProjectPaymentSqliteStore(fixture.databasePath, {
    instanceId: "lease-worker-a",
    leaseSeconds: 2,
    maxAttempts: 2,
    baseBackoffSeconds: 1
  });
  const workerB = new ProjectPaymentSqliteStore(fixture.databasePath, {
    instanceId: "lease-worker-b",
    leaseSeconds: 2,
    maxAttempts: 2,
    baseBackoffSeconds: 1
  });
  context.after(() => workerA.close());
  context.after(() => workerB.close());
  context.after(() => rm(fixture.directory, { recursive: true, force: true }));
  const claimAt = new Date(Date.now() + 100);
  assert.ok(workerA.claimDue(claimAt));
  assert.equal(workerB.claimDue(new Date(claimAt.getTime() + 1_000)), null);

  const firstRetry = workerB.processDue({ now: new Date(claimAt.getTime() + 2_100) });
  assert.equal(firstRetry.deferred, 1);
  assert.equal(workerB.snapshot().events[0].attempt_count, 2);
  assert.ok(workerB.snapshot().events[0].dead_lettered_at);
  assert.equal(workerB.snapshot().events[0].last_error, "A referenced projection is not available yet.");
});

test("full signed lifecycle advances authoritative periods once and derives evidence exactly once", async context => {
  const fixture = await temporaryDatabase(context, "lifecycle");
  const receiving = new ProjectPaymentSqliteStore(fixture.databasePath, {
    instanceId: "lifecycle-receiver",
    evidenceScope: runtimeEvidenceScope()
  });
  context.after(() => receiving.close());
  const catalog = trustedCatalog();
  const provider = new SimulatorProjectPaymentProvider({ catalog, store: receiving });
  await provider.previewPrices(["monthly", "lifetime"]);
  for (const buyer of ["buyer-once", "buyer-sub", "buyer-declined", "buyer-out"])
    await provider.createCheckout({ buyerKey: buyer, priceKey: buyer === "buyer-once" ? "lifetime" : "monthly" });
  await provider.createPortal("buyer-sub");

  const base = new Date();
  base.setUTCMilliseconds(0);
  const firstPeriod = billingPeriod(base);
  const secondPeriod = billingPeriod(new Date(Date.parse(firstPeriod.ends_at)));
  const subscriptionId = "sim_sub_lifecycle";
  const transactionId = "sim_txn_subscription";

  await deliver(receiving, transactionEvent({
    eventId: "sim_evt_once",
    occurredAt: base.toISOString(),
    customerId: "buyer-once",
    priceKey: "lifetime"
  }));
  await deliver(receiving, subscriptionEvent({
    eventId: "sim_evt_sub_created",
    eventType: "subscription.created",
    occurredAt: new Date(base.getTime() + 1_000).toISOString(),
    customerId: "buyer-sub",
    subscriptionId,
    period: firstPeriod
  }));
  await deliver(receiving, transactionEvent({
    eventId: "sim_evt_sub_transaction",
    occurredAt: new Date(base.getTime() + 1_001).toISOString(),
    customerId: "buyer-sub",
    priceKey: "monthly",
    subscriptionId,
    transactionId,
    period: firstPeriod
  }));
  await deliver(receiving, transactionEvent({
    eventId: "sim_evt_declined",
    eventType: "transaction.payment_failed",
    occurredAt: new Date(base.getTime() + 2_000).toISOString(),
    customerId: "buyer-declined",
    priceKey: "monthly",
    status: "declined",
    period: firstPeriod
  }));

  const processor = new ProjectPaymentSqliteStore(fixture.databasePath, {
    instanceId: "lifecycle-processor",
    evidenceScope: runtimeEvidenceScope()
  });
  context.after(() => processor.close());
  context.after(() => rm(fixture.directory, { recursive: true, force: true }));
  assert.equal(processor.processDue().failed, 0);

  await deliver(receiving, subscriptionEvent({
    eventId: "sim_evt_renewal",
    eventType: "subscription.updated",
    occurredAt: new Date(base.getTime() + 3_000).toISOString(),
    customerId: "buyer-sub",
    subscriptionId,
    period: secondPeriod
  }));
  await deliver(receiving, transactionEvent({
    eventId: "sim_evt_renewal_transaction",
    occurredAt: new Date(base.getTime() + 3_001).toISOString(),
    customerId: "buyer-sub",
    priceKey: "monthly",
    subscriptionId,
    transactionId: "sim_txn_renewal",
    period: secondPeriod
  }));
  assert.equal(processor.processDue().failed, 0);

  await deliver(receiving, subscriptionEvent({
    eventId: "sim_evt_scheduled",
    eventType: "subscription.updated",
    occurredAt: new Date(base.getTime() + 4_000).toISOString(),
    customerId: "buyer-sub",
    subscriptionId,
    period: secondPeriod,
    scheduledAt: secondPeriod.ends_at
  }));
  assert.equal(processor.processDue().failed, 0);
  assert.equal(processor.hasEntitlement("buyer-sub", "premium-access", new Date(Date.parse(secondPeriod.ends_at) - 1)), true);

  await deliver(receiving, adjustmentEvent({
    eventId: "sim_evt_adjustment_pending",
    eventType: "adjustment.created",
    occurredAt: new Date(base.getTime() + 5_000).toISOString(),
    transactionId: "sim_txn_renewal",
    status: "pending_approval"
  }));
  await deliver(receiving, adjustmentEvent({
    eventId: "sim_evt_adjustment_approved",
    eventType: "adjustment.updated",
    occurredAt: new Date(base.getTime() + 5_001).toISOString(),
    transactionId: "sim_txn_renewal",
    status: "approved"
  }));
  await deliver(receiving, subscriptionEvent({
    eventId: "sim_evt_canceled",
    eventType: "subscription.canceled",
    occurredAt: new Date(base.getTime() + 5_002).toISOString(),
    customerId: "buyer-sub",
    subscriptionId,
    status: "canceled",
    period: secondPeriod
  }));

  const duplicate = transactionEvent({
    eventId: "sim_evt_duplicate",
    occurredAt: new Date(base.getTime() + 6_000).toISOString(),
    customerId: "buyer-once",
    priceKey: "lifetime",
    transactionId: "sim_txn_duplicate"
  });
  await deliver(receiving, duplicate);
  await deliver(receiving, duplicate);

  const outPeriod = billingPeriod(new Date(base.getTime() + 7_000));
  const outSubscription = subscriptionEvent({
    eventId: "sim_evt_out_subscription",
    eventType: "subscription.created",
    occurredAt: new Date(base.getTime() + 7_000).toISOString(),
    customerId: "buyer-out",
    subscriptionId: "sim_sub_out",
    period: outPeriod
  });
  const outTransaction = transactionEvent({
    eventId: "sim_evt_out_transaction",
    occurredAt: new Date(base.getTime() + 7_002).toISOString(),
    customerId: "buyer-out",
    priceKey: "monthly",
    subscriptionId: "sim_sub_out",
    transactionId: "sim_txn_out",
    period: outPeriod
  });
  await deliver(receiving, outTransaction);
  await deliver(receiving, outSubscription);
  await deliver(receiving, portalEvent({
    eventId: "sim_evt_portal",
    occurredAt: new Date(base.getTime() + 8_000).toISOString(),
    customerId: "buyer-sub"
  }));

  const finalResult = processor.processDue();
  assert.equal(finalResult.failed, 0);
  assert.equal(processor.hasEntitlement("buyer-sub", "premium-access"), false);
  const snapshot = processor.snapshot();
  const subscriptionEntitlement = snapshot.entitlements.find(row => row.subject_key === "buyer-sub");
  assert.equal(subscriptionEntitlement.renewal_count, 1);
  assert.equal(subscriptionEntitlement.status, "revoked");
  assert.equal(snapshot.evidence.filter(row => row.name === "duplicate-delivery").length, 1);
  assert.deepEqual(
    snapshot.evidence.filter(row => requiredLifecycleEvidence.includes(row.name)).map(row => row.name).sort(),
    [...requiredLifecycleEvidence].sort()
  );

  const verifier = await buildVerifierPayload(verifierInput(processor));
  assert.deepEqual(verifier, {
    provider: "simulator",
    paymentsEnabled: true,
    verifierEnabled: true,
    commitSha,
    manifestDigest,
    lifecyclePassed: true,
    durableInbox: true,
    restartReplayPassed: true
  });
  assert.equal(await buildVerifierPayload({
    ...verifierInput(processor),
    expectedManifestDigest: "c".repeat(64),
    installedManifestDigest: "c".repeat(64)
  }), null);
  assert.equal(await buildVerifierPayload({
    ...verifierInput(processor),
    expectedCommit: "c".repeat(40),
    builtCommit: "c".repeat(40)
  }), null);
  assert.equal(await buildVerifierPayload({
    ...verifierInput(processor),
    environmentId: "sim_env_other"
  }), null);
});

test("discontinuous signed renewal is retained for retry and cannot regress access", async context => {
  const fixture = await temporaryDatabase(context, "continuity");
  const store = new ProjectPaymentSqliteStore(fixture.databasePath, {
    instanceId: "continuity",
    baseBackoffSeconds: 1
  });
  context.after(() => store.close());
  context.after(() => rm(fixture.directory, { recursive: true, force: true }));
  store.bindCustomer("buyer-continuity", "buyer-continuity");
  const base = new Date();
  base.setUTCMilliseconds(0);
  const initial = billingPeriod(base);
  await deliver(store, subscriptionEvent({
    eventId: "sim_evt_continuity_initial",
    eventType: "subscription.created",
    occurredAt: base.toISOString(),
    customerId: "buyer-continuity",
    subscriptionId: "sim_sub_continuity",
    period: initial
  }));
  assert.equal(store.processDue().failed, 0);

  const gapStart = new Date(Date.parse(initial.ends_at) + 24 * 60 * 60_000);
  await deliver(store, subscriptionEvent({
    eventId: "sim_evt_continuity_gap",
    eventType: "subscription.updated",
    occurredAt: new Date(base.getTime() + 1_000).toISOString(),
    customerId: "buyer-continuity",
    subscriptionId: "sim_sub_continuity",
    period: billingPeriod(gapStart)
  }));
  const result = store.processDue();
  assert.equal(result.failed, 1);
  const snapshot = store.snapshot();
  assert.equal(snapshot.subscriptions[0].billing_period_end, initial.ends_at);
  assert.equal(snapshot.events.find(row => row.provider_event_id === "sim_evt_continuity_gap").processed_at, null);
});

test("independent lifetime and subscription contributions cannot revoke each other", async context => {
  const fixture = await temporaryDatabase(context, "contributions");
  const store = new ProjectPaymentSqliteStore(fixture.databasePath, {
    instanceId: "contributions",
    evidenceScope: runtimeEvidenceScope()
  });
  context.after(() => store.close());
  context.after(() => rm(fixture.directory, { recursive: true, force: true }));
  store.bindCustomer("buyer-combined", "buyer-combined");
  const base = new Date();
  base.setUTCMilliseconds(0);
  const period = billingPeriod(base);
  await deliver(store, transactionEvent({
    eventId: "sim_evt_combined_lifetime",
    occurredAt: base.toISOString(),
    customerId: "buyer-combined",
    priceKey: "lifetime",
    transactionId: "sim_txn_combined_lifetime"
  }));
  await deliver(store, subscriptionEvent({
    eventId: "sim_evt_combined_subscription",
    eventType: "subscription.created",
    occurredAt: new Date(base.getTime() + 1_000).toISOString(),
    customerId: "buyer-combined",
    subscriptionId: "sim_sub_combined",
    period
  }));
  await deliver(store, transactionEvent({
    eventId: "sim_evt_combined_monthly_transaction",
    occurredAt: new Date(base.getTime() + 1_001).toISOString(),
    customerId: "buyer-combined",
    priceKey: "monthly",
    subscriptionId: "sim_sub_combined",
    transactionId: "sim_txn_combined_monthly",
    period
  }));
  assert.equal(store.processDue().failed, 0);

  await deliver(store, adjustmentEvent({
    eventId: "sim_evt_combined_refund",
    eventType: "adjustment.updated",
    occurredAt: new Date(base.getTime() + 2_000).toISOString(),
    transactionId: "sim_txn_combined_monthly",
    status: "approved"
  }));
  assert.equal(store.processDue().failed, 0);
  await deliver(store, transactionEvent({
    eventId: "sim_evt_combined_pre_cancel_resurrection",
    occurredAt: new Date(base.getTime() + 2_001).toISOString(),
    customerId: "buyer-combined",
    priceKey: "monthly",
    subscriptionId: "sim_sub_combined",
    transactionId: "sim_txn_combined_pre_cancel_resurrection",
    period
  }));
  assert.equal(store.processDue().failed, 1);
  await deliver(store, subscriptionEvent({
    eventId: "sim_evt_combined_canceled",
    eventType: "subscription.canceled",
    occurredAt: new Date(base.getTime() + 2_002).toISOString(),
    customerId: "buyer-combined",
    subscriptionId: "sim_sub_combined",
    status: "canceled",
    period
  }));
  assert.equal(store.processDue().failed, 0);
  await deliver(store, transactionEvent({
    eventId: "sim_evt_combined_resurrection",
    occurredAt: new Date(base.getTime() + 3_000).toISOString(),
    customerId: "buyer-combined",
    priceKey: "monthly",
    subscriptionId: "sim_sub_combined",
    transactionId: "sim_txn_combined_resurrection",
    period
  }));
  assert.equal(store.processDue().failed, 1);
  assert.equal(store.hasEntitlement("buyer-combined", "premium-access"), true);
  const snapshot = store.snapshot();
  assert.equal(snapshot.entitlements[0].status, "active");
  assert.equal(snapshot.entitlements[0].effective_until, null);
  assert.deepEqual(
    snapshot.entitlementSources.map(row => [row.source_key, row.status]).sort(),
    [
      ["subscription:sim_sub_combined", "revoked"],
      ["transaction:sim_txn_combined_lifetime", "active"]
    ]
  );
  assert.equal(
    snapshot.events.find(row => row.provider_event_id === "sim_evt_combined_resurrection").processed_at,
    null
  );
  assert.equal(
    snapshot.events.find(row => row.provider_event_id === "sim_evt_combined_pre_cancel_resurrection").processed_at,
    null
  );
});

test("provider subscription and transaction ids cannot move across bound buyers", async context => {
  const fixture = await temporaryDatabase(context, "immutable-identity");
  const store = new ProjectPaymentSqliteStore(fixture.databasePath, {
    instanceId: "immutable-identity",
    baseBackoffSeconds: 1
  });
  context.after(() => store.close());
  context.after(() => rm(fixture.directory, { recursive: true, force: true }));
  store.bindCustomer("buyer-owner", "buyer-owner");
  store.bindCustomer("buyer-attacker", "buyer-attacker");
  const base = new Date();
  base.setUTCMilliseconds(0);
  const firstPeriod = billingPeriod(base);
  await deliver(store, subscriptionEvent({
    eventId: "sim_evt_identity_created",
    eventType: "subscription.created",
    occurredAt: base.toISOString(),
    customerId: "buyer-owner",
    subscriptionId: "sim_sub_immutable",
    period: firstPeriod
  }));
  await deliver(store, transactionEvent({
    eventId: "sim_evt_identity_transaction",
    occurredAt: new Date(base.getTime() + 1).toISOString(),
    customerId: "buyer-owner",
    priceKey: "lifetime",
    transactionId: "sim_txn_immutable"
  }));
  assert.equal(store.processDue().failed, 0);

  await deliver(store, subscriptionEvent({
    eventId: "sim_evt_identity_stolen_subscription",
    eventType: "subscription.updated",
    occurredAt: new Date(base.getTime() + 1_000).toISOString(),
    customerId: "buyer-attacker",
    subscriptionId: "sim_sub_immutable",
    period: billingPeriod(new Date(Date.parse(firstPeriod.ends_at)))
  }));
  await deliver(store, transactionEvent({
    eventId: "sim_evt_identity_stolen_transaction",
    occurredAt: new Date(base.getTime() + 1_001).toISOString(),
    customerId: "buyer-attacker",
    priceKey: "lifetime",
    transactionId: "sim_txn_immutable"
  }));
  const failures = store.processDue();
  assert.equal(failures.failed, 2);
  assert.equal(store.hasEntitlement("buyer-owner", "premium-access"), true);
  assert.equal(store.hasEntitlement("buyer-attacker", "premium-access"), false);
  assert.equal(store.snapshot().events.filter(row => row.last_error !== null).length, 2);

  const outOfOrderPeriod = billingPeriod(new Date(base.getTime() + 2_000));
  await deliver(store, transactionEvent({
    eventId: "sim_evt_identity_transaction_first",
    occurredAt: new Date(base.getTime() + 2_002).toISOString(),
    customerId: "buyer-owner",
    priceKey: "monthly",
    subscriptionId: "sim_sub_transaction_first",
    transactionId: "sim_txn_transaction_first",
    period: outOfOrderPeriod
  }));
  assert.equal(store.processDue().failed, 0);
  await deliver(store, subscriptionEvent({
    eventId: "sim_evt_identity_subscription_second",
    eventType: "subscription.created",
    occurredAt: new Date(base.getTime() + 2_000).toISOString(),
    customerId: "buyer-attacker",
    subscriptionId: "sim_sub_transaction_first",
    period: outOfOrderPeriod
  }));
  assert.equal(store.processDue().failed, 1);
  assert.equal(store.hasEntitlement("buyer-attacker", "premium-access"), false);
});

test("route handlers use opaque server sessions and never trust buyer fields", async context => {
  const fixture = await temporaryDatabase(context, "routes");
  const environment = enabledEnvironment({ PROJECT_PAYMENT_DATABASE_PATH: fixture.databasePath });
  const restore = installEnvironment(environment);
  context.after(restore);
  context.after(() => rm(fixture.directory, { recursive: true, force: true }));
  const setup = openProjectPaymentRuntime(process.env);
  const token = setup.store.createFixtureSession("server-session-buyer");
  setup.close();
  const cookie = fixtureSessionCookie(token).split(";", 1)[0];

  const anonymous = await checkoutPost(new Request("https://fixture.invalid/api/project-payments/checkout", {
    method: "POST",
    body: JSON.stringify({ priceKey: "monthly" })
  }));
  assert.equal(anonymous.status, 401);

  const forged = await checkoutPost(new Request("https://fixture.invalid/api/project-payments/checkout", {
    method: "POST",
    headers: { cookie },
    body: JSON.stringify({ priceKey: "monthly", buyerKey: "attacker" })
  }));
  assert.equal(forged.status, 400);

  const checkout = await checkoutPost(new Request("https://fixture.invalid/api/project-payments/checkout", {
    method: "POST",
    headers: { cookie },
    body: JSON.stringify({ priceKey: "monthly" })
  }));
  assert.equal(checkout.status, 200);
  const checkoutBody = await checkout.json();
  assert.match(checkoutBody.checkoutUrl, /^https:\/\/simulator\.invalid\/checkout\//);
  assert.doesNotMatch(JSON.stringify(checkoutBody), /sim_price_monthly_fixture|sim_prod_fixture/);

  const prices = await pricesPost(new Request("https://fixture.invalid/api/project-payments/prices", {
    method: "POST",
    headers: { cookie },
    body: JSON.stringify({ priceKeys: ["monthly", "lifetime"] })
  }));
  assert.equal(prices.status, 200);
  assert.equal((await prices.json()).prices[0].unitAmount, 1500);

  const portal = await portalPost(new Request("https://fixture.invalid/api/project-payments/portal", {
    method: "POST",
    headers: { cookie },
    body: "{}"
  }));
  assert.equal(portal.status, 200);
  assert.match((await portal.json()).url, /server-session-buyer/);

  const occurredAt = new Date();
  const signedPayload = transactionEvent({
    eventId: "sim_evt_route_raw",
    occurredAt: occurredAt.toISOString(),
    customerId: "server-session-buyer",
    priceKey: "lifetime"
  });
  const rawBody = Buffer.from(`${JSON.stringify(signedPayload, null, 2)}\n`, "utf8");
  const timestamp = Math.floor(occurredAt.getTime() / 1_000);
  const signature = signEvent(rawBody, secret, timestamp);
  const accepted = await webhookPost(new Request("https://fixture.invalid/api/project-payments/webhook", {
    method: "POST",
    headers: { "Paddle-Signature": signature, "Content-Type": "application/json" },
    body: rawBody
  }));
  assert.equal(accepted.status, 202);
  const tampered = await webhookPost(new Request("https://fixture.invalid/api/project-payments/webhook", {
    method: "POST",
    headers: { "Paddle-Signature": signature, "Content-Type": "application/json" },
    body: Buffer.concat([rawBody, Buffer.from(" ")])
  }));
  assert.equal(tampered.status, 401);
  const oversized = Buffer.alloc(256 * 1024 + 1, 0x20);
  const rejectedOversized = await webhookPost(new Request("https://fixture.invalid/api/project-payments/webhook", {
    method: "POST",
    headers: { "Paddle-Signature": signature, "Content-Type": "application/json" },
    body: oversized
  }));
  assert.equal(rejectedOversized.status, 400);

  const evidence = openProjectPaymentRuntime(process.env);
  assert.equal(evidence.store.hasEntitlement("server-session-buyer", "premium-access"), true);
  assert.equal(evidence.store.verificationStatus().restartReplayPassed, false);
  evidence.close();
});

test("verifier requires SOURCE_COMMIT-shaped build evidence, exact challenges, and earned DB evidence", async context => {
  const fixture = await temporaryDatabase(context, "verifier");
  const store = new ProjectPaymentSqliteStore(fixture.databasePath, { instanceId: "verifier" });
  context.after(() => store.close());
  context.after(() => rm(fixture.directory, { recursive: true, force: true }));
  const incomplete = verifierInput(store);
  assert.equal(await buildVerifierPayload(incomplete), null);
  assert.equal(await buildVerifierPayload({ ...incomplete, builtCommit: undefined }), null);
  assert.equal(await buildVerifierPayload({ ...incomplete, expectedCommit: "c".repeat(40) }), null);
  assert.equal(await buildVerifierPayload({ ...incomplete, provider: providerModes.disabled }), null);
  assert.equal(await buildVerifierPayload({ ...incomplete, suppliedSecret: "short", configuredSecret: "short" }), null);

  const restore = installEnvironment(enabledEnvironment({ PROJECT_PAYMENT_DATABASE_PATH: fixture.databasePath }));
  context.after(restore);
  const verifierRequest = new Request("https://fixture.invalid/.well-known/vibenest/project-payments/verifier", {
    headers: {
      "X-VibeNest-Simulator-Secret": secret,
      "X-VibeNest-Expected-Commit": commitSha,
      "X-VibeNest-Expected-Manifest-Digest": manifestDigest
    }
  });
  assert.equal((await verifierGet(verifierRequest)).status, 404);
  assert.equal((await verifierHead(verifierRequest)).status, 405);
  process.env.VIBENEST_PROJECT_PAYMENTS_ENABLED = "false";
  process.env.VIBENEST_PROJECT_PAYMENTS_PROVIDER = "disabled";
  assert.equal((await verifierGet(verifierRequest)).status, 404);
});

test("protected restart harness stages a durable no-op that only a new runtime instance can claim", async context => {
  const fixture = await temporaryDatabase(context, "restart-harness");
  context.after(() => rm(fixture.directory, { recursive: true, force: true }));
  const beforeRestart = new ProjectPaymentSqliteStore(fixture.databasePath, {
    instanceId: "harness-before-restart",
    evidenceScope: runtimeEvidenceScope()
  });
  assert.deepEqual(beforeRestart.stageRestartReplayProbe(environmentId), {
    action: "restart-replay",
    state: "staged"
  });
  assert.deepEqual(beforeRestart.processDue(), {
    applied: 0,
    ignored: 0,
    deferred: 0,
    failed: 0,
    deadLettered: 0
  });
  assert.equal(beforeRestart.snapshot().events[0].processed_at, null);
  beforeRestart.close();

  const afterRestart = new ProjectPaymentSqliteStore(fixture.databasePath, {
    instanceId: "harness-after-restart",
    evidenceScope: runtimeEvidenceScope()
  });
  assert.equal(afterRestart.processDue().applied, 1);
  assert.equal(afterRestart.snapshot().events[0].processed_by_instance_id, "harness-after-restart");
  assert.equal(afterRestart.verificationStatus().restartReplayPassed, true);
  afterRestart.close();

  const routeFixture = await temporaryDatabase(context, "restart-harness-route");
  context.after(() => rm(routeFixture.directory, { recursive: true, force: true }));
  const restore = installEnvironment(enabledEnvironment({ PROJECT_PAYMENT_DATABASE_PATH: routeFixture.databasePath }));
  context.after(restore);
  const endpoint = "https://fixture.invalid/.well-known/vibenest/project-payments/harness";
  const request = (body, suppliedSecret = secret) => new Request(endpoint, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-VibeNest-Simulator-Secret": suppliedSecret,
      "X-VibeNest-Expected-Commit": commitSha,
      "X-VibeNest-Expected-Manifest-Digest": manifestDigest
    },
    body
  });
  assert.equal((await harnessPost(request('{"action":"restart-replay"}', "x".repeat(32)))).status, 404);
  const wrongCommit = request('{"action":"restart-replay"}');
  wrongCommit.headers.set("X-VibeNest-Expected-Commit", "c".repeat(40));
  assert.equal((await harnessPost(wrongCommit)).status, 404);
  assert.equal((await harnessPost(request('{"action":"unsupported"}'))).status, 400);
  assert.equal((await harnessPost(request(JSON.stringify({ action: "restart-replay", extra: true })))).status, 400);
  assert.equal((await harnessPost(request(`{"action":"restart-replay","padding":"${"x".repeat(1100)}"}`))).status, 413);
  const staged = await harnessPost(request('{"action":"restart-replay"}'));
  assert.equal(staged.status, 202);
  assert.deepEqual(await staged.json(), { action: "restart-replay", state: "staged" });
  assert.equal((await harnessGet(new Request(endpoint))).status, 405);
  process.env.VIBENEST_PROJECT_PAYMENTS_ENABLED = "false";
  process.env.VIBENEST_PROJECT_PAYMENTS_PROVIDER = "disabled";
  assert.equal((await harnessPost(request('{"action":"restart-replay"}'))).status, 404);
});

test("reference prices remain manifest-consistent and disabled mode fails closed", async context => {
  const fixture = await temporaryDatabase(context, "prices");
  const store = new ProjectPaymentSqliteStore(fixture.databasePath, {
    instanceId: "prices",
    evidenceScope: runtimeEvidenceScope()
  });
  context.after(() => store.close());
  context.after(() => rm(fixture.directory, { recursive: true, force: true }));
  const provider = new SimulatorProjectPaymentProvider({ catalog: trustedCatalog(), store });
  const prices = await provider.previewPrices(["monthly", "lifetime"]);
  const manifest = await readFile(new URL("../.vibenest/payments.yaml", import.meta.url), "utf8");
  for (const price of prices) {
    assert.match(manifest, new RegExp(
      `- key: ${price.priceKey}\\s+currency: ${price.currency}\\s+unitAmount: ${price.unitAmount}\\s+type: ${price.type}`,
      "m"
    ));
  }
  const disabled = new DisabledProjectPaymentProvider();
  await assert.rejects(disabled.previewPrices(), /disabled/);
  await assert.rejects(disabled.createCheckout(), /disabled/);
  await assert.rejects(disabled.createPortal(), /disabled/);
});

function transactionEvent({
  eventId,
  eventType = "transaction.completed",
  occurredAt,
  customerId,
  priceKey,
  subscriptionId = null,
  transactionId = `sim_txn_${eventId}`,
  status = "completed",
  period = null
}) {
  const price = runtimeCatalogProjection().products[0].prices.find(item => item.manifestKey === priceKey);
  return envelope(eventId, eventType, occurredAt, {
    id: transactionId,
    status,
    customer_id: customerId,
    subscription_id: subscriptionId,
    items: [{
      price_id: price.externalId,
      product_id: "sim_prod_fixture",
      quantity: 1,
      billing_period: price.type === "recurring" ? period ?? billingPeriod(new Date(occurredAt)) : null
    }],
    details: { totals: { total: String(price.unitAmount), currency_code: price.currency } },
    custom_data: { vibenest_environment_id: environmentId }
  });
}

function subscriptionEvent({
  eventId,
  eventType,
  occurredAt,
  customerId,
  subscriptionId,
  status = eventType === "subscription.canceled" ? "canceled" : "active",
  period,
  scheduledAt = null
}) {
  return envelope(eventId, eventType, occurredAt, {
    id: subscriptionId,
    status,
    customer_id: customerId,
    items: [{ price_id: "sim_price_monthly_fixture", product_id: "sim_prod_fixture", quantity: 1 }],
    current_billing_period: period,
    scheduled_change: scheduledAt === null ? null : { action: "cancel", effective_at: scheduledAt },
    custom_data: { vibenest_environment_id: environmentId }
  });
}

function adjustmentEvent({ eventId, eventType, occurredAt, transactionId, status }) {
  return envelope(eventId, eventType, occurredAt, {
    id: `sim_adj_${eventId}`,
    action: "refund",
    status,
    transaction_id: transactionId,
    totals: { total: "1500", currency_code: "USD" },
    custom_data: { vibenest_environment_id: environmentId }
  });
}

function portalEvent({ eventId, occurredAt, customerId }) {
  return envelope(eventId, "customer.portal_session.created", occurredAt, {
    id: `sim_portal_${eventId}`,
    customer_id: customerId,
    url: `https://simulator.invalid/portal/${environmentId}/${customerId}`,
    expires_at: new Date(Date.parse(occurredAt) + 30 * 60_000).toISOString(),
    custom_data: { vibenest_environment_id: environmentId }
  });
}

function envelope(eventId, eventType, occurredAt, data) {
  return { event_id: eventId, event_type: eventType, occurred_at: occurredAt, notification_id: `sim_ntf_${eventId}`, data };
}

async function deliver(store, payload, options = {}) {
  const rawBody = options.rawBody ?? Buffer.from(JSON.stringify(payload), "utf8");
  const timestamp = options.timestamp ?? Math.floor(Date.parse(payload.occurred_at) / 1_000);
  return acceptSignedEvent({
    rawBody,
    signature: options.signature ?? signEvent(rawBody, secret, timestamp),
    secret,
    nowSeconds: timestamp,
    destinationKey: environmentId,
    expectedEnvironmentId: environmentId,
    evidenceScope: runtimeEvidenceScope(),
    catalog: options.catalog ?? trustedCatalog(),
    store
  });
}

function billingPeriod(starts) {
  const start = new Date(starts);
  const targetMonth = start.getUTCMonth() + 1;
  const year = start.getUTCFullYear() + Math.floor(targetMonth / 12);
  const month = targetMonth % 12;
  const day = Math.min(start.getUTCDate(), new Date(Date.UTC(year, month + 1, 0)).getUTCDate());
  const end = new Date(Date.UTC(
    year,
    month,
    day,
    start.getUTCHours(),
    start.getUTCMinutes(),
    start.getUTCSeconds(),
    start.getUTCMilliseconds()
  ));
  return { starts_at: start.toISOString(), ends_at: end.toISOString() };
}

function runtimeCatalogProjection() {
  return {
    provider: "simulator",
    sellerExternalId: "sim_seller_fixture",
    environmentExternalId: environmentId,
    manifestDigest,
    products: [{
      manifestKey: "pro",
      externalId: "sim_prod_fixture",
      prices: [
        { manifestKey: "monthly", externalId: "sim_price_monthly_fixture", currency: "USD", unitAmount: 1500, type: "recurring", interval: "month" },
        { manifestKey: "lifetime", externalId: "sim_price_lifetime_fixture", currency: "USD", unitAmount: 9900, type: "one_time", interval: null }
      ],
      grants: [{ entitlement: "premium-access", quantity: 1 }]
    }]
  };
}

function trustedCatalog() {
  return parseRuntimeCatalog(encodeRuntimeCatalog(runtimeCatalogProjection()), runtimeCatalogExpectation());
}

function encodeRuntimeCatalog(projection) {
  return Buffer.from(JSON.stringify(projection), "utf8").toString("base64");
}

function runtimeCatalogExpectation() {
  return { expectedEnvironmentId: environmentId, expectedManifestDigest: manifestDigest };
}

function runtimeEvidenceScope() {
  return computeRuntimeEvidenceScope(environmentId, manifestDigest, commitSha);
}

function enabledEnvironment(overrides = {}) {
  return {
    VIBENEST_PROJECT_PAYMENTS_ENABLED: "true",
    VIBENEST_PROJECT_PAYMENTS_PROVIDER: "simulator",
    VIBENEST_PROJECT_PAYMENTS_VERIFIER_ENABLED: "true",
    VIBENEST_PROJECT_PAYMENTS_WEBHOOK_SECRET: secret,
    VIBENEST_PROJECT_PAYMENTS_ENVIRONMENT_ID: environmentId,
    VIBENEST_PROJECT_PAYMENTS_MANIFEST_DIGEST: manifestDigest,
    VIBENEST_PROJECT_PAYMENTS_CATALOG_B64: encodeRuntimeCatalog(runtimeCatalogProjection()),
    VIBENEST_FIXTURE_AUTH_ENABLED: "true",
    SOURCE_COMMIT: commitSha,
    ...overrides
  };
}

function verifierInput(store) {
  return {
    provider: providerModes.simulator,
    paymentsEnabled: true,
    verifierEnabled: true,
    suppliedSecret: secret,
    configuredSecret: secret,
    expectedCommit: commitSha,
    builtCommit: commitSha,
    expectedManifestDigest: manifestDigest,
    installedManifestDigest: manifestDigest,
    environmentId,
    store
  };
}

async function temporaryDatabase(context, label) {
  const directory = await mkdtemp(join(tmpdir(), `vn-pp-next-${label}-`));
  return { directory, databasePath: join(directory, "project-payments.sqlite") };
}

function installEnvironment(values) {
  const previous = new Map();
  for (const [key, value] of Object.entries(values)) {
    previous.set(key, process.env[key]);
    process.env[key] = value;
  }
  return () => {
    for (const [key, value] of previous) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
  };
}
