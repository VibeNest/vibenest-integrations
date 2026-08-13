import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile, mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import {
  acceptSignedEvent,
  buildVerifierPayload,
  computeRuntimeEvidenceScope,
  DisabledProjectPaymentProvider,
  DurableProjectPaymentProcessor,
  DurableProjectPaymentStore,
  parseRuntimeCatalog,
  providerModes,
  referenceCatalog,
  requiredLifecycleEvidence,
  signEvent,
  simulatorCustomerIdForSubject,
  SimulatorProjectPaymentProvider,
  verifyEventSignature
} from "../src/project-payments.mjs";
import { createApp } from "../src/server.mjs";

const secret = "fixture-secret-with-at-least-thirty-two-bytes";
const environmentId = "sim_env_fixture";
const commitSha = "a".repeat(40);
const manifestDigest = "b".repeat(64);
const evidenceScope = computeRuntimeEvidenceScope(environmentId, manifestDigest, commitSha);

test("HMAC uses the untouched raw Buffer and rejects missing or short secrets", () => {
  const timestamp = Math.floor(Date.now() / 1000);
  const rawBody = Buffer.from("{\n  \"message\": \"Привет\"\n}\n", "utf8");
  const signature = signEvent(rawBody, secret, timestamp);

  assert.equal(verifyEventSignature(rawBody, signature, secret, timestamp), true);
  assert.equal(verifyEventSignature(Buffer.concat([rawBody, Buffer.from(" ")]), signature, secret, timestamp), false);
  assert.equal(verifyEventSignature(rawBody, signature, undefined, timestamp), false);
  assert.equal(verifyEventSignature(rawBody, signature, "short", timestamp), false);
  assert.equal(verifyEventSignature(rawBody.toString("utf8"), signature, secret, timestamp), false);
  assert.throws(() => signEvent(rawBody.toString("utf8"), secret, timestamp), /raw Buffer/);
  assert.throws(() => signEvent(rawBody, "short", timestamp), /at least 32/);
});

test("signed event schema, event type, environment, customer, catalog, totals, and status are strict", async context => {
  const { store } = await temporaryStore(context, "schema");
  const customerId = await bindBuyer(store, "session-user");
  const valid = transactionEvent({
    eventId: "evt-valid",
    occurredAt: "2026-08-08T10:00:00.000Z",
    customerId,
    priceKey: "lifetime"
  });

  assert.equal((await deliver(store, valid)).inserted, true);

  const oversized = Buffer.alloc(128 * 1024 + 1, 0x20);
  const oversizedTimestamp = Math.floor(Date.now() / 1000);
  await assert.rejects(acceptSignedEvent({
    rawBody: oversized,
    signature: signEvent(oversized, secret, oversizedTimestamp),
    secret,
    nowSeconds: oversizedTimestamp,
    destinationKey: environmentId,
    expectedEnvironmentId: environmentId,
    evidenceScope,
    catalog: referenceCatalog,
    store
  }), /exceeds the accepted size/);

  const payloadControlled = structuredClone(valid);
  payloadControlled.event_id = "evt-payload-authority";
  payloadControlled.subjectKey = "attacker";
  payloadControlled.grantKey = "admin";
  payloadControlled.status = "active";
  await assert.rejects(deliver(store, payloadControlled), /missing or unexpected fields/);

  const wrongEnvironment = structuredClone(valid);
  wrongEnvironment.event_id = "evt-wrong-environment";
  wrongEnvironment.data.custom_data.vibenest_environment_id = "sim_env_other";
  await assert.rejects(deliver(store, wrongEnvironment), /different seller environment/);

  const unsupported = structuredClone(valid);
  unsupported.event_id = "evt-unsupported";
  unsupported.event_type = "transaction.refunded_by_payload";
  await assert.rejects(deliver(store, unsupported), /Unsupported simulator event type/);

  const forgedStatus = structuredClone(valid);
  forgedStatus.event_id = "evt-forged-status";
  forgedStatus.data.status = "revoked";
  await assert.rejects(deliver(store, forgedStatus), /status is not valid/);

  const unknownCustomer = structuredClone(valid);
  unknownCustomer.event_id = "evt-unknown-customer";
  unknownCustomer.data.customer_id = "sim_customer_unknown";
  await assert.rejects(deliver(store, unknownCustomer), /not bound/);

  const unknownPrice = structuredClone(valid);
  unknownPrice.event_id = "evt-unknown-price";
  unknownPrice.data.items[0].price_id = "attacker-price";
  await assert.rejects(deliver(store, unknownPrice), /trusted catalog mapping/);

  const forgedTotal = structuredClone(valid);
  forgedTotal.event_id = "evt-forged-total";
  forgedTotal.data.details.totals.total = "1";
  await assert.rejects(deliver(store, forgedTotal), /trusted catalog price/);

  const oneTimeWithPeriod = structuredClone(valid);
  oneTimeWithPeriod.event_id = "evt-one-time-period";
  oneTimeWithPeriod.data.items[0].billing_period = billingPeriod("2026-08-08T10:00:00.000Z", "month");
  await assert.rejects(deliver(store, oneTimeWithPeriod), /must be null for a one-time price/);

  const recurring = transactionEvent({
    eventId: "evt-recurring-period",
    occurredAt: "2026-08-08T10:00:00.001Z",
    billingPeriodStart: "2026-08-08T10:00:00.000Z",
    customerId,
    priceKey: "monthly",
    subscriptionId: "sim_sub_period"
  });
  const missingTransactionPeriod = structuredClone(recurring);
  missingTransactionPeriod.event_id = "evt-missing-transaction-period";
  delete missingTransactionPeriod.data.items[0].billing_period;
  await assert.rejects(deliver(store, missingTransactionPeriod), /missing or unexpected fields/);

  const wrongTransactionPeriod = structuredClone(recurring);
  wrongTransactionPeriod.event_id = "evt-wrong-transaction-period";
  wrongTransactionPeriod.data.items[0].billing_period.ends_at = "2026-10-08T10:00:00.000Z";
  await assert.rejects(deliver(store, wrongTransactionPeriod), /trusted catalog interval/);

  const subscription = subscriptionEvent({
    eventId: "evt-subscription-period",
    eventType: "subscription.updated",
    occurredAt: "2026-08-08T10:00:00.002Z",
    billingPeriodStart: "2026-08-08T10:00:00.000Z",
    customerId,
    subscriptionId: "sim_sub_period",
    scheduledChangeAt: "2026-09-08T10:00:00.000Z"
  });
  const missingSubscriptionPeriod = structuredClone(subscription);
  missingSubscriptionPeriod.event_id = "evt-missing-subscription-period";
  delete missingSubscriptionPeriod.data.current_billing_period;
  await assert.rejects(deliver(store, missingSubscriptionPeriod), /missing or unexpected fields/);

  const wrongScheduledEffectiveAt = structuredClone(subscription);
  wrongScheduledEffectiveAt.event_id = "evt-wrong-scheduled-effective-at";
  wrongScheduledEffectiveAt.data.scheduled_change.effective_at = "2026-09-08T10:00:00.001Z";
  await assert.rejects(deliver(store, wrongScheduledEffectiveAt), /authoritative billing-period end/);

  const canceledWithScheduledChange = structuredClone(subscription);
  canceledWithScheduledChange.event_id = "evt-canceled-with-scheduled-change";
  canceledWithScheduledChange.event_type = "subscription.canceled";
  canceledWithScheduledChange.data.status = "canceled";
  await assert.rejects(deliver(store, canceledWithScheduledChange), /cannot contain a scheduled change/);

  const portal = portalEvent({
    eventId: "evt-portal",
    occurredAt: "2026-08-08T10:00:00.003Z",
    customerId
  });
  assert.equal((await deliver(store, portal)).inserted, true);
  const portalWithoutEnvironment = structuredClone(portal);
  portalWithoutEnvironment.event_id = "evt-portal-without-environment";
  delete portalWithoutEnvironment.data.custom_data;
  await assert.rejects(deliver(store, portalWithoutEnvironment), /missing or unexpected fields/);

  const restarted = new DurableProjectPaymentStore(store.filePath, { instanceId: "schema-restart", evidenceScope });
  assert.deepEqual(await restarted.processDue(), {
    applied: 2, ignored: 0, deferred: 0, failed: 0, deadLettered: 0
  });
  const state = await restarted.snapshot();
  assert.equal(state.entitlements["session-user:premium-access"].status, "active");
  assert.equal(state.entitlements["session-user:premium-access"].sourceEventId, "evt-valid");
  assert.equal(Object.hasOwn(state.entitlements, "attacker:admin"), false);
});

test("runtime catalog is strict, environment/digest-bound, and is the only grant authority", async context => {
  const projection = runtimeCatalogProjection({
    productExternalId: "sim_prod_external",
    monthlyExternalId: "sim_price_monthly_external",
    lifetimeExternalId: "sim_price_lifetime_external",
    grants: [{ entitlement: "premium-access", quantity: 7 }]
  });
  const encoded = encodeRuntimeCatalog(projection);
  const catalog = parseRuntimeCatalog(encoded, {
    expectedEnvironmentId: environmentId,
    expectedManifestDigest: manifestDigest
  });
  assert.equal(catalog.products.pro.providerProductId, "sim_prod_external");
  assert.deepEqual(catalog.products.pro.grants, [{ entitlement: "premium-access", quantity: 7 }]);

  const { store } = await temporaryStore(context, "runtime-catalog");
  const customerId = await bindBuyer(store, "catalog-buyer");
  const payload = transactionEvent({
    eventId: "evt-runtime-catalog",
    occurredAt: "2026-08-08T10:00:00.000Z",
    customerId,
    priceKey: "lifetime",
    catalog
  });
  await deliver(store, payload, { catalog });
  const restarted = new DurableProjectPaymentStore(store.filePath, { instanceId: "runtime-catalog-restart", evidenceScope });
  await restarted.processDue();
  assert.equal((await restarted.snapshot()).entitlements["catalog-buyer:premium-access"].quantity, 7);

  assert.throws(() => parseRuntimeCatalog("not base64", {
    expectedEnvironmentId: environmentId,
    expectedManifestDigest: manifestDigest
  }), /canonical RFC4648 base64/);
  assert.throws(() => parseRuntimeCatalog(encoded, {
    expectedEnvironmentId: "sim_env_other",
    expectedManifestDigest: manifestDigest
  }), /different seller environment/);
  assert.throws(() => parseRuntimeCatalog(encoded, {
    expectedEnvironmentId: environmentId,
    expectedManifestDigest: "c".repeat(64)
  }), /manifest digest/);

  const payloadGrantAttempt = structuredClone(projection);
  payloadGrantAttempt.products[0].grants[0].quantity = 0;
  assert.throws(() => parseRuntimeCatalog(encodeRuntimeCatalog(payloadGrantAttempt), {
    expectedEnvironmentId: environmentId,
    expectedManifestDigest: manifestDigest
  }), /positive integer/);

  const legacyGrantKeys = structuredClone(projection);
  legacyGrantKeys.products[0].grantKeys = ["premium-access"];
  delete legacyGrantKeys.products[0].grants;
  assert.throws(() => parseRuntimeCatalog(encodeRuntimeCatalog(legacyGrantKeys), {
    expectedEnvironmentId: environmentId,
    expectedManifestDigest: manifestDigest
  }), /missing or unexpected fields/);

  const duplicateMapping = structuredClone(projection);
  duplicateMapping.products[0].prices.push({ ...duplicateMapping.products[0].prices[0], manifestKey: "duplicate" });
  assert.throws(() => parseRuntimeCatalog(encodeRuntimeCatalog(duplicateMapping), {
    expectedEnvironmentId: environmentId,
    expectedManifestDigest: manifestDigest
  }), /external ids globally must be unique/);

  const missingRuntimeCatalog = enabledConfiguration();
  delete missingRuntimeCatalog.VIBENEST_PROJECT_PAYMENTS_CATALOG_B64;
  assert.throws(() => createApp(missingRuntimeCatalog, { processor: noOpProcessor() }), /canonical RFC4648 base64/);

  const yearlyCatalog = parseRuntimeCatalog(encodeRuntimeCatalog(runtimeCatalogProjection({ monthlyInterval: "year" })), {
    expectedEnvironmentId: environmentId,
    expectedManifestDigest: manifestDigest
  });
  const yearlyCustomerId = await bindBuyer(restarted, "yearly-buyer");
  await deliver(restarted, subscriptionEvent({
    eventId: "evt-yearly-period",
    eventType: "subscription.created",
    occurredAt: "2024-02-29T12:00:00.000Z",
    customerId: yearlyCustomerId,
    subscriptionId: "sim_sub_yearly",
    catalog: yearlyCatalog
  }), { catalog: yearlyCatalog });
  await restarted.processDue();
  assert.deepEqual(
    (await restarted.snapshot()).subscriptions.sim_sub_yearly.billingPeriod,
    { startsAt: "2024-02-29T12:00:00.000Z", endsAt: "2025-02-28T12:00:00.000Z" }
  );
});

test("durable processor resumes after restart, deduplicates exact bytes, and fences stale events", async context => {
  const { file, store: receivingStore } = await temporaryStore(context, "restart", "receiver-instance");
  const customerId = await bindBuyer(receivingStore, "buyer-restart");
  const newer = subscriptionEvent({
    eventId: "evt-newer-cancel",
    eventType: "subscription.canceled",
    occurredAt: "2026-08-08T12:01:00.000Z",
    billingPeriodStart: "2026-08-08T12:00:00.000Z",
    customerId,
    subscriptionId: "sim_sub_restart"
  });
  const older = subscriptionEvent({
    eventId: "evt-older-create",
    eventType: "subscription.created",
    occurredAt: "2026-08-08T12:00:00.000Z",
    customerId,
    subscriptionId: "sim_sub_restart"
  });
  const stalePriorPeriod = subscriptionEvent({
    eventId: "evt-stale-prior-period",
    eventType: "subscription.created",
    occurredAt: "2026-08-08T12:02:00.000Z",
    billingPeriodStart: "2026-07-08T12:00:00.000Z",
    customerId,
    subscriptionId: "sim_sub_restart"
  });

  assert.equal((await deliver(receivingStore, newer)).inserted, true);
  assert.equal((await deliver(receivingStore, newer)).inserted, false);
  assert.equal((await deliver(receivingStore, older)).inserted, true);
  assert.equal((await deliver(receivingStore, stalePriorPeriod)).inserted, true);

  const restartedStore = new DurableProjectPaymentStore(file, { instanceId: "processor-after-restart", evidenceScope });
  const processor = new DurableProjectPaymentProcessor(restartedStore, { intervalMilliseconds: 50 });
  processor.start();
  await processor.wake();
  await restartedStore.processDue({ now: new Date(Date.now() + 31_000) });
  await processor.stop();

  const state = await restartedStore.snapshot();
  assert.equal(state.events.length, 3);
  assert.equal(state.events.find(item => item.eventId === "evt-newer-cancel").deliveryCount, 2);
  assert.equal(state.events.find(item => item.eventId === "evt-older-create").ignoredAsStale, false);
  assert.equal(state.events.find(item => item.eventId === "evt-stale-prior-period").ignoredAsStale, true);
  assert.equal(state.entitlements["buyer-restart:premium-access"].status, "revoked");
  assert.equal(state.subscriptions.sim_sub_restart.status, "revoked");
  const verification = await restartedStore.verificationStatus();
  assert.equal(verification.durableInbox, true);
  assert.equal(verification.restartReplayPassed, true);
  assert.equal(verification.lifecyclePassed, false);
  assert.deepEqual(
    state.evidence.map(item => item.name).filter(name => ["duplicate-delivery", "out-of-order-delivery"].includes(name)).sort(),
    ["duplicate-delivery", "out-of-order-delivery"]
  );
});

test("authoritative periods persist, renewal advances once, scheduled cancellation retains access, and older periods are fenced", async context => {
  const { store } = await temporaryStore(context, "period-lifecycle");
  const customerId = await bindBuyer(store, "buyer-period-lifecycle");
  const subscriptionId = "sim_sub_period_lifecycle";
  const initialPeriodStart = "2026-08-01T00:00:00.000Z";
  const initialPeriodEnd = "2026-09-01T00:00:00.000Z";
  const renewalPeriodStart = initialPeriodEnd;
  const renewalPeriodEnd = "2026-10-01T00:00:00.000Z";

  await deliver(store, subscriptionEvent({
    eventId: "evt-period-created",
    eventType: "subscription.created",
    occurredAt: initialPeriodStart,
    customerId,
    subscriptionId
  }));
  await deliver(store, transactionEvent({
    eventId: "evt-period-initial-transaction",
    occurredAt: "2026-08-01T00:00:00.001Z",
    billingPeriodStart: initialPeriodStart,
    customerId,
    priceKey: "monthly",
    subscriptionId,
    transactionId: "sim_txn_period_initial"
  }));
  assert.deepEqual(await store.processDue(), {
    applied: 2, ignored: 0, deferred: 0, failed: 0, deadLettered: 0
  });

  let snapshot = await store.snapshot();
  assert.deepEqual(snapshot.subscriptions[subscriptionId].billingPeriod, {
    startsAt: initialPeriodStart,
    endsAt: initialPeriodEnd
  });
  assert.deepEqual(snapshot.entitlements["buyer-period-lifecycle:premium-access"], {
    subjectKey: "buyer-period-lifecycle",
    grantKey: "premium-access",
    quantity: 1,
    status: "active",
    billingPeriod: { startsAt: initialPeriodStart, endsAt: initialPeriodEnd },
    effectiveFrom: initialPeriodStart,
    effectiveUntil: initialPeriodEnd,
    renewalCount: 0,
    sourceEventId: "evt-period-initial-transaction",
    lastOccurredAt: "2026-08-01T00:00:00.001Z"
  });

  await deliver(store, subscriptionEvent({
    eventId: "evt-period-renewal",
    eventType: "subscription.updated",
    occurredAt: renewalPeriodStart,
    customerId,
    subscriptionId
  }));
  await deliver(store, transactionEvent({
    eventId: "evt-period-renewal-transaction",
    occurredAt: "2026-09-01T00:00:00.001Z",
    billingPeriodStart: renewalPeriodStart,
    customerId,
    priceKey: "monthly",
    subscriptionId,
    transactionId: "sim_txn_period_renewal"
  }));
  assert.deepEqual(await store.processDue(), {
    applied: 2, ignored: 0, deferred: 0, failed: 0, deadLettered: 0
  });

  snapshot = await store.snapshot();
  assert.equal(snapshot.entitlements["buyer-period-lifecycle:premium-access"].renewalCount, 1);
  assert.deepEqual(snapshot.entitlements["buyer-period-lifecycle:premium-access"].billingPeriod, {
    startsAt: renewalPeriodStart,
    endsAt: renewalPeriodEnd
  });
  assert.deepEqual(
    snapshot.evidence.filter(item => item.name === "renewal").map(item => item.details.eventId),
    ["evt-period-renewal"]
  );

  await deliver(store, subscriptionEvent({
    eventId: "evt-period-scheduled-cancel",
    eventType: "subscription.updated",
    occurredAt: "2026-09-15T00:00:00.000Z",
    billingPeriodStart: renewalPeriodStart,
    customerId,
    subscriptionId,
    scheduledChangeAt: renewalPeriodEnd
  }));
  assert.deepEqual(await store.processDue(), {
    applied: 1, ignored: 0, deferred: 0, failed: 0, deadLettered: 0
  });
  snapshot = await store.snapshot();
  assert.equal(snapshot.entitlements["buyer-period-lifecycle:premium-access"].effectiveFrom, renewalPeriodStart);
  assert.equal(snapshot.entitlements["buyer-period-lifecycle:premium-access"].effectiveUntil, renewalPeriodEnd);
  assert.equal(await store.hasEntitlement(
    "buyer-period-lifecycle",
    "premium-access",
    new Date("2026-09-30T23:59:59.999Z")
  ), true);
  assert.equal(await store.hasEntitlement(
    "buyer-period-lifecycle",
    "premium-access",
    new Date(renewalPeriodEnd)
  ), false);

  await deliver(store, subscriptionEvent({
    eventId: "evt-period-stale-update",
    eventType: "subscription.updated",
    occurredAt: "2026-09-20T00:00:00.000Z",
    billingPeriodStart: initialPeriodStart,
    customerId,
    subscriptionId
  }));
  assert.deepEqual(await store.processDue(), {
    applied: 0, ignored: 1, deferred: 0, failed: 0, deadLettered: 0
  });

  snapshot = await store.snapshot();
  assert.equal(snapshot.subscriptions[subscriptionId].status, "scheduled_cancel");
  assert.equal(snapshot.subscriptions[subscriptionId].sourceEventId, "evt-period-scheduled-cancel");
  assert.equal(snapshot.entitlements["buyer-period-lifecycle:premium-access"].renewalCount, 1);
  assert.equal(snapshot.entitlements["buyer-period-lifecycle:premium-access"].status, "scheduled_cancel");
  assert.equal(snapshot.events.find(item => item.eventId === "evt-period-stale-update").ignoredAsStale, true);
});

test("renewal, scheduled cancellation, immediate cancellation, and recurring transactions enforce prior-period continuity", async context => {
  const cases = [
    {
      label: "renewal-gap",
      expected: /renewal billing period is not continuous/,
      payload: customerId => subscriptionEvent({
        eventId: "evt-renewal-gap",
        eventType: "subscription.updated",
        occurredAt: "2026-09-01T00:00:00.000Z",
        billingPeriodStart: "2026-10-01T00:00:00.000Z",
        customerId,
        subscriptionId: "sim_sub_continuity"
      })
    },
    {
      label: "scheduled-period-shift",
      expected: /cancellation must reuse the persisted active billing period/,
      payload: customerId => subscriptionEvent({
        eventId: "evt-scheduled-period-shift",
        eventType: "subscription.updated",
        occurredAt: "2026-08-15T00:00:00.000Z",
        billingPeriodStart: "2026-09-01T00:00:00.000Z",
        customerId,
        subscriptionId: "sim_sub_continuity",
        scheduledChangeAt: "2026-10-01T00:00:00.000Z"
      })
    },
    {
      label: "canceled-period-shift",
      expected: /cancellation must reuse the persisted active billing period/,
      payload: customerId => subscriptionEvent({
        eventId: "evt-canceled-period-shift",
        eventType: "subscription.canceled",
        occurredAt: "2026-08-15T00:00:00.000Z",
        billingPeriodStart: "2026-09-01T00:00:00.000Z",
        customerId,
        subscriptionId: "sim_sub_continuity"
      })
    },
    {
      label: "transaction-gap",
      expected: /transaction billing period is not continuous/,
      payload: customerId => transactionEvent({
        eventId: "evt-transaction-gap",
        occurredAt: "2026-09-01T00:00:00.001Z",
        billingPeriodStart: "2026-10-01T00:00:00.000Z",
        customerId,
        priceKey: "monthly",
        subscriptionId: "sim_sub_continuity",
        transactionId: "sim_txn_gap"
      })
    }
  ];

  for (const item of cases) {
    const { store } = await temporaryStore(context, item.label);
    const customerId = await bindBuyer(store, `buyer-${item.label}`);
    await deliver(store, subscriptionEvent({
      eventId: `evt-created-${item.label}`,
      eventType: "subscription.created",
      occurredAt: "2026-08-01T00:00:00.000Z",
      customerId,
      subscriptionId: "sim_sub_continuity"
    }));
    await store.processDue();
    await deliver(store, item.payload(customerId));
    const failed = await store.processDue();
    assert.deepEqual(failed, { applied: 0, ignored: 0, deferred: 0, failed: 1, deadLettered: 0 });
    const rejected = (await store.snapshot()).events.find(event => event.processedAt === null);
    assert.ok(rejected);
    assert.equal(rejected.processedAt, null);
    assert.equal(rejected.processingError, "Project Payments event processing failed.");
  }
});

test("duplicate event id with different signed bytes is rejected instead of silently deduplicated", async context => {
  const { store } = await temporaryStore(context, "collision");
  const customerId = await bindBuyer(store, "buyer-collision");
  const first = transactionEvent({
    eventId: "evt-collision",
    occurredAt: "2026-08-08T10:00:00.000Z",
    customerId,
    priceKey: "lifetime"
  });
  const collision = structuredClone(first);
  collision.notification_id = "sim_ntf_different";

  await deliver(store, first);
  await assert.rejects(deliver(store, collision), /reused with different signed bytes/);
});

test("conditional SQLite leases recover after expiration and durable backoff reaches dead-letter", async context => {
  const { file, store: receiver } = await temporaryStore(context, "leases", "lease-receiver");
  const customerId = await bindBuyer(receiver, "buyer-lease");
  const receivedAt = new Date();
  receivedAt.setUTCMilliseconds(0);
  await deliver(receiver, subscriptionEvent({
    eventId: "evt-missing-prior",
    eventType: "subscription.updated",
    occurredAt: receivedAt.toISOString(),
    customerId,
    subscriptionId: "sim_sub_missing_prior"
  }));

  const workerA = new DurableProjectPaymentStore(file, {
    instanceId: "lease-worker-a",
    leaseSeconds: 2,
    maxAttempts: 2,
    baseBackoffSeconds: 1,
    evidenceScope
  });
  const workerB = new DurableProjectPaymentStore(file, {
    instanceId: "lease-worker-b",
    leaseSeconds: 2,
    maxAttempts: 2,
    baseBackoffSeconds: 1,
    evidenceScope
  });
  const claimAt = new Date(Date.now() + 100);
  assert.ok(await workerA.claimDue(claimAt));
  assert.equal(await workerB.claimDue(new Date(claimAt.getTime() + 1_000)), null);

  const recovered = await workerB.processDue({ now: new Date(claimAt.getTime() + 2_100) });
  assert.deepEqual(recovered, { applied: 0, ignored: 0, deferred: 1, failed: 0, deadLettered: 1 });
  const event = (await workerB.snapshot()).events[0];
  assert.equal(event.attemptCount, 2);
  assert.ok(event.deadLetteredAt);
  assert.equal(event.processingError, "A referenced projection is not available yet.");
  assert.equal(event.leaseId, null);
});

test("independent provider sources survive selective revocation and a terminal subscription cannot reactivate", async context => {
  const { store } = await temporaryStore(context, "source-contributions");
  const customerId = await bindBuyer(store, "buyer-combined");
  const periodStart = "2026-08-01T00:00:00.000Z";
  const periodEnd = "2026-09-01T00:00:00.000Z";
  const subscriptionId = "sim_sub_combined";
  const monthlyTransactionId = "sim_txn_combined_monthly";

  await deliver(store, transactionEvent({
    eventId: "evt-combined-lifetime",
    occurredAt: periodStart,
    customerId,
    priceKey: "lifetime",
    transactionId: "sim_txn_combined_lifetime"
  }));
  await deliver(store, subscriptionEvent({
    eventId: "evt-combined-subscription",
    eventType: "subscription.created",
    occurredAt: "2026-08-01T00:00:00.001Z",
    billingPeriodStart: periodStart,
    billingPeriodEnd: periodEnd,
    customerId,
    subscriptionId
  }));
  await deliver(store, transactionEvent({
    eventId: "evt-combined-monthly",
    occurredAt: "2026-08-01T00:00:00.002Z",
    billingPeriodStart: periodStart,
    billingPeriodEnd: periodEnd,
    customerId,
    priceKey: "monthly",
    subscriptionId,
    transactionId: monthlyTransactionId
  }));
  assert.equal((await store.processDue()).failed, 0);

  await deliver(store, adjustmentEvent({
    eventId: "evt-combined-refund",
    eventType: "adjustment.updated",
    occurredAt: "2026-08-15T00:00:00.000Z",
    adjustmentId: "sim_adj_combined",
    transactionId: monthlyTransactionId,
    status: "approved"
  }));
  assert.equal((await store.processDue()).failed, 0);
  await deliver(store, transactionEvent({
    eventId: "evt-combined-post-refund-before-cancel",
    occurredAt: "2026-08-15T00:00:00.001Z",
    billingPeriodStart: periodStart,
    billingPeriodEnd: periodEnd,
    customerId,
    priceKey: "monthly",
    subscriptionId,
    transactionId: "sim_txn_combined_post_refund"
  }));
  assert.equal((await store.processDue()).failed, 1);
  await deliver(store, subscriptionEvent({
    eventId: "evt-combined-canceled",
    eventType: "subscription.canceled",
    occurredAt: "2026-08-15T00:00:00.002Z",
    billingPeriodStart: periodStart,
    billingPeriodEnd: periodEnd,
    customerId,
    subscriptionId
  }));
  assert.equal((await store.processDue()).failed, 0);

  await deliver(store, transactionEvent({
    eventId: "evt-combined-late-delivered-old-transaction",
    occurredAt: "2026-08-10T00:00:00.000Z",
    billingPeriodStart: periodStart,
    billingPeriodEnd: periodEnd,
    customerId,
    priceKey: "monthly",
    subscriptionId,
    transactionId: "sim_txn_combined_old_delivery"
  }));
  const oldDelivery = await store.processDue();
  assert.equal(oldDelivery.ignored, 1);

  await deliver(store, transactionEvent({
    eventId: "evt-combined-resurrection",
    occurredAt: "2026-08-15T00:00:00.003Z",
    billingPeriodStart: periodStart,
    billingPeriodEnd: periodEnd,
    customerId,
    priceKey: "monthly",
    subscriptionId,
    transactionId: "sim_txn_combined_resurrection"
  }));
  assert.equal((await store.processDue()).failed, 1);
  assert.equal(await store.hasEntitlement("buyer-combined", "premium-access"), true);
  const snapshot = await store.snapshot();
  assert.equal(snapshot.entitlements["buyer-combined:premium-access"].status, "active");
  assert.equal(snapshot.entitlements["buyer-combined:premium-access"].effectiveUntil, null);
  assert.deepEqual(
    snapshot.entitlementSources.map(source => [source.sourceKey, source.status]).sort(),
    [
      ["subscription:sim_sub_combined", "revoked"],
      ["transaction:sim_txn_combined_lifetime", "active"]
    ]
  );
  assert.equal(snapshot.events.find(event => event.eventId === "evt-combined-resurrection").processedAt, null);
});

test("subscription and transaction identity is immutable in both arrival orders", async context => {
  const { store } = await temporaryStore(context, "immutable-identity");
  const ownerCustomer = await bindBuyer(store, "buyer-owner");
  const attackerCustomer = await bindBuyer(store, "buyer-attacker");
  const initialStart = "2026-08-01T00:00:00.000Z";
  const initialEnd = "2026-09-01T00:00:00.000Z";

  await deliver(store, subscriptionEvent({
    eventId: "evt-identity-created",
    eventType: "subscription.created",
    occurredAt: initialStart,
    billingPeriodStart: initialStart,
    billingPeriodEnd: initialEnd,
    customerId: ownerCustomer,
    subscriptionId: "sim_sub_immutable"
  }));
  await deliver(store, transactionEvent({
    eventId: "evt-identity-transaction",
    occurredAt: "2026-08-01T00:00:00.001Z",
    customerId: ownerCustomer,
    priceKey: "lifetime",
    transactionId: "sim_txn_immutable"
  }));
  assert.equal((await store.processDue()).failed, 0);

  await deliver(store, subscriptionEvent({
    eventId: "evt-identity-recreated-period",
    eventType: "subscription.created",
    occurredAt: initialEnd,
    billingPeriodStart: initialEnd,
    billingPeriodEnd: "2026-10-01T00:00:00.000Z",
    customerId: ownerCustomer,
    subscriptionId: "sim_sub_immutable"
  }));
  assert.equal((await store.processDue()).failed, 1);

  await deliver(store, subscriptionEvent({
    eventId: "evt-stolen-subscription",
    eventType: "subscription.updated",
    occurredAt: initialEnd,
    billingPeriodStart: initialEnd,
    billingPeriodEnd: "2026-10-01T00:00:00.000Z",
    customerId: attackerCustomer,
    subscriptionId: "sim_sub_immutable"
  }));
  const stolenTransaction = transactionEvent({
    eventId: "evt-stolen-transaction",
    occurredAt: "2026-08-01T00:00:00.002Z",
    customerId: attackerCustomer,
    priceKey: "lifetime",
    transactionId: "sim_txn_immutable"
  });
  await deliver(store, stolenTransaction);
  const stolen = await store.processDue();
  assert.equal(stolen.failed, 2);
  assert.equal(await store.hasEntitlement("buyer-owner", "premium-access"), true);
  assert.equal(await store.hasEntitlement("buyer-attacker", "premium-access"), false);

  await deliver(store, transactionEvent({
    eventId: "evt-transaction-first",
    occurredAt: "2026-11-01T00:00:00.002Z",
    billingPeriodStart: "2026-11-01T00:00:00.000Z",
    billingPeriodEnd: "2026-12-01T00:00:00.000Z",
    customerId: ownerCustomer,
    priceKey: "monthly",
    subscriptionId: "sim_sub_transaction_first",
    transactionId: "sim_txn_transaction_first"
  }));
  assert.equal((await store.processDue()).failed, 0);
  await deliver(store, subscriptionEvent({
    eventId: "evt-subscription-second-attacker",
    eventType: "subscription.created",
    occurredAt: "2026-11-01T00:00:00.000Z",
    billingPeriodStart: "2026-11-01T00:00:00.000Z",
    billingPeriodEnd: "2026-12-01T00:00:00.000Z",
    customerId: attackerCustomer,
    subscriptionId: "sim_sub_transaction_first"
  }));
  assert.equal((await store.processDue()).failed, 1);
  assert.equal(await store.hasEntitlement("buyer-attacker", "premium-access"), false);

  await deliver(store, transactionEvent({
    eventId: "evt-period-transaction-first",
    occurredAt: "2027-01-01T00:00:00.001Z",
    billingPeriodStart: "2027-01-01T00:00:00.000Z",
    billingPeriodEnd: "2027-02-01T00:00:00.000Z",
    customerId: ownerCustomer,
    priceKey: "monthly",
    subscriptionId: "sim_sub_period_swap",
    transactionId: "sim_txn_period_swap"
  }));
  assert.equal((await store.processDue()).failed, 0);
  await deliver(store, subscriptionEvent({
    eventId: "evt-period-subscription-second",
    eventType: "subscription.created",
    occurredAt: "2027-02-01T00:00:00.000Z",
    billingPeriodStart: "2027-02-01T00:00:00.000Z",
    billingPeriodEnd: "2027-03-01T00:00:00.000Z",
    customerId: ownerCustomer,
    subscriptionId: "sim_sub_period_swap"
  }));
  assert.equal((await store.processDue()).failed, 1);
});

test("complete verifier evidence comes from real operations, events, durable inbox, and restart replay", async context => {
  const { file, store: receivingStore } = await temporaryStore(context, "lifecycle", "lifecycle-receiver");
  const provider = new SimulatorProjectPaymentProvider({ catalog: referenceCatalog, store: receivingStore });
  assert.deepEqual(
    (await provider.previewPrices(["monthly", "lifetime"])).map(price => [price.priceKey, price.unitAmount]),
    [["monthly", 1500], ["lifetime", 9900]]
  );

  const oneTimeCustomer = await checkoutBuyer(provider, "buyer-one-time", "lifetime");
  const subscriptionCustomer = await checkoutBuyer(provider, "buyer-subscription", "monthly");
  const declinedCustomer = await checkoutBuyer(provider, "buyer-declined", "lifetime");
  const staleCustomer = await checkoutBuyer(provider, "buyer-stale", "monthly");
  await provider.createPortal("buyer-subscription");

  const subscriptionId = "sim_sub_complete";
  const transactionId = "sim_txn_complete";
  const renewalTransactionId = "sim_txn_renewal";
  const initialPeriodStart = "2026-08-08T10:01:00.000Z";
  const renewalPeriodStart = "2026-09-08T10:01:00.000Z";
  const renewalPeriodEnd = "2026-10-08T10:01:00.000Z";
  const deliveries = [
    transactionEvent({
      eventId: "evt-one-time",
      occurredAt: "2026-08-08T10:00:00.000Z",
      customerId: oneTimeCustomer,
      priceKey: "lifetime"
    }),
    subscriptionEvent({
      eventId: "evt-subscription-created",
      eventType: "subscription.created",
      occurredAt: "2026-08-08T10:01:00.000Z",
      customerId: subscriptionCustomer,
      subscriptionId
    }),
    transactionEvent({
      eventId: "evt-subscription-transaction",
      occurredAt: "2026-08-08T10:01:00.001Z",
      customerId: subscriptionCustomer,
      priceKey: "monthly",
      subscriptionId,
      transactionId,
      billingPeriodStart: initialPeriodStart
    }),
    transactionEvent({
      eventId: "evt-declined",
      eventType: "transaction.payment_failed",
      occurredAt: "2026-08-08T10:02:00.000Z",
      customerId: declinedCustomer,
      priceKey: "lifetime",
      status: "declined"
    }),
    subscriptionEvent({
      eventId: "evt-renewal",
      eventType: "subscription.updated",
      occurredAt: renewalPeriodStart,
      customerId: subscriptionCustomer,
      subscriptionId
    }),
    transactionEvent({
      eventId: "evt-renewal-transaction",
      occurredAt: "2026-09-08T10:01:00.001Z",
      billingPeriodStart: renewalPeriodStart,
      customerId: subscriptionCustomer,
      priceKey: "monthly",
      subscriptionId,
      transactionId: renewalTransactionId
    }),
    subscriptionEvent({
      eventId: "evt-scheduled-cancel",
      eventType: "subscription.updated",
      occurredAt: "2026-09-15T10:01:00.000Z",
      billingPeriodStart: renewalPeriodStart,
      customerId: subscriptionCustomer,
      subscriptionId,
      scheduledChangeAt: renewalPeriodEnd
    }),
    adjustmentEvent({
      eventId: "evt-refund-pending",
      eventType: "adjustment.created",
      occurredAt: "2026-09-20T10:01:00.000Z",
      adjustmentId: "sim_adj_complete",
      transactionId: renewalTransactionId,
      status: "pending_approval"
    }),
    adjustmentEvent({
      eventId: "evt-refund-approved",
      eventType: "adjustment.updated",
      occurredAt: "2026-09-20T10:01:00.001Z",
      adjustmentId: "sim_adj_complete",
      transactionId: renewalTransactionId,
      status: "approved"
    }),
    subscriptionEvent({
      eventId: "evt-refund-canceled",
      eventType: "subscription.canceled",
      occurredAt: "2026-09-20T10:01:00.002Z",
      billingPeriodStart: renewalPeriodStart,
      customerId: subscriptionCustomer,
      subscriptionId
    }),
    transactionEvent({
      eventId: "evt-out-of-order-transaction",
      occurredAt: "2026-12-08T10:01:00.002Z",
      billingPeriodStart: "2026-12-08T10:01:00.000Z",
      customerId: staleCustomer,
      priceKey: "monthly",
      subscriptionId: "sim_sub_stale",
      transactionId: "sim_txn_stale"
    }),
    subscriptionEvent({
      eventId: "evt-out-of-order-subscription",
      eventType: "subscription.created",
      occurredAt: "2026-12-08T10:01:00.000Z",
      customerId: staleCustomer,
      subscriptionId: "sim_sub_stale"
    }),
    portalEvent({
      eventId: "evt-customer-portal",
      occurredAt: "2026-12-08T10:02:00.000Z",
      customerId: subscriptionCustomer
    })
  ];

  for (const payload of deliveries) await deliver(receivingStore, payload);
  await deliver(receivingStore, deliveries[0]);

  const processingStore = new DurableProjectPaymentStore(file, { instanceId: "lifecycle-processor", evidenceScope });
  assert.deepEqual(await processingStore.processDue(), {
    applied: 12, ignored: 1, deferred: 0, failed: 0, deadLettered: 0
  });
  const evidence = await processingStore.verificationStatus();
  assert.deepEqual(evidence, { lifecyclePassed: true, durableInbox: true, restartReplayPassed: true });
  const snapshot = await processingStore.snapshot();
  assert.equal(Object.hasOwn(snapshot.entitlements, "buyer-declined:premium-access"), false);
  assert.deepEqual(
    snapshot.evidence.map(item => item.name).sort(),
    [...requiredLifecycleEvidence, "restart-replay"].sort()
  );

  const payload = await buildVerifierPayload(verifierInput(processingStore));
  assert.deepEqual(payload, {
    provider: "simulator",
    paymentsEnabled: true,
    verifierEnabled: true,
    commitSha,
    manifestDigest,
    lifecyclePassed: true,
    durableInbox: true,
    restartReplayPassed: true
  });

  const nextCommitScope = computeRuntimeEvidenceScope(environmentId, manifestDigest, "c".repeat(40));
  const nextBuildStore = new DurableProjectPaymentStore(file, {
    instanceId: "lifecycle-next-build",
    evidenceScope: nextCommitScope
  });
  assert.deepEqual(await nextBuildStore.verificationStatus(), {
    lifecyclePassed: false,
    durableInbox: false,
    restartReplayPassed: false
  });
  assert.equal(await buildVerifierPayload({
    ...verifierInput(nextBuildStore),
    expectedCommit: "c".repeat(40),
    builtCommit: "c".repeat(40)
  }), null);
});

test("evidence scope changes for environment, manifest, or exact SOURCE_COMMIT", () => {
  assert.notEqual(
    evidenceScope,
    computeRuntimeEvidenceScope("sim_env_other", manifestDigest, commitSha)
  );
  assert.notEqual(
    evidenceScope,
    computeRuntimeEvidenceScope(environmentId, "c".repeat(64), commitSha)
  );
  assert.notEqual(
    evidenceScope,
    computeRuntimeEvidenceScope(environmentId, manifestDigest, "c".repeat(40))
  );
});

test("verifier rejects missing or short secrets, missing build SHA, mismatched challenge, and unearned evidence", async () => {
  const completeStore = {
    evidenceScope,
    async verificationStatus() {
      return { lifecyclePassed: true, durableInbox: true, restartReplayPassed: true };
    }
  };
  const input = verifierInput(completeStore);

  assert.ok(await buildVerifierPayload(input));
  assert.equal(await buildVerifierPayload({ ...input, suppliedSecret: undefined, configuredSecret: undefined }), null);
  assert.equal(await buildVerifierPayload({ ...input, suppliedSecret: undefined }), null);
  assert.equal(await buildVerifierPayload({ ...input, configuredSecret: undefined }), null);
  assert.equal(await buildVerifierPayload({ ...input, suppliedSecret: "short", configuredSecret: "short" }), null);
  assert.equal(await buildVerifierPayload({ ...input, suppliedSecret: "short" }), null);
  assert.equal(await buildVerifierPayload({ ...input, configuredSecret: "short" }), null);
  assert.equal(await buildVerifierPayload({ ...input, builtCommit: undefined, expectedCommit: commitSha }), null);
  assert.equal(await buildVerifierPayload({ ...input, expectedCommit: "c".repeat(40) }), null);
  assert.equal(await buildVerifierPayload({ ...input, provider: providerModes.disabled }), null);
  assert.equal(await buildVerifierPayload({
    ...input,
    store: {
      evidenceScope,
      async verificationStatus() {
        return { lifecyclePassed: true, durableInbox: true, restartReplayPassed: false };
      }
    }
  }), null);
});

test("HTTP verifier accepts only the exact GET route and SOURCE_COMMIT is authoritative", async context => {
  const completeStore = verifierReadyStore();
  const processor = noOpProcessor();
  const configuration = enabledConfiguration({
    SOURCE_COMMIT: commitSha,
    VIBENEST_BUILD_COMMIT_SHA: "c".repeat(40)
  });
  const app = createApp(configuration, { store: completeStore, processor });

  await withServer(context, app, async baseUrl => {
    const headers = verifierHeaders();
    const success = await fetch(`${baseUrl}/.well-known/vibenest/project-payments/verifier`, { headers });
    assert.equal(success.status, 200);
    assert.equal((await success.json()).commitSha, commitSha);

    assert.equal((await fetch(`${baseUrl}/.well-known/vibenest/project-payments/verifier`, { method: "HEAD", headers })).status, 405);
    assert.equal((await fetch(`${baseUrl}/.well-known/vibenest/project-payments/verifier`, { method: "POST", headers })).status, 405);
    assert.equal((await fetch(`${baseUrl}/.well-known/vibenest/project-payments/verifier/`, { headers })).status, 404);
    assert.equal((await fetch(`${baseUrl}/.well-known/vibenest/project-payments/Verifier`, { headers })).status, 404);

    const legacyChallenge = { ...headers, "X-VibeNest-Expected-Commit": "c".repeat(40) };
    assert.equal((await fetch(`${baseUrl}/.well-known/vibenest/project-payments/verifier`, { headers: legacyChallenge })).status, 404);
    const missingSecretHeaders = { ...headers };
    delete missingSecretHeaders["X-VibeNest-Simulator-Secret"];
    assert.equal((await fetch(`${baseUrl}/.well-known/vibenest/project-payments/verifier`, { headers: missingSecretHeaders })).status, 404);
  });

  const legacyFallback = enabledConfiguration({ SOURCE_COMMIT: " ", VIBENEST_BUILD_COMMIT_SHA: commitSha });
  assert.throws(
    () => createApp(legacyFallback, { store: verifierReadyStore(), processor: noOpProcessor() }),
    /evidence build commit is invalid/
  );

  const disabledApp = createApp({
    ...enabledConfiguration(),
    VIBENEST_PROJECT_PAYMENTS_ENABLED: "false",
    VIBENEST_PROJECT_PAYMENTS_PROVIDER: "disabled"
  }, { store: verifierReadyStore(), processor: noOpProcessor() });
  await withServer(context, disabledApp, async baseUrl => {
    assert.equal((await fetch(`${baseUrl}/.well-known/vibenest/project-payments/verifier`, {
      headers: verifierHeaders()
    })).status, 404);
    assert.equal((await fetch(`${baseUrl}/webhooks/project-payments`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: "{}"
    })).status, 404);
  });
});

test("protected restart harness stages a probe that only another process instance can claim", async context => {
  const { file, store } = await temporaryStore(context, "restart-harness", "harness-before-restart");
  const app = createApp(enabledConfiguration(), { store, processor: noOpProcessor() });

  await withServer(context, app, async baseUrl => {
    const endpoint = `${baseUrl}/.well-known/vibenest/project-payments/harness`;
    const post = (body, suppliedSecret = secret) => fetch(endpoint, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-VibeNest-Simulator-Secret": suppliedSecret,
        "X-VibeNest-Expected-Commit": commitSha,
        "X-VibeNest-Expected-Manifest-Digest": manifestDigest
      },
      body
    });
    assert.equal((await post('{"action":"restart-replay"}', "x".repeat(32))).status, 404);
    assert.equal((await fetch(endpoint, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-VibeNest-Simulator-Secret": secret,
        "X-VibeNest-Expected-Commit": "c".repeat(40),
        "X-VibeNest-Expected-Manifest-Digest": manifestDigest
      },
      body: '{"action":"restart-replay"}'
    })).status, 404);
    assert.equal((await post('{"action":"unsupported"}')).status, 400);
    assert.equal((await post(JSON.stringify({ action: "restart-replay", extra: true }))).status, 400);
    assert.equal((await post(JSON.stringify({ action: "restart-replay", padding: "x".repeat(1100) }))).status, 413);
    assert.equal((await fetch(endpoint, { headers: verifierHeaders() })).status, 405);

    const staged = await post('{"action":"restart-replay"}');
    assert.equal(staged.status, 202);
    assert.deepEqual(await staged.json(), { action: "restart-replay", state: "staged" });
  });

  assert.deepEqual(await store.processDue(), {
    applied: 0,
    ignored: 0,
    deferred: 0,
    failed: 0,
    deadLettered: 0
  });
  assert.equal((await store.snapshot()).events[0].processedAt, null);

  const afterRestart = new DurableProjectPaymentStore(file, {
    instanceId: "harness-after-restart",
    evidenceScope
  });
  assert.equal((await afterRestart.processDue()).applied, 1);
  const snapshot = await afterRestart.snapshot();
  assert.equal(snapshot.events[0].processedByInstanceId, "harness-after-restart");
  assert.equal((await afterRestart.verificationStatus()).restartReplayPassed, true);

  const disabled = createApp({
    ...enabledConfiguration(),
    VIBENEST_PROJECT_PAYMENTS_ENABLED: "false",
    VIBENEST_PROJECT_PAYMENTS_PROVIDER: "disabled"
  }, { store: verifierReadyStore(), processor: noOpProcessor() });
  await withServer(context, disabled, async baseUrl => {
    assert.equal((await fetch(`${baseUrl}/.well-known/vibenest/project-payments/harness`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-VibeNest-Simulator-Secret": secret
      },
      body: '{"action":"restart-replay"}'
    })).status, 404);
  });
});

test("HTTP verifier cannot substitute its request challenge for a missing built SHA and weak secrets stay hidden", async context => {
  const processor = noOpProcessor();
  const missingBuild = enabledConfiguration({ SOURCE_COMMIT: "", VIBENEST_BUILD_COMMIT_SHA: "" });
  assert.throws(
    () => createApp(missingBuild, { store: verifierReadyStore(), processor }),
    /evidence build commit is invalid/
  );

  const weakSecret = enabledConfiguration({ VIBENEST_PROJECT_PAYMENTS_WEBHOOK_SECRET: "short" });
  assert.throws(
    () => createApp(weakSecret, { store: verifierReadyStore(), processor: noOpProcessor() }),
    /at least 32 UTF-8 bytes/
  );
});

test("HTTP webhook verifies the exact Buffer before parsing and durably ACKs only a strict event", async context => {
  const { store } = await temporaryStore(context, "http-webhook");
  const customerId = await bindBuyer(store, "http-buyer");
  const configuration = enabledConfiguration({ VIBENEST_PROJECT_PAYMENTS_VERIFIER_ENABLED: "false" });
  const app = createApp(configuration, { store, processor: noOpProcessor() });
  const payload = transactionEvent({
    eventId: "evt-http-raw",
    occurredAt: "2026-08-08T11:00:00.000Z",
    customerId,
    priceKey: "lifetime"
  });
  const rawBody = Buffer.from(`${JSON.stringify(payload, null, 2)}\n`, "utf8");
  const timestamp = Math.floor(Date.now() / 1000);
  const signature = signEvent(rawBody, secret, timestamp);

  await withServer(context, app, async baseUrl => {
    const accepted = await fetch(`${baseUrl}/webhooks/project-payments`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "Paddle-Signature": signature },
      body: rawBody
    });
    assert.equal(accepted.status, 202);
    const state = await store.snapshot();
    assert.equal(state.events.length, 1);
    assert.equal(state.events[0].bodyDigest, createHash("sha256").update(rawBody).digest("hex"));

    const tampered = Buffer.concat([rawBody, Buffer.from(" ")]);
    assert.equal((await fetch(`${baseUrl}/webhooks/project-payments`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "Paddle-Signature": signature },
      body: tampered
    })).status, 401);

    assert.equal((await fetch(`${baseUrl}/webhooks/project-payments`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Content-Encoding": "gzip",
        "Paddle-Signature": signature
      },
      body: rawBody
    })).status, 415);

    const invalidPayload = structuredClone(payload);
    invalidPayload.event_id = "evt-http-invalid";
    invalidPayload.status = "active";
    const invalidRaw = Buffer.from(JSON.stringify(invalidPayload), "utf8");
    assert.equal((await fetch(`${baseUrl}/webhooks/project-payments`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Paddle-Signature": signEvent(invalidRaw, secret, timestamp)
      },
      body: invalidRaw
    })).status, 400);
  });
});

test("checkout and portal use an injected server identity; fixture header auth is explicitly fail-closed", async context => {
  const { store } = await temporaryStore(context, "auth");
  const configuration = enabledConfiguration({ VIBENEST_PROJECT_PAYMENTS_VERIFIER_ENABLED: "false" });
  const app = createApp(configuration, {
    store,
    processor: noOpProcessor(),
    resolveAuthenticatedIdentity: async () => ({ subjectKey: "server-session-user" })
  });

  await withServer(context, app, async baseUrl => {
    const checkout = await fetch(`${baseUrl}/api/project-payments/checkout`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-Fixture-Authenticated-Buyer": "attacker" },
      body: JSON.stringify({ priceKey: "monthly" })
    });
    assert.equal(checkout.status, 200);

    const payloadBuyerAttempt = await fetch(`${baseUrl}/api/project-payments/checkout`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ priceKey: "monthly", buyerKey: "attacker" })
    });
    assert.equal(payloadBuyerAttempt.status, 400);

    const portal = await fetch(`${baseUrl}/api/project-payments/portal`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: "{}"
    });
    assert.equal(portal.status, 200);
    assert.match((await portal.json()).url, new RegExp(simulatorCustomerIdForSubject("server-session-user")));
  });

  const state = await store.snapshot();
  assert.equal(state.customerSubjects[simulatorCustomerIdForSubject("server-session-user")], "server-session-user");
  assert.equal(Object.values(state.customerSubjects).includes("attacker"), false);

  const fixtureShimApp = createApp(configuration, { store, processor: noOpProcessor() });
  await withServer(context, fixtureShimApp, async baseUrl => {
    assert.equal((await fetch(`${baseUrl}/api/project-payments/checkout`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ priceKey: "monthly" })
    })).status, 401);
  });
});

test("reference provider prices stay consistent with the manifest", async () => {
  const manifest = await readFile(new URL("../.vibenest/payments.yaml", import.meta.url), "utf8");
  const provider = new SimulatorProjectPaymentProvider();
  const prices = await provider.previewPrices(["monthly", "lifetime"]);

  for (const price of prices) {
    const definition = Object.values(referenceCatalog.products)
      .map(product => product.prices[price.priceKey])
      .find(Boolean);
    assert.ok(definition);
    assert.equal(price.unitAmount, definition.unitAmount);
    assert.equal(price.currency, definition.currency);
    assert.match(manifest, new RegExp(
      `- key: ${price.priceKey}\\s+currency: ${price.currency}\\s+unitAmount: ${price.unitAmount}\\s+type: ${definition.type}`,
      "m"
    ));
  }
  assert.equal(prices.find(price => price.priceKey === "monthly").interval, "month");
  assert.equal(prices.find(price => price.priceKey === "lifetime").interval, null);
});

test("disabled provider fails closed", async () => {
  const provider = new DisabledProjectPaymentProvider();
  await assert.rejects(provider.previewPrices(), /disabled/);
  await assert.rejects(provider.createCheckout(), /disabled/);
  await assert.rejects(provider.createPortal(), /disabled/);
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
  catalog = referenceCatalog,
  billingPeriodStart = occurredAt,
  billingPeriodEnd
}) {
  const product = catalog.products.pro;
  const price = product.prices[priceKey];
  return envelope(eventId, eventType, occurredAt, {
    id: transactionId,
    status,
    customer_id: customerId,
    subscription_id: subscriptionId,
    items: [{
      price_id: price.providerPriceId,
      product_id: product.providerProductId,
      quantity: 1,
      billing_period: price.type === "recurring"
        ? billingPeriod(billingPeriodStart, price.interval, billingPeriodEnd)
        : null
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
  scheduledChangeAt = null,
  billingPeriodStart = occurredAt,
  billingPeriodEnd,
  catalog = referenceCatalog
}) {
  const product = catalog.products.pro;
  const price = product.prices.monthly;
  return envelope(eventId, eventType, occurredAt, {
    id: subscriptionId,
    status: eventType === "subscription.canceled" ? "canceled" : "active",
    customer_id: customerId,
    items: [{
      price_id: price.providerPriceId,
      product_id: product.providerProductId,
      quantity: 1
    }],
    current_billing_period: billingPeriod(billingPeriodStart, price.interval, billingPeriodEnd),
    scheduled_change: scheduledChangeAt === null
      ? null
      : { action: "cancel", effective_at: scheduledChangeAt },
    custom_data: { vibenest_environment_id: environmentId }
  });
}

function billingPeriod(startsAt, interval, explicitEndsAt) {
  if (explicitEndsAt) return { starts_at: startsAt, ends_at: explicitEndsAt };
  const starts = new Date(startsAt);
  const year = starts.getUTCFullYear();
  const month = starts.getUTCMonth();
  const day = starts.getUTCDate();
  const targetMonthIndex = interval === "month" ? month + 1 : month;
  const targetYear = interval === "year" ? year + 1 : year + Math.floor(targetMonthIndex / 12);
  const targetMonth = ((targetMonthIndex % 12) + 12) % 12;
  const lastTargetDay = new Date(Date.UTC(targetYear, targetMonth + 1, 0)).getUTCDate();
  const ends = new Date(Date.UTC(
    targetYear,
    targetMonth,
    Math.min(day, lastTargetDay),
    starts.getUTCHours(),
    starts.getUTCMinutes(),
    starts.getUTCSeconds(),
    starts.getUTCMilliseconds()
  ));
  return { starts_at: startsAt, ends_at: ends.toISOString() };
}

function adjustmentEvent({ eventId, eventType, occurredAt, adjustmentId, transactionId, status }) {
  const price = referenceCatalog.products.pro.prices.monthly;
  return envelope(eventId, eventType, occurredAt, {
    id: adjustmentId,
    action: "refund",
    status,
    transaction_id: transactionId,
    totals: { total: String(price.unitAmount), currency_code: price.currency },
    custom_data: { vibenest_environment_id: environmentId }
  });
}

function portalEvent({ eventId, occurredAt, customerId }) {
  return envelope(eventId, "customer.portal_session.created", occurredAt, {
    id: `sim_portal_${eventId}`,
    customer_id: customerId,
    url: `https://simulator.invalid/portal/${encodeURIComponent(environmentId)}/${encodeURIComponent(customerId)}`,
    expires_at: new Date(Date.parse(occurredAt) + 30 * 60 * 1_000).toISOString(),
    custom_data: { vibenest_environment_id: environmentId }
  });
}

function envelope(eventId, eventType, occurredAt, data) {
  return {
    event_id: eventId,
    event_type: eventType,
    occurred_at: occurredAt,
    notification_id: `sim_ntf_${eventId}`,
    data
  };
}

async function deliver(store, payload, options = {}) {
  const rawBody = options.rawBody ?? Buffer.from(JSON.stringify(payload), "utf8");
  const timestamp = options.timestamp ?? Math.floor(Date.now() / 1000);
  return acceptSignedEvent({
    rawBody,
    signature: options.signature ?? signEvent(rawBody, secret, timestamp),
    secret: options.secret ?? secret,
    nowSeconds: timestamp,
    destinationKey: options.destinationKey ?? environmentId,
    expectedEnvironmentId: options.expectedEnvironmentId ?? environmentId,
    evidenceScope: options.evidenceScope ?? evidenceScope,
    catalog: options.catalog ?? referenceCatalog,
    store
  });
}

async function bindBuyer(store, subjectKey) {
  const customerId = simulatorCustomerIdForSubject(subjectKey);
  await store.bindCustomer(customerId, subjectKey);
  return customerId;
}

async function checkoutBuyer(provider, subjectKey, priceKey) {
  await provider.createCheckout({ buyerKey: subjectKey, priceKey });
  return simulatorCustomerIdForSubject(subjectKey);
}

async function temporaryStore(context, label, instanceId = `${label}-receiver`) {
  const directory = await mkdtemp(join(tmpdir(), `vn-pp-node-${label}-`));
  const file = join(directory, "store.sqlite");
  context.after(async () => {
    DurableProjectPaymentStore.closeAllForPath(file);
    await rm(directory, { recursive: true, force: true });
  });
  return {
    directory,
    file,
    store: new DurableProjectPaymentStore(file, { instanceId, evidenceScope })
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

function enabledConfiguration(overrides = {}) {
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

function runtimeCatalogProjection({
  productExternalId = referenceCatalog.products.pro.providerProductId,
  monthlyExternalId = referenceCatalog.products.pro.prices.monthly.providerPriceId,
  lifetimeExternalId = referenceCatalog.products.pro.prices.lifetime.providerPriceId,
  monthlyInterval = referenceCatalog.products.pro.prices.monthly.interval,
  grants = referenceCatalog.products.pro.grants
} = {}) {
  return {
    provider: "simulator",
    sellerExternalId: "sim_seller_fixture",
    environmentExternalId: environmentId,
    manifestDigest,
    products: [{
      manifestKey: "pro",
      externalId: productExternalId,
      prices: [
        {
          manifestKey: "monthly",
          externalId: monthlyExternalId,
          currency: "USD",
          unitAmount: 1500,
          type: "recurring",
          interval: monthlyInterval
        },
        {
          manifestKey: "lifetime",
          externalId: lifetimeExternalId,
          currency: "USD",
          unitAmount: 9900,
          type: "one_time",
          interval: null
        }
      ],
      grants: grants.map(grant => ({ ...grant }))
    }]
  };
}

function encodeRuntimeCatalog(projection) {
  return Buffer.from(JSON.stringify(projection), "utf8").toString("base64");
}

function verifierHeaders() {
  return {
    "X-VibeNest-Simulator-Secret": secret,
    "X-VibeNest-Expected-Commit": commitSha,
    "X-VibeNest-Expected-Manifest-Digest": manifestDigest
  };
}

function verifierReadyStore() {
  return {
    evidenceScope,
    async verificationStatus() {
      return { lifecyclePassed: true, durableInbox: true, restartReplayPassed: true };
    },
    async processDue() {
      return { applied: 0, ignored: 0, deferred: 0 };
    }
  };
}

function noOpProcessor() {
  return {
    start() {},
    wake() { return Promise.resolve(); },
    stop() { return Promise.resolve(); }
  };
}

async function withServer(context, app, work) {
  const server = app.listen(0, "127.0.0.1");
  await new Promise((resolve, reject) => {
    server.once("listening", resolve);
    server.once("error", reject);
  });
  context.after(async () => {
    await app.locals.projectPayments.processor.stop();
    await new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
  });
  const address = server.address();
  await work(`http://127.0.0.1:${address.port}`);
}
