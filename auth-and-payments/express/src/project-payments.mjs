import { createHash, createHmac, randomUUID, timingSafeEqual } from "node:crypto";
import { mkdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { TextDecoder } from "node:util";

const minimumSecretBytes = 32;
const maximumWebhookBytes = 128 * 1024;
const providerEvidenceAuthority = Symbol("provider-evidence-authority");
const openStoresByPath = new Map();
const restartReplayProbeEventType = "vibenest.restart_replay_probe";
const strictUtf8 = new TextDecoder("utf-8", { fatal: true });
const verifierCommitPattern = /^[0-9a-f]{40}$/;
const verifierDigestPattern = /^[0-9a-f]{64}$/;
const identifierPattern = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,159}$/;
const manifestKeyPattern = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;
const entitlementKeyPattern = /^[a-z0-9]+(?:[-_][a-z0-9]+)*$/;
const isoTimestampPattern = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})$/;

export const providerModes = Object.freeze({
  simulator: "simulator",
  paddle: "paddle",
  disabled: "disabled"
});

// These observations are derived from successful provider operations and processed,
// signature-verified simulator events. Secret scanning remains control-plane/CI evidence;
// an application runtime cannot honestly attest to a repository scan.
export const requiredLifecycleEvidence = Object.freeze([
  "price-preview",
  "one-time-purchase",
  "subscription-purchase",
  "declined-checkout",
  "duplicate-delivery",
  "out-of-order-delivery",
  "renewal",
  "scheduled-cancellation",
  "immediate-refund",
  "customer-portal"
]);

export function computeRuntimeEvidenceScope(environmentId, manifestDigest, builtCommit) {
  requireOpaqueIdentifier(environmentId, "Evidence environment id");
  if (!verifierDigestPattern.test(manifestDigest ?? "")) throw new Error("The evidence manifest digest is invalid.");
  if (!verifierCommitPattern.test(builtCommit ?? "")) throw new Error("The evidence build commit is invalid.");
  return createHash("sha256")
    .update("vibenest-project-payments-evidence-v1\0", "utf8")
    .update(environmentId, "utf8")
    .update("\0", "utf8")
    .update(manifestDigest, "ascii")
    .update("\0", "utf8")
    .update(builtCommit, "ascii")
    .digest("hex");
}

// This fixture catalog deliberately mirrors .vibenest/payments.yaml. An adapted
// application should hydrate providerProductId/providerPriceId from its server-owned
// applied catalog mapping, never from checkout input or webhook custom_data.
export const referenceCatalog = deepFreeze({
  products: {
    pro: {
      providerProductId: "pro",
      grants: [{ entitlement: "premium-access", quantity: 1 }],
      prices: {
        monthly: {
          providerPriceId: "monthly",
          currency: "USD",
          unitAmount: 1500,
          type: "recurring",
          interval: "month"
        },
        lifetime: {
          providerPriceId: "lifetime",
          currency: "USD",
          unitAmount: 9900,
          type: "one_time",
          interval: null
        }
      }
    }
  }
});

export class DisabledProjectPaymentProvider {
  mode = providerModes.disabled;
  async previewPrices() { throw new Error("Project payments are disabled."); }
  async createCheckout() { throw new Error("Project payments are disabled."); }
  async createPortal() { throw new Error("Project payments are disabled."); }
}

export function parseRuntimeCatalog(encoded, { expectedEnvironmentId, expectedManifestDigest }) {
  requireOpaqueIdentifier(expectedEnvironmentId, "Expected environment id");
  if (!verifierDigestPattern.test(expectedManifestDigest ?? ""))
    throw new Error("The installed manifest digest is invalid.");
  if (typeof encoded !== "string" || encoded.length === 0 || encoded.length > 65_536
      || encoded.length % 4 !== 0
      || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(encoded)) {
    throw new Error("The simulator runtime catalog must be canonical RFC4648 base64.");
  }

  const bytes = Buffer.from(encoded, "base64");
  if (bytes.length === 0 || bytes.length > 48 * 1024 || bytes.toString("base64") !== encoded)
    throw new Error("The simulator runtime catalog is invalid or exceeds the runtime limit.");
  let json;
  try { json = strictUtf8.decode(bytes); }
  catch { throw new Error("The simulator runtime catalog is not valid UTF-8."); }
  let projection;
  try { projection = JSON.parse(json); }
  catch { throw new Error("The simulator runtime catalog is not valid JSON."); }

  requireExactCatalogObject(
    projection,
    ["provider", "sellerExternalId", "environmentExternalId", "manifestDigest", "products"],
    "runtime catalog"
  );
  if (projection.provider !== providerModes.simulator)
    throw new Error("The runtime catalog is not a simulator catalog.");
  requireOpaqueIdentifier(projection.sellerExternalId, "Runtime seller id");
  requireOpaqueIdentifier(projection.environmentExternalId, "Runtime environment id");
  if (!safeEqualText(projection.environmentExternalId, expectedEnvironmentId))
    throw new Error("The runtime catalog targets a different seller environment.");
  if (!verifierDigestPattern.test(projection.manifestDigest ?? "")
      || !safeEqualText(projection.manifestDigest, expectedManifestDigest))
    throw new Error("The runtime catalog manifest digest does not match the installed manifest.");
  if (!Array.isArray(projection.products) || projection.products.length === 0 || projection.products.length > 100)
    throw new Error("The runtime catalog must contain a bounded product list.");

  const products = Object.create(null);
  const productExternalIds = new Set();
  const priceExternalIds = new Set();
  for (const product of projection.products) {
    requireExactCatalogObject(product, ["manifestKey", "externalId", "prices", "grants"], "runtime product");
    requireManifestKey(product.manifestKey, "Runtime product key");
    requireOpaqueIdentifier(product.externalId, "Runtime product external id");
    if (Object.hasOwn(products, product.manifestKey) || productExternalIds.has(product.externalId))
      throw new Error("Runtime product keys and external ids must be unique.");
    productExternalIds.add(product.externalId);
    if (!Array.isArray(product.grants) || product.grants.length === 0 || product.grants.length > 100)
      throw new Error("A runtime product must contain bounded trusted grants.");
    const grants = product.grants.map(grant => {
      requireExactCatalogObject(grant, ["entitlement", "quantity"], "runtime grant");
      requireEntitlementKey(grant.entitlement, "Runtime grant entitlement");
      if (!Number.isSafeInteger(grant.quantity) || grant.quantity <= 0)
        throw new Error("Runtime grant quantity must be a positive integer.");
      return { entitlement: grant.entitlement, quantity: grant.quantity };
    });
    if (new Set(grants.map(grant => grant.entitlement)).size !== grants.length)
      throw new Error("Runtime grant entitlements must be unique.");
    if (!Array.isArray(product.prices) || product.prices.length === 0 || product.prices.length > 100)
      throw new Error("A runtime product must contain a bounded price list.");

    const prices = Object.create(null);
    for (const price of product.prices) {
      requireExactCatalogObject(
        price,
        ["manifestKey", "externalId", "currency", "unitAmount", "type", "interval"],
        "runtime price"
      );
      requireManifestKey(price.manifestKey, "Runtime price key");
      requireOpaqueIdentifier(price.externalId, "Runtime price external id");
      if (Object.hasOwn(prices, price.manifestKey) || priceExternalIds.has(price.externalId))
        throw new Error("Runtime price keys within a product and external ids globally must be unique.");
      priceExternalIds.add(price.externalId);
      prices[price.manifestKey] = {
        providerPriceId: price.externalId,
        currency: price.currency,
        unitAmount: price.unitAmount,
        type: price.type,
        interval: price.interval
      };
    }
    products[product.manifestKey] = {
      providerProductId: product.externalId,
      grants,
      prices
    };
  }

  const catalog = {
    products,
    manifestDigest: projection.manifestDigest,
    environmentExternalId: projection.environmentExternalId
  };
  validateCatalog(catalog);
  return deepFreeze(catalog);
}

export class SimulatorProjectPaymentProvider {
  mode = providerModes.simulator;

  constructor({ catalog = referenceCatalog, store = null } = {}) {
    validateCatalog(catalog);
    this.catalog = catalog;
    this.store = store;
  }

  async previewPrices(priceKeys) {
    if (!Array.isArray(priceKeys) || priceKeys.length === 0 || priceKeys.length > 20)
      throw new Error("One or more trusted catalog price keys are required.");
    const prices = priceKeys.map(priceKey => {
      const mapped = resolveCatalogPriceByKey(this.catalog, priceKey);
      return {
        priceKey,
        unitAmount: mapped.unitAmount,
        currency: mapped.currency,
        type: mapped.type,
        interval: mapped.interval,
        formatted: `${mapped.currency} ${(mapped.unitAmount / 100).toFixed(2)}`
      };
    });
    if (this.store) {
      await this.store.recordProviderEvidence(providerEvidenceAuthority, "price-preview", {
        priceKeys: prices.map(price => price.priceKey)
      });
    }
    return prices;
  }

  async createCheckout({ buyerKey, priceKey }) {
    requireOpaqueIdentifier(buyerKey, "Authenticated buyer");
    resolveCatalogPriceByKey(this.catalog, priceKey);
    const providerCustomerId = simulatorCustomerIdForSubject(buyerKey);
    if (this.store) await this.store.bindCustomer(providerCustomerId, buyerKey);
    return {
      id: stableId("sim_checkout", buyerKey, priceKey),
      expiresAt: new Date(Date.now() + 900_000).toISOString()
    };
  }

  async createPortal(buyerKey) {
    requireOpaqueIdentifier(buyerKey, "Authenticated buyer");
    const providerCustomerId = simulatorCustomerIdForSubject(buyerKey);
    if (this.store) {
      await this.store.bindCustomer(providerCustomerId, buyerKey);
      await this.store.recordProviderEvidence(providerEvidenceAuthority, "customer-portal", {
        providerCustomerId
      });
    }
    return {
      url: `https://simulator.invalid/portal/${encodeURIComponent(providerCustomerId)}`,
      expiresAt: new Date(Date.now() + 900_000).toISOString()
    };
  }
}

// The fixture uses SQLite so ACK, conditional leases, retries, projections and effects all
// survive a process restart. A production integration may substitute PostgreSQL while keeping
// the same transactional boundaries and immutable provider-source rules.
export class DurableProjectPaymentStore {
  constructor(filePath, {
    instanceId = randomUUID(),
    leaseSeconds = 30,
    maxAttempts = 10,
    baseBackoffSeconds = 30,
    maxBackoffSeconds = 1_800,
    evidenceScope = null
  } = {}) {
    if (typeof filePath !== "string" || filePath.trim() === "") throw new Error("A SQLite store path is required.");
    requireOpaqueIdentifier(instanceId, "Store instance id");
    if (!Number.isSafeInteger(leaseSeconds) || leaseSeconds < 1) throw new Error("Lease seconds must be positive.");
    if (!Number.isSafeInteger(maxAttempts) || maxAttempts < 1) throw new Error("Max attempts must be positive.");
    if (!Number.isSafeInteger(baseBackoffSeconds) || baseBackoffSeconds < 1)
      throw new Error("Base backoff seconds must be positive.");
    if (!Number.isSafeInteger(maxBackoffSeconds) || maxBackoffSeconds < baseBackoffSeconds)
      throw new Error("Maximum backoff seconds must not be below the base backoff.");
    if (evidenceScope !== null && !verifierDigestPattern.test(evidenceScope))
      throw new Error("The lifecycle evidence scope must be a SHA-256 digest.");
    this.filePath = resolve(filePath);
    this.instanceId = instanceId;
    this.leaseSeconds = leaseSeconds;
    this.maxAttempts = maxAttempts;
    this.baseBackoffSeconds = baseBackoffSeconds;
    this.maxBackoffSeconds = maxBackoffSeconds;
    this.evidenceScope = evidenceScope;
    mkdirSync(dirname(this.filePath), { recursive: true });
    this.db = new DatabaseSync(this.filePath);
    this.db.exec("PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON; PRAGMA busy_timeout = 5000;");
    this.#migrate();
    const openStores = openStoresByPath.get(this.filePath) ?? new Set();
    openStores.add(this);
    openStoresByPath.set(this.filePath, openStores);
  }

  close() {
    if (!this.db) return;
    this.db.close();
    this.db = null;
    const openStores = openStoresByPath.get(this.filePath);
    openStores?.delete(this);
    if (openStores?.size === 0) openStoresByPath.delete(this.filePath);
  }

  static closeAllForPath(filePath) {
    const resolvedPath = resolve(filePath);
    for (const store of [...(openStoresByPath.get(resolvedPath) ?? [])]) store.close();
  }

  async bindCustomer(providerCustomerId, subjectKey) {
    requireOpaqueIdentifier(providerCustomerId, "Provider customer id");
    requireOpaqueIdentifier(subjectKey, "Authenticated subject");
    return this.#transaction(() => {
      const byCustomer = this.db.prepare(
        "SELECT subject_key FROM project_payment_customer_binding WHERE provider_customer_id = ?"
      ).get(providerCustomerId);
      const bySubject = this.db.prepare(
        "SELECT provider_customer_id FROM project_payment_customer_binding WHERE subject_key = ?"
      ).get(subjectKey);
      if ((byCustomer && byCustomer.subject_key !== subjectKey)
          || (bySubject && bySubject.provider_customer_id !== providerCustomerId)) {
        throw new Error("A provider customer binding cannot be reassigned.");
      }
      this.db.prepare(`
        INSERT OR IGNORE INTO project_payment_customer_binding(provider_customer_id, subject_key, created_at)
        VALUES (?, ?, ?)
      `).run(providerCustomerId, subjectKey, new Date().toISOString());
      return { providerCustomerId, subjectKey };
    });
  }

  async resolveSubject(providerCustomerId) {
    requireOpaqueIdentifier(providerCustomerId, "Provider customer id");
    return this.db.prepare(
      "SELECT subject_key FROM project_payment_customer_binding WHERE provider_customer_id = ?"
    ).get(providerCustomerId)?.subject_key ?? null;
  }

  async insertVerifiedEvent(event, receivedAt = new Date()) {
    validateNormalizedEvent(event);
    const receivedIso = requireOperationalDate(receivedAt, "Received at").toISOString();
    return this.#transaction(() => {
      const existing = this.db.prepare(`
        SELECT body_sha256 FROM project_payment_webhook_event
        WHERE destination_key = ? AND provider_event_id = ?
      `).get(event.destinationKey, event.eventId);
      if (existing) {
        if (!safeEqualHex(existing.body_sha256, event.bodyDigest))
          throw new InvalidSimulatorEventError("A provider event id was reused with different signed bytes.");
        this.db.prepare(`
          UPDATE project_payment_webhook_event SET delivery_count = delivery_count + 1
          WHERE destination_key = ? AND provider_event_id = ?
        `).run(event.destinationKey, event.eventId);
        this.#recordEvidence(event.evidenceScope, "duplicate-delivery", event.eventId, receivedIso);
        return { inserted: false, eventId: event.eventId };
      }
      this.db.prepare(`
        INSERT INTO project_payment_webhook_event(
          destination_key, provider_event_id, event_type, occurred_at, received_at,
          body_sha256, normalized_payload, next_attempt_at, received_by_instance_id)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run(
        event.destinationKey,
        event.eventId,
        event.eventType,
        event.occurredAt,
        receivedIso,
        event.bodyDigest,
        JSON.stringify(event),
        receivedIso,
        this.instanceId
      );
      return { inserted: true, eventId: event.eventId };
    });
  }

  async stageRestartReplayProbe(destinationKey, now = new Date()) {
    requireOpaqueIdentifier(destinationKey, "Restart replay destination");
    if (!verifierDigestPattern.test(this.evidenceScope ?? ""))
      throw new Error("Restart replay requires an exact runtime evidence scope.");
    const stagedAt = requireOperationalDate(now, "Restart replay stage time").toISOString();
    const eventId = stableId("vn_restart_probe", destinationKey, this.evidenceScope, this.instanceId);
    const event = {
      destinationKey,
      eventId,
      eventType: restartReplayProbeEventType,
      occurredAt: stagedAt,
      bodyDigest: createHash("sha256")
        .update(`restart-replay\0${destinationKey}\0${this.evidenceScope}\0${this.instanceId}`, "utf8")
        .digest("hex"),
      evidenceScope: this.evidenceScope,
      effectKind: "restart-replay-probe",
      environmentId: destinationKey
    };
    this.#transaction(() => this.db.prepare(`
      INSERT OR IGNORE INTO project_payment_webhook_event(
        destination_key, provider_event_id, event_type, occurred_at, received_at,
        body_sha256, normalized_payload, next_attempt_at, received_by_instance_id)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      destinationKey,
      eventId,
      restartReplayProbeEventType,
      stagedAt,
      stagedAt,
      event.bodyDigest,
      JSON.stringify(event),
      stagedAt,
      this.instanceId
    ));
    return { action: "restart-replay", state: "staged" };
  }

  async claimDue(now = new Date()) {
    const nowDate = requireOperationalDate(now, "Claim time");
    const nowIso = nowDate.toISOString();
    const leaseId = randomUUID();
    const leaseExpiresAt = new Date(nowDate.getTime() + this.leaseSeconds * 1_000).toISOString();
    return this.#transaction(() => {
      const candidate = this.db.prepare(`
        SELECT id FROM project_payment_webhook_event
        WHERE processed_at IS NULL AND dead_lettered_at IS NULL AND next_attempt_at <= ?
          AND (lease_id IS NULL OR lease_expires_at <= ?)
          AND (event_type <> ? OR received_by_instance_id <> ?)
        ORDER BY next_attempt_at, received_at, id
        LIMIT 1
      `).get(nowIso, nowIso, restartReplayProbeEventType, this.instanceId);
      if (!candidate) return null;
      const updated = this.db.prepare(`
        UPDATE project_payment_webhook_event
        SET lease_id = ?, lease_expires_at = ?, last_attempt_at = ?, attempt_count = attempt_count + 1
        WHERE id = ? AND processed_at IS NULL AND dead_lettered_at IS NULL AND next_attempt_at <= ?
          AND (lease_id IS NULL OR lease_expires_at <= ?)
          AND (event_type <> ? OR received_by_instance_id <> ?)
      `).run(
        leaseId,
        leaseExpiresAt,
        nowIso,
        candidate.id,
        nowIso,
        nowIso,
        restartReplayProbeEventType,
        this.instanceId
      );
      if (updated.changes !== 1) return null;
      return this.db.prepare("SELECT * FROM project_payment_webhook_event WHERE id = ?").get(candidate.id);
    });
  }

  async processDue({ now = new Date(), maxEvents = 100 } = {}) {
    const nowDate = requireOperationalDate(now, "Processing time");
    if (!Number.isSafeInteger(maxEvents) || maxEvents < 1 || maxEvents > 1_000)
      throw new Error("maxEvents must be between 1 and 1000.");
    const result = { applied: 0, ignored: 0, deferred: 0, failed: 0, deadLettered: 0 };
    for (let index = 0; index < maxEvents; index += 1) {
      const claim = await this.claimDue(nowDate);
      if (!claim) break;
      try {
        const outcome = this.#applyClaim(claim, nowDate);
        if (outcome === "applied" || outcome === "observed") result.applied += 1;
        else if (outcome === "stale") result.ignored += 1;
        else if (outcome === "deferred") {
          result.deferred += 1;
          if (this.#releaseClaim(claim, nowDate, "A referenced projection is not available yet."))
            result.deadLettered += 1;
        }
      } catch {
        result.failed += 1;
        if (this.#releaseClaim(claim, nowDate, "Project Payments event processing failed."))
          result.deadLettered += 1;
      }
    }
    return result;
  }

  async recordProviderEvidence(authority, name, _details, observedAt = new Date()) {
    if (authority !== providerEvidenceAuthority || !["price-preview", "customer-portal"].includes(name))
      throw new Error("Lifecycle evidence must be produced by a trusted provider operation.");
    if (!this.evidenceScope) throw new Error("Trusted provider evidence requires an exact runtime scope.");
    const observedIso = requireOperationalDate(observedAt, "Evidence time").toISOString();
    this.#transaction(() => this.#recordEvidence(this.evidenceScope, name, null, observedIso));
  }

  async hasEntitlement(subjectKey, grantKey, now = new Date()) {
    requireOpaqueIdentifier(subjectKey, "Authenticated subject");
    requireEntitlementKey(grantKey, "Grant key");
    const row = this.db.prepare(`
      SELECT status, effective_until FROM project_payment_entitlement
      WHERE subject_key = ? AND grant_key = ?
    `).get(subjectKey, grantKey);
    if (!row || !["active", "scheduled_cancel"].includes(row.status)) return false;
    return row.effective_until === null
      || Date.parse(row.effective_until) > requireOperationalDate(now, "Entitlement time").getTime();
  }

  async snapshot() {
    const events = this.db.prepare("SELECT * FROM project_payment_webhook_event ORDER BY id").all().map(row => ({
      id: Number(row.id),
      destinationKey: row.destination_key,
      eventId: row.provider_event_id,
      eventType: row.event_type,
      occurredAt: row.occurred_at,
      receivedAt: row.received_at,
      bodyDigest: row.body_sha256,
      nextAttemptAt: row.next_attempt_at,
      lastAttemptAt: row.last_attempt_at,
      attemptCount: Number(row.attempt_count),
      deliveryCount: Number(row.delivery_count),
      leaseId: row.lease_id,
      leaseExpiresAt: row.lease_expires_at,
      processedAt: row.processed_at,
      processedByInstanceId: row.processed_by_instance_id,
      receivedByInstanceId: row.received_by_instance_id,
      ignoredAsStale: Number(row.ignored_as_stale) === 1,
      processingError: row.last_error,
      deadLetteredAt: row.dead_lettered_at
    }));
    const entitlements = Object.fromEntries(this.db.prepare(
      "SELECT * FROM project_payment_entitlement ORDER BY subject_key, grant_key"
    ).all().map(row => [`${row.subject_key}:${row.grant_key}`, mapEntitlementRow(row)]));
    const entitlementSources = this.db.prepare(
      "SELECT * FROM project_payment_entitlement_source ORDER BY subject_key, grant_key, source_key"
    ).all().map(row => ({
      ...mapEntitlementRow(row),
      sourceKey: row.source_key,
      providerSubscriptionId: row.provider_subscription_id,
      providerTransactionId: row.provider_transaction_id
    }));
    const subscriptions = Object.fromEntries(this.db.prepare(
      "SELECT * FROM project_payment_subscription ORDER BY provider_subscription_id"
    ).all().map(row => [row.provider_subscription_id, mapProjectionRow(row, true)]));
    const transactions = Object.fromEntries(this.db.prepare(
      "SELECT * FROM project_payment_transaction ORDER BY provider_transaction_id"
    ).all().map(row => [row.provider_transaction_id, mapProjectionRow(row, false)]));
    const customerSubjects = Object.fromEntries(this.db.prepare(
      "SELECT provider_customer_id, subject_key FROM project_payment_customer_binding ORDER BY provider_customer_id"
    ).all().map(row => [row.provider_customer_id, row.subject_key]));
    const evidence = this.db.prepare(
      "SELECT * FROM project_payment_evidence ORDER BY observed_at, name"
    ).all().map(row => ({
      scopeDigest: row.scope_digest,
      name: row.name,
      observedAt: row.observed_at,
      details: row.source_event_id ? { eventId: row.source_event_id } : {}
    }));
    return { events, entitlements, entitlementSources, subscriptions, transactions, customerSubjects, evidence };
  }

  async verificationStatus(evidenceScope = this.evidenceScope) {
    if (!verifierDigestPattern.test(evidenceScope ?? ""))
      return { lifecyclePassed: false, durableInbox: false, restartReplayPassed: false };
    const observed = new Set(this.db.prepare(
      "SELECT name FROM project_payment_evidence WHERE scope_digest = ?"
    ).all(evidenceScope).map(row => row.name));
    const counts = this.db.prepare(`
      SELECT COUNT(*) AS total,
        SUM(CASE WHEN processed_at IS NULL THEN 1 ELSE 0 END) AS pending,
        SUM(CASE WHEN dead_lettered_at IS NOT NULL THEN 1 ELSE 0 END) AS dead
      FROM project_payment_webhook_event
      WHERE json_extract(normalized_payload, '$.evidenceScope') = ?
    `).get(evidenceScope);
    return {
      lifecyclePassed: requiredLifecycleEvidence.every(name => observed.has(name)),
      durableInbox: Number(counts.total) > 0
        && Number(counts.pending ?? 0) === 0
        && Number(counts.dead ?? 0) === 0,
      restartReplayPassed: observed.has("restart-replay")
    };
  }

  #applyClaim(claim, now) {
    return this.#transaction(() => {
      const locked = this.db.prepare(`
        SELECT * FROM project_payment_webhook_event
        WHERE id = ? AND lease_id = ? AND processed_at IS NULL AND dead_lettered_at IS NULL
      `).get(claim.id, claim.lease_id);
      if (!locked) throw new Error("The webhook lease is no longer owned by this worker.");
      const event = JSON.parse(locked.normalized_payload);
      const outcome = this.#applyEvent(event, now);
      if (outcome === "deferred") return "deferred";
      const processedAt = now.toISOString();
      const marked = this.db.prepare(`
        UPDATE project_payment_webhook_event
        SET processed_at = ?, processed_by_instance_id = ?, ignored_as_stale = ?,
            lease_id = NULL, lease_expires_at = NULL, last_error = NULL
        WHERE id = ? AND lease_id = ? AND processed_at IS NULL
      `).run(processedAt, this.instanceId, outcome === "stale" ? 1 : 0, locked.id, locked.lease_id);
      if (marked.changes !== 1) throw new Error("The webhook lease was lost while applying effects.");
      if (locked.received_by_instance_id !== this.instanceId)
        this.#recordEvidence(event.evidenceScope, "restart-replay", event.eventId, processedAt);
      if (outcome === "stale")
        this.#recordEvidence(event.evidenceScope, "out-of-order-delivery", event.eventId, processedAt);
      return outcome;
    });
  }

  #releaseClaim(claim, now, publicError) {
    const attemptCount = Number(claim.attempt_count);
    const deadLettered = attemptCount >= this.maxAttempts;
    const delaySeconds = Math.min(
      this.maxBackoffSeconds,
      this.baseBackoffSeconds * (2 ** Math.max(0, attemptCount - 1))
    );
    const nextAttemptAt = new Date(now.getTime() + delaySeconds * 1_000).toISOString();
    const result = this.db.prepare(`
      UPDATE project_payment_webhook_event
      SET lease_id = NULL, lease_expires_at = NULL, next_attempt_at = ?, last_error = ?,
          dead_lettered_at = CASE WHEN ? = 1 THEN ? ELSE dead_lettered_at END
      WHERE id = ? AND lease_id = ? AND processed_at IS NULL
    `).run(nextAttemptAt, publicError, deadLettered ? 1 : 0, now.toISOString(), claim.id, claim.lease_id);
    return result.changes === 1 && deadLettered;
  }

  #applyEvent(event, now) {
    switch (event.effectKind) {
      case "restart-replay-probe":
        if (event.eventType !== restartReplayProbeEventType
            || !safeEqualText(event.evidenceScope ?? "", this.evidenceScope ?? "")) {
          throw new InvalidSimulatorEventError("The restart replay probe is not bound to this exact runtime build.");
        }
        return "observed";
      case "transaction-completed": {
        const continuity = this.#validateTransactionContinuity(event);
        if (continuity) return continuity;
        this.#upsertTransaction(event);
        const outcome = this.#applyEntitlements(event, "active", event.billingPeriod?.endsAt ?? null);
        if (event.priceType === "one_time")
          this.#recordEvidence(event.evidenceScope, "one-time-purchase", event.eventId, now.toISOString());
        return outcome;
      }
      case "transaction-declined":
        this.#recordEvidence(event.evidenceScope, "declined-checkout", event.eventId, now.toISOString());
        return "observed";
      case "subscription-created": {
        const current = this.#subscription(event.providerSubscriptionId);
        if (current) {
          this.#assertSubscriptionIdentity(current, event);
          const periodComparison = compareBillingPeriods(event.billingPeriod, rowBillingPeriod(current));
          if (periodComparison < 0) return "stale";
          if (periodComparison > 0)
            throw new InvalidSimulatorEventError("A subscription id cannot be recreated for another billing period.");
          if (compareEventWithRow(event, current) < 0) return "stale";
          if (current.status !== "active")
            throw new InvalidSimulatorEventError("A terminal subscription id cannot be created again.");
          return "stale";
        }
        const priorTransaction = this.db.prepare(`
          SELECT * FROM project_payment_transaction WHERE provider_subscription_id = ?
          ORDER BY occurred_at LIMIT 1
        `).get(event.providerSubscriptionId);
        if (priorTransaction) {
          this.#assertProjectionIdentity(priorTransaction, event, "subscription");
          if (compareBillingPeriods(rowBillingPeriod(priorTransaction), event.billingPeriod) !== 0)
            throw new InvalidSimulatorEventError("A transaction-first subscription must confirm the same authoritative period.");
        }
        this.#upsertSubscription(event, "active", event.billingPeriod.endsAt);
        const outcome = this.#applyEntitlements(event, "active", event.billingPeriod.endsAt);
        this.#recordEvidence(event.evidenceScope, "subscription-purchase", event.eventId, now.toISOString());
        return outcome;
      }
      case "subscription-updated": {
        const continuity = this.#validateSubscriptionContinuity(event, "advance");
        if (continuity) return continuity;
        this.#upsertSubscription(event, "active", event.billingPeriod.endsAt);
        return this.#applyEntitlements(event, "active", event.billingPeriod.endsAt);
      }
      case "subscription-scheduled-cancel": {
        const continuity = this.#validateSubscriptionContinuity(event, "reuse");
        if (continuity) return continuity;
        this.#upsertSubscription(event, "scheduled_cancel", event.effectiveUntil);
        const outcome = this.#applyEntitlements(event, "scheduled_cancel", event.effectiveUntil);
        this.#recordEvidence(event.evidenceScope, "scheduled-cancellation", event.eventId, now.toISOString());
        return outcome;
      }
      case "subscription-canceled": {
        const continuity = this.#validateSubscriptionContinuity(event, "reuse-for-cancel");
        if (continuity) return continuity;
        this.#upsertSubscription(event, "revoked", event.occurredAt);
        const outcome = this.#applyEntitlements(event, "revoked", event.occurredAt);
        this.#recordImmediateRefundIfComplete(
          event.providerSubscriptionId,
          event.evidenceScope,
          event.eventId,
          now.toISOString()
        );
        return outcome;
      }
      case "adjustment-pending":
        return "observed";
      case "adjustment-approved": {
        const transaction = this.db.prepare(
          "SELECT * FROM project_payment_transaction WHERE provider_transaction_id = ?"
        ).get(event.providerTransactionId);
        if (!transaction) return "deferred";
        if (transaction.environment_id !== event.environmentId
            || Number(transaction.amount_minor) !== event.amountMinor
            || transaction.currency !== event.currency)
          throw new InvalidSimulatorEventError("The approved refund does not match its trusted transaction projection.");
        if (Date.parse(event.occurredAt) < Date.parse(transaction.occurred_at))
          throw new InvalidSimulatorEventError("A refund cannot precede its trusted transaction.");
        const resolved = {
          ...event,
          environmentId: transaction.environment_id,
          subjectKey: transaction.subject_key,
          grants: JSON.parse(transaction.grants_json),
          providerProductId: transaction.provider_product_id,
          providerPriceId: transaction.provider_price_id,
          productKey: transaction.product_key,
          priceKey: transaction.price_key,
          priceType: transaction.price_type,
          providerSubscriptionId: transaction.provider_subscription_id,
          billingPeriod: rowBillingPeriod(transaction)
        };
        this.db.prepare(`
          INSERT INTO project_payment_refund(provider_transaction_id, provider_subscription_id, source_event_id, approved_at)
          VALUES (?, ?, ?, ?)
          ON CONFLICT(provider_transaction_id) DO UPDATE SET
            provider_subscription_id = excluded.provider_subscription_id,
            source_event_id = excluded.source_event_id,
            approved_at = excluded.approved_at
        `).run(event.providerTransactionId, transaction.provider_subscription_id, event.eventId, event.occurredAt);
        const outcome = this.#applyEntitlements(resolved, "revoked", event.occurredAt);
        this.#recordImmediateRefundIfComplete(
          transaction.provider_subscription_id,
          event.evidenceScope,
          event.eventId,
          now.toISOString()
        );
        return outcome;
      }
      case "portal-created":
        this.#recordEvidence(event.evidenceScope, "customer-portal", event.eventId, now.toISOString());
        return "observed";
      default:
        throw new InvalidSimulatorEventError("The normalized event effect is unsupported.");
    }
  }

  #applyEntitlements(event, status, effectiveUntil) {
    let applied = 0;
    let renewalAdvanced = false;
    const sourceKey = event.providerSubscriptionId
      ? `subscription:${event.providerSubscriptionId}`
      : event.providerTransactionId
        ? `transaction:${event.providerTransactionId}`
        : null;
    if (!sourceKey) throw new InvalidSimulatorEventError("An entitlement effect has no immutable provider source.");
    for (const grant of event.grants) {
      const current = this.db.prepare(`
        SELECT * FROM project_payment_entitlement_source
        WHERE subject_key = ? AND grant_key = ? AND source_key = ?
      `).get(event.subjectKey, grant.entitlement, sourceKey);
      if (current && compareEventWithRow(event, current) < 0) continue;
      const currentPeriod = rowBillingPeriod(current);
      const advances = currentPeriod && event.billingPeriod
        && compareBillingPeriods(event.billingPeriod, currentPeriod) > 0;
      const isRenewal = event.effectKind === "subscription-updated"
        || (event.effectKind === "transaction-completed" && event.providerSubscriptionId !== null);
      const renewalCount = Number(current?.renewal_count ?? 0) + (advances && isRenewal ? 1 : 0);
      renewalAdvanced ||= advances && isRenewal;
      this.db.prepare(`
        INSERT INTO project_payment_entitlement_source(
          subject_key, grant_key, source_key, provider_subscription_id, provider_transaction_id,
          quantity, status, effective_from, effective_until,
          billing_period_start, billing_period_end, source_price_key, source_event_id,
          last_occurred_at, renewal_count)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(subject_key, grant_key, source_key) DO UPDATE SET
          provider_subscription_id = excluded.provider_subscription_id,
          provider_transaction_id = excluded.provider_transaction_id,
          quantity = excluded.quantity, status = excluded.status,
          effective_from = excluded.effective_from, effective_until = excluded.effective_until,
          billing_period_start = excluded.billing_period_start, billing_period_end = excluded.billing_period_end,
          source_price_key = excluded.source_price_key, source_event_id = excluded.source_event_id,
          last_occurred_at = excluded.last_occurred_at, renewal_count = excluded.renewal_count
      `).run(
        event.subjectKey,
        grant.entitlement,
        sourceKey,
        event.providerSubscriptionId ?? null,
        event.providerTransactionId ?? null,
        grant.quantity,
        status,
        event.billingPeriod?.startsAt ?? event.occurredAt,
        effectiveUntil,
        event.billingPeriod?.startsAt ?? null,
        event.billingPeriod?.endsAt ?? null,
        event.priceKey ?? "refund",
        event.eventId,
        event.occurredAt,
        renewalCount
      );
      this.#rebuildEntitlementAggregate(event.subjectKey, grant.entitlement);
      applied += 1;
    }
    if (renewalAdvanced)
      this.#recordEvidence(event.evidenceScope, "renewal", event.eventId, new Date().toISOString());
    return applied === 0 ? "stale" : "applied";
  }

  #rebuildEntitlementAggregate(subjectKey, grantKey) {
    const sources = this.db.prepare(`
      SELECT * FROM project_payment_entitlement_source
      WHERE subject_key = ? AND grant_key = ?
    `).all(subjectKey, grantKey);
    if (sources.length === 0) throw new Error("The entitlement contribution was not persisted.");
    const available = sources.filter(row => ["active", "scheduled_cancel"].includes(row.status));
    const latest = [...sources].sort((left, right) =>
      Date.parse(right.last_occurred_at) - Date.parse(left.last_occurred_at)
      || String(right.source_event_id).localeCompare(String(left.source_event_id), "en"))[0];
    const aggregateStatus = available.some(row => row.status === "active")
      ? "active"
      : available.length > 0
        ? "scheduled_cancel"
        : "revoked";
    const activeQuantity = available.reduce((total, row) => total + Number(row.quantity), 0);
    const effectiveFrom = available.length > 0
      ? new Date(Math.min(...available.map(row => Date.parse(row.effective_from)))).toISOString()
      : latest.effective_from;
    const effectiveUntil = available.length === 0
      ? latest.effective_until
      : available.some(row => row.effective_until === null)
        ? null
        : new Date(Math.max(...available.map(row => Date.parse(row.effective_until)))).toISOString();
    const periodSource = [...(available.length > 0 ? available : sources)]
      .filter(row => row.billing_period_end !== null)
      .sort((left, right) => Date.parse(right.billing_period_end) - Date.parse(left.billing_period_end))[0] ?? latest;
    const renewalCount = sources.reduce((total, row) => total + Number(row.renewal_count), 0);
    this.db.prepare(`
      INSERT INTO project_payment_entitlement(
        subject_key, grant_key, quantity, status, effective_from, effective_until,
        billing_period_start, billing_period_end, source_price_key, source_event_id,
        last_occurred_at, renewal_count)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(subject_key, grant_key) DO UPDATE SET
        quantity = excluded.quantity, status = excluded.status,
        effective_from = excluded.effective_from, effective_until = excluded.effective_until,
        billing_period_start = excluded.billing_period_start, billing_period_end = excluded.billing_period_end,
        source_price_key = excluded.source_price_key, source_event_id = excluded.source_event_id,
        last_occurred_at = excluded.last_occurred_at, renewal_count = excluded.renewal_count
    `).run(
      subjectKey,
      grantKey,
      activeQuantity > 0 ? activeQuantity : Number(latest.quantity),
      aggregateStatus,
      effectiveFrom,
      effectiveUntil,
      periodSource.billing_period_start,
      periodSource.billing_period_end,
      latest.source_price_key,
      latest.source_event_id,
      latest.last_occurred_at,
      renewalCount
    );
  }

  #upsertTransaction(event) {
    const current = this.db.prepare(
      "SELECT * FROM project_payment_transaction WHERE provider_transaction_id = ?"
    ).get(event.providerTransactionId);
    if (current) {
      this.#assertTransactionIdentity(current, event);
      if (compareEventWithRow(event, current) < 0) return false;
    }
    this.db.prepare(`
      INSERT INTO project_payment_transaction(
        provider_transaction_id, environment_id, subject_key, grants_json,
        provider_product_id, provider_price_id, product_key, price_key, price_type,
        provider_subscription_id, amount_minor, currency, billing_period_start,
        billing_period_end, occurred_at, source_event_id)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(provider_transaction_id) DO UPDATE SET
        environment_id = excluded.environment_id, subject_key = excluded.subject_key,
        grants_json = excluded.grants_json,
        provider_product_id = excluded.provider_product_id, provider_price_id = excluded.provider_price_id,
        product_key = excluded.product_key,
        price_key = excluded.price_key, price_type = excluded.price_type,
        provider_subscription_id = excluded.provider_subscription_id,
        amount_minor = excluded.amount_minor, currency = excluded.currency,
        billing_period_start = excluded.billing_period_start, billing_period_end = excluded.billing_period_end,
        occurred_at = excluded.occurred_at, source_event_id = excluded.source_event_id
    `).run(
      event.providerTransactionId,
      event.environmentId,
      event.subjectKey,
      JSON.stringify(event.grants),
      event.providerProductId,
      event.providerPriceId,
      event.productKey,
      event.priceKey,
      event.priceType,
      event.providerSubscriptionId,
      event.amountMinor,
      event.currency,
      event.billingPeriod?.startsAt ?? null,
      event.billingPeriod?.endsAt ?? null,
      event.occurredAt,
      event.eventId
    );
    return true;
  }

  #upsertSubscription(event, status, effectiveUntil) {
    const current = this.#subscription(event.providerSubscriptionId);
    if (current) this.#assertSubscriptionIdentity(current, event);
    this.db.prepare(`
      INSERT INTO project_payment_subscription(
        provider_subscription_id, environment_id, subject_key, grants_json,
        provider_product_id, provider_price_id, product_key, price_key, status,
        billing_period_start, billing_period_end, effective_until, occurred_at, source_event_id)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(provider_subscription_id) DO UPDATE SET
        environment_id = excluded.environment_id, subject_key = excluded.subject_key,
        grants_json = excluded.grants_json,
        provider_product_id = excluded.provider_product_id, provider_price_id = excluded.provider_price_id,
        product_key = excluded.product_key,
        price_key = excluded.price_key, status = excluded.status,
        billing_period_start = excluded.billing_period_start, billing_period_end = excluded.billing_period_end,
        effective_until = excluded.effective_until, occurred_at = excluded.occurred_at,
        source_event_id = excluded.source_event_id
    `).run(
      event.providerSubscriptionId,
      event.environmentId,
      event.subjectKey,
      JSON.stringify(event.grants),
      event.providerProductId,
      event.providerPriceId,
      event.productKey,
      event.priceKey,
      status,
      event.billingPeriod.startsAt,
      event.billingPeriod.endsAt,
      effectiveUntil,
      event.occurredAt,
      event.eventId
    );
  }

  #validateTransactionContinuity(event) {
    const refund = this.db.prepare(
      "SELECT approved_at FROM project_payment_refund WHERE provider_transaction_id = ?"
    ).get(event.providerTransactionId);
    if (refund) {
      if (Date.parse(event.occurredAt) <= Date.parse(refund.approved_at)) return "stale";
      throw new InvalidSimulatorEventError("A refunded transaction cannot reactivate an entitlement.");
    }
    if (event.providerSubscriptionId) {
      const subscriptionRefund = this.db.prepare(`
        SELECT approved_at FROM project_payment_refund
        WHERE provider_subscription_id = ? ORDER BY approved_at DESC LIMIT 1
      `).get(event.providerSubscriptionId);
      if (subscriptionRefund) {
        if (Date.parse(event.occurredAt) <= Date.parse(subscriptionRefund.approved_at)) return "stale";
        throw new InvalidSimulatorEventError("A refunded subscription source cannot be reactivated by another transaction.");
      }
    }
    if (event.priceType !== "recurring" || event.providerSubscriptionId === null) return null;
    const current = this.#subscription(event.providerSubscriptionId);
    if (!current) {
      const priorTransaction = this.db.prepare(`
        SELECT * FROM project_payment_transaction WHERE provider_subscription_id = ?
        ORDER BY billing_period_end DESC, occurred_at DESC LIMIT 1
      `).get(event.providerSubscriptionId);
      if (priorTransaction) {
        this.#assertProjectionIdentity(priorTransaction, event, "recurring transaction");
        const comparison = compareBillingPeriods(event.billingPeriod, rowBillingPeriod(priorTransaction));
        if (comparison < 0) return "stale";
        if (comparison > 0
            && Date.parse(event.billingPeriod.startsAt) !== Date.parse(priorTransaction.billing_period_end)) {
          throw new InvalidSimulatorEventError("A transaction-first recurring period is discontinuous.");
        }
      }
      return null;
    }
    this.#assertSubscriptionIdentity(current, event);
    const comparison = compareBillingPeriods(event.billingPeriod, rowBillingPeriod(current));
    if (comparison < 0) return "stale";
    if (comparison === 0 && compareEventWithRow(event, current) < 0) return "stale";
    if (current.status !== "active") {
      if (compareEventWithRow(event, current) < 0) return "stale";
      throw new InvalidSimulatorEventError("A transaction cannot reactivate a non-active subscription.");
    }
    if (comparison > 0 && Date.parse(event.billingPeriod.startsAt) !== Date.parse(current.billing_period_end))
      throw new InvalidSimulatorEventError("The recurring transaction billing period is not continuous with the persisted subscription period.");
    return null;
  }

  #validateSubscriptionContinuity(event, mode) {
    const current = this.#subscription(event.providerSubscriptionId);
    if (!current) return "deferred";
    this.#assertSubscriptionIdentity(current, event);
    const comparison = compareBillingPeriods(event.billingPeriod, rowBillingPeriod(current));
    if (comparison < 0) return "stale";
    if (mode === "advance") {
      if (comparison === 0) return "stale";
      if (current.status !== "active")
        throw new InvalidSimulatorEventError("A renewal cannot advance a non-active subscription.");
      if (Date.parse(event.billingPeriod.startsAt) !== Date.parse(current.billing_period_end))
        throw new InvalidSimulatorEventError("The renewal billing period is not continuous with the persisted subscription period.");
      return null;
    }
    if (comparison > 0)
      throw new InvalidSimulatorEventError("A cancellation must reuse the persisted active billing period.");
    if (mode === "reuse" && current.status !== "active")
      throw new InvalidSimulatorEventError("A scheduled cancellation requires an active subscription.");
    if (mode === "reuse-for-cancel" && !["active", "scheduled_cancel"].includes(current.status))
      throw new InvalidSimulatorEventError("An immediate cancellation requires an active subscription period.");
    return null;
  }

  #subscription(id) {
    return this.db.prepare(
      "SELECT * FROM project_payment_subscription WHERE provider_subscription_id = ?"
    ).get(id);
  }

  #assertProjectionIdentity(row, event, label) {
    if (row.environment_id !== event.environmentId
        || row.subject_key !== event.subjectKey
        || row.provider_product_id !== event.providerProductId
        || row.provider_price_id !== event.providerPriceId
        || row.product_key !== event.productKey
        || row.price_key !== event.priceKey
        || !safeEqualText(row.grants_json, JSON.stringify(event.grants))) {
      throw new InvalidSimulatorEventError(`The ${label} provider id changed its immutable buyer or catalog mapping.`);
    }
  }

  #assertSubscriptionIdentity(row, event) {
    this.#assertProjectionIdentity(row, event, "subscription");
  }

  #assertTransactionIdentity(row, event) {
    this.#assertProjectionIdentity(row, event, "transaction");
    if ((row.provider_subscription_id ?? null) !== (event.providerSubscriptionId ?? null)
        || row.price_type !== event.priceType
        || Number(row.amount_minor) !== event.amountMinor
        || row.currency !== event.currency) {
      throw new InvalidSimulatorEventError("The transaction provider id changed its immutable payment mapping.");
    }
  }

  #recordImmediateRefundIfComplete(subscriptionId, scopeDigest, sourceEventId, observedAt) {
    if (!subscriptionId) return;
    const subscription = this.#subscription(subscriptionId);
    const refund = this.db.prepare(`
      SELECT provider_transaction_id FROM project_payment_refund
      WHERE provider_subscription_id = ? LIMIT 1
    `).get(subscriptionId);
    if (subscription?.status === "revoked" && refund)
      this.#recordEvidence(scopeDigest, "immediate-refund", sourceEventId, observedAt);
  }

  #recordEvidence(scopeDigest, name, sourceEventId, observedAt) {
    if (!verifierDigestPattern.test(scopeDigest ?? ""))
      throw new Error("Lifecycle evidence requires an exact runtime scope.");
    if (![...requiredLifecycleEvidence, "restart-replay"].includes(name))
      throw new Error(`Unknown lifecycle evidence: ${name}`);
    this.db.prepare(`
      INSERT OR IGNORE INTO project_payment_evidence(scope_digest, name, source_event_id, observed_at)
      VALUES (?, ?, ?, ?)
    `).run(scopeDigest, name, sourceEventId, observedAt);
  }

  #transaction(work) {
    this.db.exec("BEGIN IMMEDIATE");
    try {
      const result = work();
      this.db.exec("COMMIT");
      return result;
    } catch (error) {
      try { this.db.exec("ROLLBACK"); } catch {}
      throw error;
    }
  }

  #migrate() {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS project_payment_customer_binding (
        provider_customer_id TEXT PRIMARY KEY,
        subject_key TEXT NOT NULL UNIQUE,
        created_at TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS project_payment_webhook_event (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        destination_key TEXT NOT NULL,
        provider_event_id TEXT NOT NULL,
        event_type TEXT NOT NULL,
        occurred_at TEXT NOT NULL,
        received_at TEXT NOT NULL,
        body_sha256 TEXT NOT NULL,
        normalized_payload TEXT NOT NULL,
        next_attempt_at TEXT NOT NULL,
        last_attempt_at TEXT NULL,
        attempt_count INTEGER NOT NULL DEFAULT 0,
        delivery_count INTEGER NOT NULL DEFAULT 1,
        lease_id TEXT NULL,
        lease_expires_at TEXT NULL,
        processed_at TEXT NULL,
        processed_by_instance_id TEXT NULL,
        received_by_instance_id TEXT NOT NULL,
        ignored_as_stale INTEGER NOT NULL DEFAULT 0,
        last_error TEXT NULL,
        dead_lettered_at TEXT NULL,
        UNIQUE(destination_key, provider_event_id)
      );
      CREATE INDEX IF NOT EXISTS ix_project_payment_webhook_due
        ON project_payment_webhook_event(next_attempt_at, received_at)
        WHERE processed_at IS NULL AND dead_lettered_at IS NULL;
      CREATE TABLE IF NOT EXISTS project_payment_entitlement (
        subject_key TEXT NOT NULL,
        grant_key TEXT NOT NULL,
        quantity INTEGER NOT NULL CHECK(quantity > 0),
        status TEXT NOT NULL CHECK(status IN ('active', 'scheduled_cancel', 'revoked', 'expired')),
        effective_from TEXT NOT NULL,
        effective_until TEXT NULL,
        billing_period_start TEXT NULL,
        billing_period_end TEXT NULL,
        source_price_key TEXT NOT NULL,
        source_event_id TEXT NOT NULL,
        last_occurred_at TEXT NOT NULL,
        renewal_count INTEGER NOT NULL DEFAULT 0,
        PRIMARY KEY(subject_key, grant_key)
      );
      CREATE TABLE IF NOT EXISTS project_payment_entitlement_source (
        subject_key TEXT NOT NULL,
        grant_key TEXT NOT NULL,
        source_key TEXT NOT NULL,
        provider_subscription_id TEXT NULL,
        provider_transaction_id TEXT NULL,
        quantity INTEGER NOT NULL CHECK(quantity > 0),
        status TEXT NOT NULL CHECK(status IN ('active', 'scheduled_cancel', 'revoked', 'expired')),
        effective_from TEXT NOT NULL,
        effective_until TEXT NULL,
        billing_period_start TEXT NULL,
        billing_period_end TEXT NULL,
        source_price_key TEXT NOT NULL,
        source_event_id TEXT NOT NULL,
        last_occurred_at TEXT NOT NULL,
        renewal_count INTEGER NOT NULL DEFAULT 0,
        PRIMARY KEY(subject_key, grant_key, source_key),
        UNIQUE(grant_key, source_key)
      );
      CREATE TABLE IF NOT EXISTS project_payment_subscription (
        provider_subscription_id TEXT PRIMARY KEY,
        environment_id TEXT NOT NULL,
        subject_key TEXT NOT NULL,
        grants_json TEXT NOT NULL,
        provider_product_id TEXT NOT NULL,
        provider_price_id TEXT NOT NULL,
        product_key TEXT NOT NULL,
        price_key TEXT NOT NULL,
        status TEXT NOT NULL,
        billing_period_start TEXT NOT NULL,
        billing_period_end TEXT NOT NULL,
        effective_until TEXT NULL,
        occurred_at TEXT NOT NULL,
        source_event_id TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS project_payment_transaction (
        provider_transaction_id TEXT PRIMARY KEY,
        environment_id TEXT NOT NULL,
        subject_key TEXT NOT NULL,
        grants_json TEXT NOT NULL,
        provider_product_id TEXT NOT NULL,
        provider_price_id TEXT NOT NULL,
        product_key TEXT NOT NULL,
        price_key TEXT NOT NULL,
        price_type TEXT NOT NULL,
        provider_subscription_id TEXT NULL,
        amount_minor INTEGER NOT NULL,
        currency TEXT NOT NULL,
        billing_period_start TEXT NULL,
        billing_period_end TEXT NULL,
        occurred_at TEXT NOT NULL,
        source_event_id TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS project_payment_refund (
        provider_transaction_id TEXT PRIMARY KEY,
        provider_subscription_id TEXT NULL,
        source_event_id TEXT NOT NULL,
        approved_at TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS project_payment_evidence (
        scope_digest TEXT NOT NULL,
        name TEXT NOT NULL,
        source_event_id TEXT NULL,
        observed_at TEXT NOT NULL,
        PRIMARY KEY(scope_digest, name)
      );
    `);
  }
}

export class DurableProjectPaymentProcessor {
  #tail = Promise.resolve();
  #timer = null;

  constructor(store, { intervalMilliseconds = 1_000, onError = () => {} } = {}) {
    if (!store || typeof store.processDue !== "function") throw new Error("A durable store is required.");
    if (!Number.isSafeInteger(intervalMilliseconds) || intervalMilliseconds < 10)
      throw new Error("The processor interval must be at least 10ms.");
    this.store = store;
    this.intervalMilliseconds = intervalMilliseconds;
    this.onError = onError;
  }

  start() {
    if (this.#timer) return;
    this.wake();
    this.#timer = setInterval(() => this.wake(), this.intervalMilliseconds);
    this.#timer.unref?.();
  }

  wake() {
    const operation = this.#tail.then(() => this.store.processDue());
    this.#tail = operation.catch(error => this.onError(error));
    return this.#tail;
  }

  async stop() {
    if (this.#timer) clearInterval(this.#timer);
    this.#timer = null;
    await this.#tail;
  }
}

export function signEvent(rawBody, secret, timestamp) {
  requireRawBuffer(rawBody);
  requireStrongSecret(secret);
  if (!Number.isSafeInteger(timestamp)) throw new Error("A safe integer signature timestamp is required.");
  const digest = eventDigest(rawBody, secret, timestamp).toString("hex");
  return `ts=${timestamp};h1=${digest}`;
}

export function verifyEventSignature(rawBody, signature, secret, nowSeconds, toleranceSeconds = 300) {
  if (!Buffer.isBuffer(rawBody) || !hasStrongSecret(secret) || !Number.isSafeInteger(nowSeconds)
      || !Number.isSafeInteger(toleranceSeconds) || toleranceSeconds < 0) return false;
  const parsed = parseSignature(signature);
  if (!parsed || Math.abs(nowSeconds - parsed.timestamp) > toleranceSeconds) return false;
  const expected = eventDigest(rawBody, secret, parsed.timestamp);
  return parsed.digests.some(digest => safeEqualBuffer(digest, expected));
}

export async function acceptSignedEvent({
  rawBody,
  signature,
  secret,
  nowSeconds,
  destinationKey,
  expectedEnvironmentId,
  evidenceScope,
  catalog = referenceCatalog,
  store
}) {
  requireOpaqueIdentifier(destinationKey, "Destination key");
  requireOpaqueIdentifier(expectedEnvironmentId, "Expected environment id");
  if (!verifierDigestPattern.test(evidenceScope ?? ""))
    throw new Error("The simulator evidence scope is invalid.");
  validateCatalog(catalog);
  if (!store || typeof store.insertVerifiedEvent !== "function" || typeof store.resolveSubject !== "function")
    throw new Error("A durable project-payment store is required.");
  requireRawBuffer(rawBody);
  if (rawBody.length === 0 || rawBody.length > maximumWebhookBytes)
    throw new InvalidSimulatorEventError("The signed simulator event exceeds the accepted size.");
  if (!verifyEventSignature(rawBody, signature, secret, nowSeconds))
    throw new InvalidSimulatorSignatureError();

  const parsed = parseSignedJson(rawBody);
  const event = await normalizeSimulatorEvent(parsed, {
    destinationKey,
    expectedEnvironmentId,
    evidenceScope,
    catalog,
    store,
    bodyDigest: createHash("sha256").update(rawBody).digest("hex")
  });
  return store.insertVerifiedEvent(event);
}

export async function buildVerifierPayload({
  provider,
  paymentsEnabled,
  verifierEnabled,
  suppliedSecret,
  configuredSecret,
  expectedCommit,
  builtCommit,
  expectedManifestDigest,
  installedManifestDigest,
  environmentId,
  store
}) {
  if (provider !== providerModes.simulator || paymentsEnabled !== true || verifierEnabled !== true) return null;
  if (!hasStrongSecret(configuredSecret) || !hasStrongSecret(suppliedSecret)
      || !safeEqualText(suppliedSecret, configuredSecret)) return null;
  if (!verifierCommitPattern.test(builtCommit ?? "") || !verifierDigestPattern.test(installedManifestDigest ?? "")) return null;
  if (!safeEqualText(expectedCommit ?? "", builtCommit)
      || !safeEqualText(expectedManifestDigest ?? "", installedManifestDigest)) return null;
  if (!store || typeof store.verificationStatus !== "function") return null;
  let expectedScope;
  try { expectedScope = computeRuntimeEvidenceScope(environmentId, installedManifestDigest, builtCommit); }
  catch { return null; }
  if (!safeEqualText(store.evidenceScope ?? "", expectedScope)) return null;
  const evidence = await store.verificationStatus(expectedScope);
  if (evidence.lifecyclePassed !== true || evidence.durableInbox !== true || evidence.restartReplayPassed !== true)
    return null;
  return {
    provider: providerModes.simulator,
    paymentsEnabled: true,
    verifierEnabled: true,
    commitSha: builtCommit,
    manifestDigest: installedManifestDigest,
    lifecyclePassed: true,
    durableInbox: true,
    restartReplayPassed: true
  };
}

export function isSimulatorHarnessAuthorized({
  provider,
  paymentsEnabled,
  verifierEnabled,
  suppliedSecret,
  configuredSecret,
  expectedCommit,
  builtCommit,
  expectedManifestDigest,
  installedManifestDigest
}) {
  return provider === providerModes.simulator
    && paymentsEnabled === true
    && verifierEnabled === true
    && hasStrongSecret(configuredSecret)
    && hasStrongSecret(suppliedSecret)
    && safeEqualText(suppliedSecret, configuredSecret)
    && verifierCommitPattern.test(builtCommit ?? "")
    && verifierDigestPattern.test(installedManifestDigest ?? "")
    && safeEqualText(expectedCommit ?? "", builtCommit)
    && safeEqualText(expectedManifestDigest ?? "", installedManifestDigest);
}

export function simulatorCustomerIdForSubject(subjectKey) {
  requireOpaqueIdentifier(subjectKey, "Authenticated subject");
  // The control-plane simulator names this field buyerExternalId and emits it as
  // data.customer_id. Binding the same opaque, server-authenticated user id lets lifecycle
  // scenarios target the buyer without accepting a subject from the webhook payload.
  return subjectKey;
}

export class InvalidSimulatorSignatureError extends Error {
  constructor() {
    super("Invalid simulator signature.");
    this.name = "InvalidSimulatorSignatureError";
  }
}

export class InvalidSimulatorEventError extends Error {
  constructor(message = "Invalid simulator event.") {
    super(message);
    this.name = "InvalidSimulatorEventError";
  }
}

async function normalizeSimulatorEvent(parsed, context) {
  requireExactObject(parsed, ["event_id", "event_type", "occurred_at", "notification_id", "data"], "event");
  const eventId = requireIdentifier(parsed.event_id, "event_id");
  const eventType = requireIdentifier(parsed.event_type, "event_type");
  requireIdentifier(parsed.notification_id, "notification_id");
  const occurredAt = requireTimestamp(parsed.occurred_at, "occurred_at");
  if (!isPlainObject(parsed.data)) throw invalid("data must be an object.");

  const base = {
    destinationKey: context.destinationKey,
    eventId,
    eventType,
    occurredAt,
    bodyDigest: context.bodyDigest,
    evidenceScope: context.evidenceScope
  };

  switch (eventType) {
    case "transaction.completed":
      return { ...base, ...await normalizeTransaction(parsed.data, context, "completed", "transaction-completed") };
    case "transaction.payment_failed":
      return { ...base, ...await normalizeTransaction(parsed.data, context, "declined", "transaction-declined") };
    case "subscription.created":
      return { ...base, ...await normalizeSubscription(parsed.data, context, "active", "subscription-created") };
    case "subscription.updated":
      return { ...base, ...await normalizeSubscription(parsed.data, context, "active", "subscription-updated") };
    case "subscription.canceled":
      return { ...base, ...await normalizeSubscription(parsed.data, context, "canceled", "subscription-canceled") };
    case "adjustment.created":
      return { ...base, ...normalizeAdjustment(parsed.data, context, "pending_approval", "adjustment-pending") };
    case "adjustment.updated":
      return { ...base, ...normalizeAdjustment(parsed.data, context, "approved", "adjustment-approved") };
    case "customer.portal_session.created":
      return { ...base, ...await normalizePortal(parsed.data, context) };
    default:
      throw invalid(`Unsupported simulator event type: ${eventType}`);
  }
}

async function normalizeTransaction(data, context, expectedStatus, effectKind) {
  requireExactObject(data, ["id", "status", "customer_id", "subscription_id", "items", "details", "custom_data"], "transaction data");
  if (data.status !== expectedStatus) throw invalid("The transaction status is not valid for its event type.");
  const providerTransactionId = requireIdentifier(data.id, "transaction id");
  const providerCustomerId = requireIdentifier(data.customer_id, "customer id");
  const subjectKey = await requireBoundSubject(context.store, providerCustomerId);
  const environmentId = requireEnvironment(data.custom_data, context.expectedEnvironmentId);
  const item = requireSingleItem(data.items, { includesBillingPeriod: true });
  const catalogPrice = resolveCatalogProviderItem(context.catalog, item.product_id, item.price_id);
  if (item.quantity !== 1) throw invalid("The simulator item quantity must be exactly one.");
  const billingPeriod = requireBillingPeriod(item.billing_period, catalogPrice, "item.billing_period");
  requireExactObject(data.details, ["totals"], "transaction details");
  validateTotals(data.details.totals, catalogPrice, item.quantity);
  const providerSubscriptionId = data.subscription_id === null
    ? null
    : requireIdentifier(data.subscription_id, "subscription id");
  if (catalogPrice.type === "recurring" && effectKind === "transaction-completed" && !providerSubscriptionId)
    throw invalid("A completed recurring transaction must reference its subscription.");
  if (catalogPrice.type === "one_time" && providerSubscriptionId !== null)
    throw invalid("A one-time transaction cannot reference a subscription.");
  return {
    effectKind,
    environmentId,
    providerTransactionId,
    providerSubscriptionId,
    providerCustomerId,
    subjectKey,
    grants: catalogPrice.grants,
    providerProductId: catalogPrice.providerProductId,
    providerPriceId: catalogPrice.providerPriceId,
    productKey: catalogPrice.productKey,
    priceKey: catalogPrice.priceKey,
    priceType: catalogPrice.type,
    billingPeriod,
    amountMinor: catalogPrice.unitAmount * item.quantity,
    currency: catalogPrice.currency,
    effectiveUntil: billingPeriod?.endsAt ?? null
  };
}

async function normalizeSubscription(data, context, expectedStatus, effectKind) {
  requireExactObject(
    data,
    ["id", "status", "customer_id", "items", "current_billing_period", "scheduled_change", "custom_data"],
    "subscription data"
  );
  if (data.status !== expectedStatus) throw invalid("The subscription status is not valid for its event type.");
  const providerSubscriptionId = requireIdentifier(data.id, "subscription id");
  const providerCustomerId = requireIdentifier(data.customer_id, "customer id");
  const subjectKey = await requireBoundSubject(context.store, providerCustomerId);
  const environmentId = requireEnvironment(data.custom_data, context.expectedEnvironmentId);
  const item = requireSingleItem(data.items, { includesBillingPeriod: false });
  const catalogPrice = resolveCatalogProviderItem(context.catalog, item.product_id, item.price_id);
  if (catalogPrice.type !== "recurring" || item.quantity !== 1)
    throw invalid("The subscription item does not match a recurring trusted catalog price.");
  const billingPeriod = requireBillingPeriod(data.current_billing_period, catalogPrice, "current_billing_period");
  let effectiveUntil = null;
  if (data.scheduled_change !== null) {
    requireExactObject(data.scheduled_change, ["action", "effective_at"], "scheduled_change");
    if (data.scheduled_change.action !== "cancel") throw invalid("Only a scheduled cancellation is supported.");
    effectiveUntil = requireTimestamp(data.scheduled_change.effective_at, "scheduled_change.effective_at");
  }
  if (effectKind === "subscription-created" && data.scheduled_change !== null)
    throw invalid("A created subscription cannot already contain a scheduled change.");
  if (effectKind === "subscription-canceled" && data.scheduled_change !== null)
    throw invalid("An immediately canceled subscription cannot contain a scheduled change.");
  if (effectKind === "subscription-updated" && effectiveUntil
      && Date.parse(effectiveUntil) !== Date.parse(billingPeriod.endsAt)) {
    throw invalid("A scheduled cancellation must remain active through the authoritative billing-period end.");
  }
  return {
    effectKind: effectKind === "subscription-updated" && effectiveUntil ? "subscription-scheduled-cancel" : effectKind,
    environmentId,
    providerSubscriptionId,
    providerCustomerId,
    subjectKey,
    grants: catalogPrice.grants,
    providerProductId: catalogPrice.providerProductId,
    providerPriceId: catalogPrice.providerPriceId,
    productKey: catalogPrice.productKey,
    priceKey: catalogPrice.priceKey,
    priceType: catalogPrice.type,
    billingPeriod,
    effectiveUntil: effectiveUntil ?? billingPeriod.endsAt
  };
}

function normalizeAdjustment(data, context, expectedStatus, effectKind) {
  requireExactObject(data, ["id", "action", "status", "transaction_id", "totals", "custom_data"], "adjustment data");
  if (data.action !== "refund" || data.status !== expectedStatus)
    throw invalid("The adjustment action or status is not valid for its event type.");
  const environmentId = requireEnvironment(data.custom_data, context.expectedEnvironmentId);
  const totals = readTotals(data.totals);
  return {
    effectKind,
    environmentId,
    providerAdjustmentId: requireIdentifier(data.id, "adjustment id"),
    providerTransactionId: requireIdentifier(data.transaction_id, "transaction id"),
    amountMinor: totals.amountMinor,
    currency: totals.currency
  };
}

async function normalizePortal(data, context) {
  requireExactObject(data, ["id", "customer_id", "url", "expires_at", "custom_data"], "portal data");
  const providerCustomerId = requireIdentifier(data.customer_id, "customer id");
  const subjectKey = await requireBoundSubject(context.store, providerCustomerId);
  const environmentId = requireEnvironment(data.custom_data, context.expectedEnvironmentId);
  requireIdentifier(data.id, "portal session id");
  requireTimestamp(data.expires_at, "portal expires_at");
  let url;
  try { url = new URL(data.url); }
  catch { throw invalid("The portal URL is invalid."); }
  if (url.protocol !== "https:" || url.hostname !== "simulator.invalid")
    throw invalid("The portal URL is not a simulator URL.");
  return {
    effectKind: "portal-created",
    environmentId,
    providerCustomerId,
    subjectKey
  };
}

function compareBillingPeriods(first, second) {
  const endComparison = Date.parse(first.endsAt) - Date.parse(second.endsAt);
  if (endComparison !== 0) return Math.sign(endComparison);
  return Math.sign(Date.parse(first.startsAt) - Date.parse(second.startsAt));
}

function compareEventWithRow(event, row) {
  const rowPeriod = rowBillingPeriod(row);
  if (event.billingPeriod && rowPeriod) {
    const periodComparison = compareBillingPeriods(event.billingPeriod, rowPeriod);
    if (periodComparison !== 0) return periodComparison;
  }
  const rowOccurredAt = row.last_occurred_at ?? row.occurred_at;
  const timeComparison = Date.parse(event.occurredAt) - Date.parse(rowOccurredAt);
  if (timeComparison !== 0) return Math.sign(timeComparison);
  return event.eventId.localeCompare(row.source_event_id, "en");
}

function rowBillingPeriod(row) {
  return row?.billing_period_start && row?.billing_period_end
    ? { startsAt: row.billing_period_start, endsAt: row.billing_period_end }
    : null;
}

function mapEntitlementRow(row) {
  return {
    subjectKey: row.subject_key,
    grantKey: row.grant_key,
    quantity: Number(row.quantity),
    status: row.status,
    billingPeriod: rowBillingPeriod(row),
    effectiveFrom: row.effective_from,
    effectiveUntil: row.effective_until,
    renewalCount: Number(row.renewal_count),
    sourceEventId: row.source_event_id,
    lastOccurredAt: row.last_occurred_at
  };
}

function mapProjectionRow(row, subscription) {
  return {
    environmentId: row.environment_id,
    subjectKey: row.subject_key,
    grants: JSON.parse(row.grants_json),
    providerProductId: row.provider_product_id,
    providerPriceId: row.provider_price_id,
    productKey: row.product_key,
    priceKey: row.price_key,
    ...(subscription
      ? { status: row.status, effectiveUntil: row.effective_until }
      : {
          priceType: row.price_type,
          providerSubscriptionId: row.provider_subscription_id,
          amountMinor: Number(row.amount_minor),
          currency: row.currency
        }),
    billingPeriod: rowBillingPeriod(row),
    occurredAt: row.occurred_at,
    sourceEventId: row.source_event_id
  };
}

function validateNormalizedEvent(event) {
  if (!isPlainObject(event)) throw invalid("The normalized event is invalid.");
  for (const key of ["destinationKey", "eventId", "eventType", "occurredAt", "effectKind", "environmentId"])
    if (typeof event[key] !== "string" || event[key] === "") throw invalid(`The normalized ${key} is invalid.`);
  if (!/^[0-9a-f]{64}$/.test(event.bodyDigest ?? "")) throw invalid("The normalized body digest is invalid.");
  if (!verifierDigestPattern.test(event.evidenceScope ?? "")) throw invalid("The normalized evidence scope is invalid.");
}

function parseSignedJson(rawBody) {
  requireRawBuffer(rawBody);
  let text;
  try { text = strictUtf8.decode(rawBody); }
  catch { throw invalid("The signed simulator event is not valid UTF-8."); }
  try { return JSON.parse(text); }
  catch { throw invalid("The signed simulator event is not valid JSON."); }
}

function parseSignature(signature) {
  if (typeof signature !== "string" || signature.length > 1_024) return null;
  let timestampText = null;
  const digests = [];
  for (const rawPart of signature.split(";")) {
    const part = rawPart.trim();
    const separator = part.indexOf("=");
    if (separator <= 0) continue;
    const key = part.slice(0, separator);
    const value = part.slice(separator + 1);
    if (key === "ts") {
      if (timestampText !== null) return null;
      timestampText = value;
    } else if (key === "h1" && /^[0-9a-f]{64}$/i.test(value)) {
      digests.push(Buffer.from(value, "hex"));
    }
  }
  if (!/^\d{1,15}$/.test(timestampText ?? "") || digests.length === 0) return null;
  const timestamp = Number(timestampText);
  return Number.isSafeInteger(timestamp) ? { timestamp, digests } : null;
}

function eventDigest(rawBody, secret, timestamp) {
  return createHmac("sha256", Buffer.from(secret, "utf8"))
    .update(String(timestamp), "ascii")
    .update(":", "ascii")
    .update(rawBody)
    .digest();
}

function requireRawBuffer(rawBody) {
  if (!Buffer.isBuffer(rawBody)) throw new TypeError("The webhook body must be the untouched raw Buffer.");
}

function hasStrongSecret(secret) {
  return typeof secret === "string" && Buffer.byteLength(secret, "utf8") >= minimumSecretBytes;
}

function requireStrongSecret(secret) {
  if (!hasStrongSecret(secret)) throw new Error("The simulator secret must contain at least 32 UTF-8 bytes.");
}

function safeEqualBuffer(actual, expected) {
  return actual.length === expected.length && timingSafeEqual(actual, expected);
}

function safeEqualHex(actual, expected) {
  if (!/^[0-9a-f]{64}$/i.test(actual ?? "") || !/^[0-9a-f]{64}$/i.test(expected ?? "")) return false;
  return safeEqualBuffer(Buffer.from(actual, "hex"), Buffer.from(expected, "hex"));
}

function safeEqualText(actual, expected) {
  const actualDigest = createHash("sha256").update(actual, "utf8").digest();
  const expectedDigest = createHash("sha256").update(expected, "utf8").digest();
  return timingSafeEqual(actualDigest, expectedDigest);
}

function requireEnvironment(customData, expectedEnvironmentId) {
  requireExactObject(customData, ["vibenest_environment_id"], "custom_data");
  const environmentId = requireIdentifier(customData.vibenest_environment_id, "environment id");
  if (!safeEqualText(environmentId, expectedEnvironmentId))
    throw invalid("The signed event targets a different seller environment.");
  return environmentId;
}

function requireSingleItem(items, { includesBillingPeriod }) {
  if (!Array.isArray(items) || items.length !== 1) throw invalid("Exactly one catalog item is required.");
  requireExactObject(
    items[0],
    includesBillingPeriod
      ? ["price_id", "product_id", "quantity", "billing_period"]
      : ["price_id", "product_id", "quantity"],
    "item"
  );
  requireIdentifier(items[0].price_id, "price id");
  requireIdentifier(items[0].product_id, "product id");
  if (!Number.isSafeInteger(items[0].quantity) || items[0].quantity <= 0)
    throw invalid("The item quantity is invalid.");
  return items[0];
}

function requireBillingPeriod(value, catalogPrice, label) {
  if (catalogPrice.type === "one_time") {
    if (value !== null) throw invalid(`${label} must be null for a one-time price.`);
    return null;
  }
  if (catalogPrice.type !== "recurring" || !["month", "year"].includes(catalogPrice.interval))
    throw invalid("The trusted recurring catalog interval is invalid.");
  requireExactObject(value, ["starts_at", "ends_at"], label);
  const startsAt = requireTimestamp(value.starts_at, `${label}.starts_at`);
  const endsAt = requireTimestamp(value.ends_at, `${label}.ends_at`);
  if (!/(?:Z|\+00:00)$/.test(startsAt) || !/(?:Z|\+00:00)$/.test(endsAt))
    throw invalid(`${label} must use the simulator UTC offset.`);
  const startsAtMilliseconds = Date.parse(startsAt);
  const endsAtMilliseconds = Date.parse(endsAt);
  if (endsAtMilliseconds <= startsAtMilliseconds
      || addBillingInterval(startsAtMilliseconds, catalogPrice.interval) !== endsAtMilliseconds) {
    throw invalid(`${label} does not match the trusted catalog interval.`);
  }
  return { startsAt, endsAt };
}

function addBillingInterval(startsAtMilliseconds, interval) {
  const startsAt = new Date(startsAtMilliseconds);
  const year = startsAt.getUTCFullYear();
  const month = startsAt.getUTCMonth();
  const day = startsAt.getUTCDate();
  const targetMonthIndex = interval === "month" ? month + 1 : month;
  const targetYear = interval === "year" ? year + 1 : year + Math.floor(targetMonthIndex / 12);
  const targetMonth = ((targetMonthIndex % 12) + 12) % 12;
  const lastTargetDay = new Date(Date.UTC(targetYear, targetMonth + 1, 0)).getUTCDate();
  return Date.UTC(
    targetYear,
    targetMonth,
    Math.min(day, lastTargetDay),
    startsAt.getUTCHours(),
    startsAt.getUTCMinutes(),
    startsAt.getUTCSeconds(),
    startsAt.getUTCMilliseconds()
  );
}

function validateTotals(value, catalogPrice, quantity) {
  const totals = readTotals(value);
  if (totals.currency !== catalogPrice.currency || totals.amountMinor !== catalogPrice.unitAmount * quantity)
    throw invalid("The event totals do not match the trusted catalog price.");
}

function readTotals(value) {
  requireExactObject(value, ["total", "currency_code"], "totals");
  if (typeof value.total !== "string" || !/^[1-9]\d{0,17}$/.test(value.total))
    throw invalid("The monetary total is invalid.");
  const amountMinor = Number(value.total);
  if (!Number.isSafeInteger(amountMinor)) throw invalid("The monetary total is outside the safe range.");
  if (typeof value.currency_code !== "string" || !/^[A-Z]{3}$/.test(value.currency_code))
    throw invalid("The currency is invalid.");
  return { amountMinor, currency: value.currency_code };
}

async function requireBoundSubject(store, providerCustomerId) {
  const subjectKey = await store.resolveSubject(providerCustomerId);
  if (!subjectKey) throw invalid("The provider customer is not bound to an authenticated application subject.");
  return subjectKey;
}

function resolveCatalogPriceByKey(catalog, priceKey) {
  requireIdentifier(priceKey, "price key");
  const matches = [];
  for (const [productKey, product] of Object.entries(catalog.products)) {
    if (Object.hasOwn(product.prices, priceKey))
      matches.push(catalogProjection(productKey, product, priceKey, product.prices[priceKey]));
  }
  if (matches.length !== 1) throw new Error(`Unknown or ambiguous trusted catalog price: ${priceKey}`);
  return matches[0];
}

function resolveCatalogProviderItem(catalog, providerProductId, providerPriceId) {
  const matches = [];
  for (const [productKey, product] of Object.entries(catalog.products)) {
    for (const [priceKey, price] of Object.entries(product.prices)) {
      if (product.providerProductId === providerProductId && price.providerPriceId === providerPriceId)
        matches.push(catalogProjection(productKey, product, priceKey, price));
    }
  }
  if (matches.length !== 1) throw invalid("The event item has no unique trusted catalog mapping.");
  return matches[0];
}

function catalogProjection(productKey, product, priceKey, price) {
  return {
    providerProductId: product.providerProductId,
    providerPriceId: price.providerPriceId,
    productKey,
    priceKey,
    grants: product.grants,
    unitAmount: price.unitAmount,
    currency: price.currency,
    type: price.type,
    interval: price.interval
  };
}

function validateCatalog(catalog) {
  if (!isPlainObject(catalog) || !isPlainObject(catalog.products) || Object.keys(catalog.products).length === 0)
    throw new Error("A trusted server-side catalog is required.");
  const providerIds = new Set();
  for (const [productKey, product] of Object.entries(catalog.products)) {
    requireManifestKey(productKey, "Product key");
    if (!isPlainObject(product) || !isPlainObject(product.prices) || Object.keys(product.prices).length === 0)
      throw new Error("Each trusted product requires prices.");
    requireOpaqueIdentifier(product.providerProductId, "Provider product id");
    if (!Array.isArray(product.grants) || product.grants.length === 0)
      throw new Error("Catalog grants are required.");
    for (const grant of product.grants) {
      if (!isPlainObject(grant)) throw new Error("Catalog grant is invalid.");
      requireEntitlementKey(grant.entitlement, "Grant entitlement");
      if (!Number.isSafeInteger(grant.quantity) || grant.quantity <= 0)
        throw new Error("Catalog grant quantity is invalid.");
    }
    if (new Set(product.grants.map(grant => grant.entitlement)).size !== product.grants.length)
      throw new Error("Catalog grant entitlements must be unique.");
    for (const [priceKey, price] of Object.entries(product.prices)) {
      requireManifestKey(priceKey, "Price key");
      requireOpaqueIdentifier(price.providerPriceId, "Provider price id");
      const providerIdentity = `${product.providerProductId}:${price.providerPriceId}`;
      if (providerIds.has(providerIdentity)) throw new Error("Provider catalog mappings must be unique.");
      providerIds.add(providerIdentity);
      if (!Number.isSafeInteger(price.unitAmount) || price.unitAmount <= 0 || !/^[A-Z]{3}$/.test(price.currency ?? ""))
        throw new Error("Catalog price amount or currency is invalid.");
      if (price.type === "one_time" ? price.interval !== null : price.type !== "recurring" || !["month", "year"].includes(price.interval))
        throw new Error("Catalog price type or interval is invalid.");
    }
  }
}

function requireExactObject(value, requiredKeys, label) {
  if (!isPlainObject(value)) throw invalid(`${label} must be an object.`);
  const actual = Object.keys(value).sort();
  const expected = [...requiredKeys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index]))
    throw invalid(`${label} has missing or unexpected fields.`);
}

function requireExactCatalogObject(value, requiredKeys, label) {
  if (!isPlainObject(value)) throw new Error(`${label} must be an object.`);
  const actual = Object.keys(value).sort();
  const expected = [...requiredKeys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index]))
    throw new Error(`${label} has missing or unexpected fields.`);
}

function isPlainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function requireIdentifier(value, label) {
  if (typeof value !== "string" || !identifierPattern.test(value)) throw invalid(`${label} is invalid.`);
  return value;
}

function requireOpaqueIdentifier(value, label) {
  if (typeof value !== "string" || !identifierPattern.test(value)) throw new Error(`${label} is invalid.`);
  return value;
}

function requireManifestKey(value, label) {
  if (typeof value !== "string" || !manifestKeyPattern.test(value)) throw new Error(`${label} is invalid.`);
  return value;
}

function requireEntitlementKey(value, label) {
  if (typeof value !== "string" || !entitlementKeyPattern.test(value)) throw new Error(`${label} is invalid.`);
  return value;
}

function requireTimestamp(value, label) {
  if (typeof value !== "string" || !isoTimestampPattern.test(value) || !Number.isFinite(Date.parse(value)))
    throw invalid(`${label} is invalid.`);
  return value;
}

function requireOperationalDate(value, label) {
  if (!(value instanceof Date) || !Number.isFinite(value.getTime())) throw new Error(`${label} is invalid.`);
  return value;
}

function invalid(message) {
  return new InvalidSimulatorEventError(message);
}

function stableId(prefix, ...parts) {
  return `${prefix}_${createHash("sha256").update(parts.join(":"), "utf8").digest("hex").slice(0, 24)}`;
}

function deepFreeze(value) {
  Object.freeze(value);
  for (const child of Object.values(value)) if (child && typeof child === "object" && !Object.isFrozen(child)) deepFreeze(child);
  return value;
}
