import express from "express";
import {
  acceptSignedEvent,
  buildVerifierPayload,
  computeRuntimeEvidenceScope,
  DisabledProjectPaymentProvider,
  DurableProjectPaymentProcessor,
  DurableProjectPaymentStore,
  InvalidSimulatorEventError,
  InvalidSimulatorSignatureError,
  isSimulatorHarnessAuthorized,
  parseRuntimeCatalog,
  providerModes,
  referenceCatalog,
  SimulatorProjectPaymentProvider
} from "./project-payments.mjs";

const verifierPath = "/.well-known/vibenest/project-payments/verifier";
const harnessPath = "/.well-known/vibenest/project-payments/harness";

export function createApp(configuration = process.env, dependencies = {}) {
  const app = express();
  app.enable("strict routing");
  app.enable("case sensitive routing");

  const paymentsEnabled = configuration.VIBENEST_PROJECT_PAYMENTS_ENABLED === "true";
  const simulatorEnabled = paymentsEnabled
    && configuration.VIBENEST_PROJECT_PAYMENTS_PROVIDER === providerModes.simulator;
  if (simulatorEnabled
      && (typeof configuration.VIBENEST_PROJECT_PAYMENTS_WEBHOOK_SECRET !== "string"
        || Buffer.byteLength(configuration.VIBENEST_PROJECT_PAYMENTS_WEBHOOK_SECRET, "utf8") < 32)) {
    throw new Error("The simulator secret must contain at least 32 UTF-8 bytes.");
  }
  const sourceCommit = simulatorEnabled ? nonEmpty(configuration.SOURCE_COMMIT) : null;
  const evidenceScope = simulatorEnabled
    ? computeRuntimeEvidenceScope(
        configuration.VIBENEST_PROJECT_PAYMENTS_ENVIRONMENT_ID,
        configuration.VIBENEST_PROJECT_PAYMENTS_MANIFEST_DIGEST,
        sourceCommit
      )
    : null;
  const catalog = simulatorEnabled
    ? parseRuntimeCatalog(configuration.VIBENEST_PROJECT_PAYMENTS_CATALOG_B64, {
        expectedEnvironmentId: configuration.VIBENEST_PROJECT_PAYMENTS_ENVIRONMENT_ID,
        expectedManifestDigest: configuration.VIBENEST_PROJECT_PAYMENTS_MANIFEST_DIGEST
      })
    : referenceCatalog;
  const store = dependencies.store
    ?? new DurableProjectPaymentStore(
      configuration.PROJECT_PAYMENT_FIXTURE_STORE ?? ".data/project-payments.sqlite",
      { evidenceScope }
    );
  if (simulatorEnabled && store.evidenceScope !== evidenceScope)
    throw new Error("The durable store is not bound to this exact simulator build.");
  const provider = simulatorEnabled
    ? new SimulatorProjectPaymentProvider({ catalog, store })
    : new DisabledProjectPaymentProvider();
  const resolveAuthenticatedIdentity = dependencies.resolveAuthenticatedIdentity
    ?? fixtureOnlyHeaderIdentityResolver;
  const processor = dependencies.processor ?? new DurableProjectPaymentProcessor(store, {
    // Do not include request bodies, credentials, or provider error messages in this callback.
    onError: dependencies.onProcessorError ?? (() => {})
  });
  processor.start();

  app.locals.projectPayments = { store, provider, processor, catalog };

  // The raw-body route is deliberately mounted before the global JSON parser. The Buffer is
  // passed unchanged into HMAC verification and decoded only after verification succeeds.
  app.post(
    "/webhooks/project-payments",
    express.raw({ type: "application/json", limit: "128kb", inflate: false }),
    async (request, response) => {
      if (!simulatorEnabled) return response.sendStatus(404);
      try {
        const accepted = await acceptSignedEvent({
          rawBody: request.body,
          signature: request.get("Paddle-Signature"),
          secret: configuration.VIBENEST_PROJECT_PAYMENTS_WEBHOOK_SECRET,
          nowSeconds: Math.floor(Date.now() / 1000),
          destinationKey: configuration.VIBENEST_PROJECT_PAYMENTS_ENVIRONMENT_ID,
          expectedEnvironmentId: configuration.VIBENEST_PROJECT_PAYMENTS_ENVIRONMENT_ID,
          evidenceScope,
          catalog,
          store
        });
        if (accepted.inserted) processor.wake();
        response.sendStatus(202);
      } catch (error) {
        if (error instanceof InvalidSimulatorSignatureError) return response.sendStatus(401);
        if (error instanceof InvalidSimulatorEventError || error instanceof TypeError) return response.sendStatus(400);
        response.sendStatus(503);
      }
    }
  );

  app.all(
    harnessPath,
    (request, response, next) => {
      const authorized = isSimulatorHarnessAuthorized({
        provider: provider.mode,
        paymentsEnabled,
        verifierEnabled: configuration.VIBENEST_PROJECT_PAYMENTS_VERIFIER_ENABLED === "true",
        suppliedSecret: request.get("X-VibeNest-Simulator-Secret"),
        configuredSecret: configuration.VIBENEST_PROJECT_PAYMENTS_WEBHOOK_SECRET,
        expectedCommit: request.get("X-VibeNest-Expected-Commit"),
        builtCommit: sourceCommit,
        expectedManifestDigest: request.get("X-VibeNest-Expected-Manifest-Digest"),
        installedManifestDigest: configuration.VIBENEST_PROJECT_PAYMENTS_MANIFEST_DIGEST
      });
      if (!authorized) return response.sendStatus(404);
      if (request.method !== "POST") {
        response.set("Allow", "POST");
        return response.sendStatus(405);
      }
      if (!request.is("application/json")) return response.sendStatus(415);
      next();
    },
    express.json({ limit: "1kb", strict: true, inflate: false }),
    async (request, response) => {
      try {
        requireExactRequestBody(request.body, ["action"]);
        if (request.body.action !== "restart-replay") return response.sendStatus(400);
        response.status(202).json(await store.stageRestartReplayProbe(
          configuration.VIBENEST_PROJECT_PAYMENTS_ENVIRONMENT_ID
        ));
      } catch {
        response.sendStatus(400);
      }
    }
  );

  app.use(express.json({ limit: "128kb", strict: true }));

  app.post(
    "/api/project-payments/prices/preview",
    requireAuthenticatedBuyer(resolveAuthenticatedIdentity),
    async (request, response) => {
      try {
        requireExactRequestBody(request.body, ["priceKeys"]);
        response.json(await provider.previewPrices(request.body.priceKeys));
      } catch {
        response.sendStatus(provider.mode === providerModes.disabled ? 503 : 400);
      }
    }
  );

  app.post(
    "/api/project-payments/checkout",
    requireAuthenticatedBuyer(resolveAuthenticatedIdentity),
    async (request, response) => {
      try {
        requireExactRequestBody(request.body, ["priceKey"]);
        response.json(await provider.createCheckout({
          buyerKey: request.authenticatedIdentity.subjectKey,
          priceKey: request.body.priceKey
        }));
      } catch {
        response.sendStatus(provider.mode === providerModes.disabled ? 503 : 400);
      }
    }
  );

  app.post(
    "/api/project-payments/portal",
    requireAuthenticatedBuyer(resolveAuthenticatedIdentity),
    async (request, response) => {
      try {
        requireExactRequestBody(request.body, []);
        response.json(await provider.createPortal(request.authenticatedIdentity.subjectKey));
      } catch {
        response.sendStatus(provider.mode === providerModes.disabled ? 503 : 400);
      }
    }
  );

  // Express treats GET handlers as implicit HEAD handlers. app.all plus an exact method check
  // prevents HEAD (and every other method) from inheriting verifier success.
  app.all(verifierPath, async (request, response) => {
    const verifierExposed = simulatorEnabled
      && configuration.VIBENEST_PROJECT_PAYMENTS_VERIFIER_ENABLED === "true";
    if (!verifierExposed) return response.sendStatus(404);
    if (request.method !== "GET") {
      response.set("Allow", "GET");
      return response.sendStatus(405);
    }

    const payload = await buildVerifierPayload({
      provider: provider.mode,
      paymentsEnabled,
      verifierEnabled: true,
      suppliedSecret: request.get("X-VibeNest-Simulator-Secret"),
      configuredSecret: configuration.VIBENEST_PROJECT_PAYMENTS_WEBHOOK_SECRET,
      expectedCommit: request.get("X-VibeNest-Expected-Commit"),
      builtCommit: sourceCommit,
      expectedManifestDigest: request.get("X-VibeNest-Expected-Manifest-Digest"),
      installedManifestDigest: configuration.VIBENEST_PROJECT_PAYMENTS_MANIFEST_DIGEST,
      environmentId: configuration.VIBENEST_PROJECT_PAYMENTS_ENVIRONMENT_ID,
      store
    });
    if (!payload) return response.sendStatus(404);
    response.json(payload);
  });

  // Body-parser failures are intentionally reduced to status codes. Never reflect raw bodies,
  // signature material, provider payloads, or parser diagnostics to a caller.
  app.use((error, _request, response, _next) => {
    const status = [400, 413, 415].includes(error?.status) ? error.status : 500;
    response.sendStatus(status);
  });

  return app;
}

// FIXTURE-ONLY AUTH SHIM: this header makes the self-contained fixture testable. A real
// integration must inject a resolver backed by its server-side session/auth middleware and
// must never accept a buyer/subject from request JSON, query parameters, or client metadata.
export function fixtureOnlyHeaderIdentityResolver(request) {
  const subjectKey = request.get("X-Fixture-Authenticated-Buyer");
  return typeof subjectKey === "string" && /^[A-Za-z0-9][A-Za-z0-9._:-]{0,159}$/.test(subjectKey)
    ? { subjectKey }
    : null;
}

function requireAuthenticatedBuyer(resolveAuthenticatedIdentity) {
  if (typeof resolveAuthenticatedIdentity !== "function")
    throw new Error("A server-side authenticated identity resolver is required.");
  return async (request, response, next) => {
    try {
      const identity = await resolveAuthenticatedIdentity(request);
      if (!identity || typeof identity.subjectKey !== "string"
          || !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,159}$/.test(identity.subjectKey)) {
        return response.sendStatus(401);
      }
      request.authenticatedIdentity = Object.freeze({ subjectKey: identity.subjectKey });
      next();
    } catch {
      response.sendStatus(401);
    }
  };
}

function requireExactRequestBody(body, keys) {
  if (body === null || typeof body !== "object" || Array.isArray(body))
    throw new Error("A JSON object is required.");
  const actual = Object.keys(body).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index]))
    throw new Error("The request body has missing or unexpected fields.");
}

function nonEmpty(value) {
  return typeof value === "string" && value.trim() !== "" ? value.trim() : null;
}

if (process.argv[1] && new URL(import.meta.url).pathname.endsWith(process.argv[1].replaceAll("\\", "/"))) {
  createApp().listen(Number.parseInt(process.env.PORT ?? "3000", 10));
}
