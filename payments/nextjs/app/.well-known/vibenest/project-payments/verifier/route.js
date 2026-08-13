import {
  buildVerifierPayload,
  openProjectPaymentRuntime
} from "../../../../../lib/project-payments.js";

export const runtime = "nodejs";

export async function GET(request) {
  let projectPayments;
  try {
    projectPayments = openProjectPaymentRuntime();
    if (!projectPayments.enabled
        || projectPayments.providerMode !== "simulator"
        || process.env.VIBENEST_PROJECT_PAYMENTS_VERIFIER_ENABLED !== "true") {
      return new Response(null, { status: 404 });
    }
    const payload = await buildVerifierPayload({
      provider: projectPayments.providerMode,
      paymentsEnabled: true,
      verifierEnabled: true,
      suppliedSecret: request.headers.get("x-vibenest-simulator-secret"),
      configuredSecret: projectPayments.secret,
      expectedCommit: request.headers.get("x-vibenest-expected-commit"),
      builtCommit: projectPayments.builtCommit,
      expectedManifestDigest: request.headers.get("x-vibenest-expected-manifest-digest"),
      installedManifestDigest: projectPayments.manifestDigest,
      environmentId: projectPayments.environmentId,
      store: projectPayments.store
    });
    return payload ? Response.json(payload) : new Response(null, { status: 404 });
  } catch {
    return new Response(null, { status: 404 });
  } finally {
    projectPayments?.close();
  }
}

const rejectNonGet = () => new Response(null, { status: 405, headers: { Allow: "GET" } });
export const HEAD = rejectNonGet;
export const POST = rejectNonGet;
export const PUT = rejectNonGet;
export const PATCH = rejectNonGet;
export const DELETE = rejectNonGet;
export const OPTIONS = rejectNonGet;
