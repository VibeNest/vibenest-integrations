import { TextDecoder } from "node:util";
import {
  InvalidSimulatorEventError,
  isSimulatorHarnessAuthorized,
  openProjectPaymentRuntime,
  parseExactJsonObject,
  readBoundedRawBody
} from "../../../../../lib/project-payments.js";

export const runtime = "nodejs";

const maximumHarnessBodyBytes = 1024;
const strictUtf8 = new TextDecoder("utf-8", { fatal: true });

export async function POST(request) {
  let projectPayments;
  try {
    projectPayments = openProjectPaymentRuntime();
    const verifierEnabled = process.env.VIBENEST_PROJECT_PAYMENTS_VERIFIER_ENABLED === "true";
    if (!projectPayments.enabled
        || !isSimulatorHarnessAuthorized({
          provider: projectPayments.providerMode,
          paymentsEnabled: true,
          verifierEnabled,
          suppliedSecret: request.headers.get("x-vibenest-simulator-secret"),
          configuredSecret: projectPayments.secret,
          expectedCommit: request.headers.get("x-vibenest-expected-commit"),
          builtCommit: projectPayments.builtCommit,
          expectedManifestDigest: request.headers.get("x-vibenest-expected-manifest-digest"),
          installedManifestDigest: projectPayments.manifestDigest
        })) {
      return new Response(null, { status: 404 });
    }
    if (!(request.headers.get("content-type") ?? "").toLowerCase().startsWith("application/json"))
      return new Response(null, { status: 415 });
    const rawBody = await readBoundedRawBody(request, maximumHarnessBodyBytes);
    let body;
    try { body = parseExactJsonObject(strictUtf8.decode(rawBody), ["action"]); }
    catch { return new Response(null, { status: 400 }); }
    if (body.action !== "restart-replay") return new Response(null, { status: 400 });
    const staged = projectPayments.store.stageRestartReplayProbe(projectPayments.environmentId);
    return Response.json(staged, { status: 202 });
  } catch (error) {
    return new Response(null, { status: error instanceof InvalidSimulatorEventError ? 413 : 404 });
  } finally {
    projectPayments?.close();
  }
}

const rejectNonPost = () => new Response(null, { status: 405, headers: { Allow: "POST" } });
export const GET = rejectNonPost;
export const HEAD = rejectNonPost;
export const PUT = rejectNonPost;
export const PATCH = rejectNonPost;
export const DELETE = rejectNonPost;
export const OPTIONS = rejectNonPost;
