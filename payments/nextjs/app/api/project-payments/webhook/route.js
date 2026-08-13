import {
  InvalidSimulatorEventError,
  InvalidSimulatorSignatureError,
  acceptSignedEvent,
  openProjectPaymentRuntime,
  readBoundedRawBody
} from "../../../../lib/project-payments.js";

export const runtime = "nodejs";

export async function POST(request) {
  let projectPayments;
  try {
    projectPayments = openProjectPaymentRuntime();
    if (!projectPayments.enabled || projectPayments.providerMode !== "simulator")
      return new Response(null, { status: 404 });

    const rawBody = await readBoundedRawBody(request);
    await acceptSignedEvent({
      rawBody,
      signature: request.headers.get("paddle-signature"),
      secret: projectPayments.secret,
      nowSeconds: Math.floor(Date.now() / 1_000),
      destinationKey: projectPayments.environmentId,
      expectedEnvironmentId: projectPayments.environmentId,
      evidenceScope: projectPayments.evidenceScope,
      catalog: projectPayments.catalog,
      store: projectPayments.store
    });

    // The insert above is committed before ACK. A later server-side runtime open claims it
    // from SQLite; no in-memory queue is required, and an application restart can replay an
    // acknowledged event under a new process instance.
    return new Response(null, { status: 202 });
  } catch (error) {
    if (error instanceof InvalidSimulatorSignatureError) return new Response(null, { status: 401 });
    if (error instanceof InvalidSimulatorEventError) return new Response(null, { status: 400 });
    return new Response(null, { status: 503 });
  } finally {
    projectPayments?.close();
  }
}
