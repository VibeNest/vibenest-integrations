import {
  authenticatedBuyerFromRequest,
  openProjectPaymentRuntime,
  parseExactJsonObject
} from "../../../../lib/project-payments.js";

export const runtime = "nodejs";

export async function POST(request) {
  let projectPayments;
  try {
    projectPayments = openProjectPaymentRuntime();
    if (!projectPayments.enabled) return new Response(null, { status: 404 });
    const buyerKey = authenticatedBuyerFromRequest(request, projectPayments.store);
    if (!buyerKey) return new Response(null, { status: 401 });
    parseExactJsonObject(await request.text(), []);
    return Response.json(await projectPayments.provider.createPortal(buyerKey));
  } catch {
    return new Response(null, { status: 400 });
  } finally {
    projectPayments?.close();
  }
}
