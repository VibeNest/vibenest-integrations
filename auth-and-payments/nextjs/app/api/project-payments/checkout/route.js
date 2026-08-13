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
    const body = parseExactJsonObject(await request.text(), ["priceKey"]);
    return Response.json(await projectPayments.provider.createCheckout({ buyerKey, priceKey: body.priceKey }));
  } catch {
    return new Response(null, { status: 400 });
  } finally {
    projectPayments?.close();
  }
}
