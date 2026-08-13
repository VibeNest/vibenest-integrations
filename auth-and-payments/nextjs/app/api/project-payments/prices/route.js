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
    if (!authenticatedBuyerFromRequest(request, projectPayments.store))
      return new Response(null, { status: 401 });
    const body = parseExactJsonObject(await request.text(), ["priceKeys"]);
    return Response.json({ prices: await projectPayments.provider.previewPrices(body.priceKeys) });
  } catch {
    return new Response(null, { status: 400 });
  } finally {
    projectPayments?.close();
  }
}
