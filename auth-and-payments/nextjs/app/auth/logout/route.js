import { NextResponse } from "next/server";
import { settings } from "../../../lib/vibenest-auth.js";
import { expiredSessionCookie, readSession, requireCsrf } from "../../../lib/session.js";

export async function POST(request) {
  const session = readSession(request.headers.get("cookie"), process.env.APP_SESSION_SECRET);
  try { requireCsrf(request, session, settings().applicationOrigin); }
  catch { return new Response(null, { status: 403 }); }
  const response = NextResponse.redirect(settings().applicationOrigin, 303);
  response.headers.set("set-cookie", expiredSessionCookie());
  return response;
}
