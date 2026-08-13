import { NextResponse } from "next/server";
import { beginLogin } from "../../../../lib/vibenest-auth.js";
import { readSession, sessionCookie } from "../../../../lib/session.js";

export async function GET(request) {
  const session = readSession(request.headers.get("cookie"), process.env.APP_SESSION_SECRET);
  const result = await beginLogin(session);
  const response = NextResponse.redirect(result.authorizationUrl, 303);
  response.headers.set("set-cookie", sessionCookie(result.session, process.env.APP_SESSION_SECRET));
  return response;
}
