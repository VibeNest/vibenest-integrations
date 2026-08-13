import { NextResponse } from "next/server";
import { finishLogin, settings } from "../../../../lib/vibenest-auth.js";
import { readSession, sessionCookie } from "../../../../lib/session.js";

export async function GET(request) {
  try {
    const session = readSession(
      request.headers.get("cookie"),
      process.env.APP_SESSION_SECRET,
    );
    const authenticated = await finishLogin(request, session);
    const response = NextResponse.redirect(settings().applicationOrigin, 303);
    response.headers.set(
      "set-cookie",
      sessionCookie(authenticated, process.env.APP_SESSION_SECRET),
    );
    return response;
  } catch {
    return new Response("Invalid authentication callback", { status: 400 });
  }
}
