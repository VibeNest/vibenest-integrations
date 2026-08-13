import { readSession } from "../../../lib/session.js";

export async function GET(request) {
  const session = readSession(request.headers.get("cookie"), process.env.APP_SESSION_SECRET);
  if (!session.subject) return new Response(null, { status: 401 });
  return Response.json({ authenticated: true, subject: session.subject, email: session.email, emailVerified: session.emailVerified, csrf: session.csrf });
}
