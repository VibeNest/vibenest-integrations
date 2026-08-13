import "server-only";
import {
  createCipheriv,
  createDecipheriv,
  createHash,
  randomBytes,
  timingSafeEqual,
} from "node:crypto";

export const sessionCookieName = "vibenest_app_session";

export function readSession(cookieHeader, secret, now = Date.now()) {
  const encoded = parseCookie(cookieHeader, sessionCookieName);
  if (!encoded) return {};
  try {
    const session = decrypt(encoded, secret);
    return Number.isSafeInteger(session.expiresAt) && session.expiresAt > now
      ? session
      : {};
  } catch {
    return {};
  }
}

export function sessionCookie(session, secret) {
  const encoded = encrypt(session, secret);
  return `${sessionCookieName}=${encodeURIComponent(encoded)}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=28800`;
}

export function expiredSessionCookie() {
  return `${sessionCookieName}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`;
}

export function requireCsrf(request, session, applicationOrigin) {
  const origin = request.headers.get("origin");
  const token = request.headers.get("x-csrf-token");
  if (
    origin !== new URL(applicationOrigin).origin ||
    typeof session.csrf !== "string" ||
    typeof token !== "string"
  ) {
    throw new Error("invalid csrf");
  }
  const left = Buffer.from(session.csrf);
  const right = Buffer.from(token);
  if (left.length !== right.length || !timingSafeEqual(left, right))
    throw new Error("invalid csrf");
}

export function newCsrf() {
  return randomBytes(24).toString("base64url");
}

function key(secret) {
  if (typeof secret !== "string" || secret.length < 32)
    throw new Error("APP_SESSION_SECRET must contain at least 32 characters");
  return createHash("sha256").update(secret).digest();
}

function encrypt(value, secret) {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key(secret), iv);
  const ciphertext = Buffer.concat([
    cipher.update(JSON.stringify(value)),
    cipher.final(),
  ]);
  return Buffer.concat([iv, cipher.getAuthTag(), ciphertext]).toString(
    "base64url",
  );
}

function decrypt(value, secret) {
  const payload = Buffer.from(value, "base64url");
  if (payload.length < 29) throw new Error("invalid session");
  const decipher = createDecipheriv(
    "aes-256-gcm",
    key(secret),
    payload.subarray(0, 12),
  );
  decipher.setAuthTag(payload.subarray(12, 28));
  return JSON.parse(
    Buffer.concat([
      decipher.update(payload.subarray(28)),
      decipher.final(),
    ]).toString("utf8"),
  );
}

function parseCookie(header, name) {
  for (const part of (header ?? "").split(";")) {
    const [key, ...rest] = part.trim().split("=");
    if (key === name) return decodeURIComponent(rest.join("="));
  }
  return null;
}
