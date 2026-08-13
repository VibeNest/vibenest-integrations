import assert from "node:assert/strict";
import test from "node:test";
import { callbackUrlFromRequest, settings } from "../lib/vibenest-auth.js";
import { expiredSessionCookie, readSession, sessionCookie } from "../lib/session.js";
import { authenticatedBuyerFromRequest } from "../lib/project-payments.js";

const environment = {
  VIBENEST_AUTH_ISSUER: "https://vibenest.net/",
  VIBENEST_AUTH_CLIENT_ID: "client-reference",
  VIBENEST_AUTH_CLIENT_SECRET: "confidential-placeholder",
  VIBENEST_AUTH_REDIRECT_URI: "https://reference.example/auth/vibenest/callback",
};
const secret = "test-session-secret-with-at-least-32-characters";

test("callback origin and path are pinned to server configuration", () => {
  const callback = callbackUrlFromRequest("https://attacker.invalid/other?code=abc&state=state", environment);
  assert.equal(callback.href, "https://reference.example/auth/vibenest/callback?code=abc&state=state");
});

test("configuration accepts confidential and public PKCE clients", () => {
  assert.equal(settings(environment).clientSecret, "confidential-placeholder");
  assert.equal(settings({ ...environment, VIBENEST_AUTH_CLIENT_SECRET: "" }).clientSecret, undefined);
});

test("local session is authenticated, encrypted, expiring and clearable", () => {
  const cookie = sessionCookie({ subject: "pairwise-sub", expiresAt: Date.now() + 60_000 }, secret);
  assert.doesNotMatch(cookie, /pairwise-sub/);
  assert.equal(readSession(cookie, secret).subject, "pairwise-sub");
  assert.deepEqual(readSession(cookie, "different-secret-with-at-least-32-characters"), {});
  assert.match(expiredSessionCookie(), /Max-Age=0/);
});

test("missing, plain or incomplete PKCE callback state is rejected before exchange", async () => {
  const source = await import("node:fs/promises").then(({ readFile }) => readFile(new URL("../lib/vibenest-auth.js", import.meta.url), "utf8"));
  assert.match(source, /code_challenge_method: "S256"/);
  assert.match(source, /expectedState: pending\.state/);
  assert.match(source, /expectedNonce: pending\.nonce/);
  assert.match(source, /if \(!pending\.codeVerifier \|\| !pending\.state \|\| !pending\.nonce\)/);
  assert.doesNotMatch(source, /code_challenge_method: "plain"/);
});

test("Payments derives the buyer from the same Auth session and requires CSRF", () => {
  const previous = { ...process.env };
  Object.assign(process.env, environment, { APP_SESSION_SECRET: secret });
  try {
    const csrf = "csrf-reference-token";
    const cookie = sessionCookie({ subject: "pairwise-sub", csrf, expiresAt: Date.now() + 60_000 }, secret).split(";", 1)[0];
    const request = new Request("https://reference.example/api/project-payments/checkout", {
      method: "POST",
      headers: { cookie, origin: "https://reference.example", "x-csrf-token": csrf },
    });
    assert.equal(authenticatedBuyerFromRequest(request, null), "pairwise-sub");
    assert.throws(() => authenticatedBuyerFromRequest(new Request(request.url, { method: "POST", headers: { cookie } }), null), /csrf/);
  } finally {
    for (const key of Object.keys(process.env)) if (!(key in previous)) delete process.env[key];
    Object.assign(process.env, previous);
  }
});
