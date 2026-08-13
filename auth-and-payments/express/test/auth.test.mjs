import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { authSettings, callbackUrlFromRequest } from "../src/vibenest-auth.mjs";
import { vibenestSessionIdentityResolver } from "../src/server.mjs";

const environment = {
  VIBENEST_AUTH_ISSUER: "https://vibenest.net/",
  VIBENEST_AUTH_CLIENT_ID: "client-reference",
  VIBENEST_AUTH_CLIENT_SECRET: "confidential-placeholder",
  VIBENEST_AUTH_REDIRECT_URI: "https://reference.example/auth/vibenest/callback",
};

test("callback copies only the authorization response query", () => {
  const callback = callbackUrlFromRequest("https://attacker.invalid/other?code=abc&state=state", environment);
  assert.equal(callback.href, "https://reference.example/auth/vibenest/callback?code=abc&state=state");
});

test("public and confidential client variants are explicit", () => {
  assert.equal(authSettings(environment).clientSecret, "confidential-placeholder");
  assert.equal(authSettings({ ...environment, VIBENEST_AUTH_CLIENT_SECRET: "" }).clientSecret, undefined);
});

test("security invariants are wired through the maintained OIDC library", async () => {
  const source = await readFile(new URL("../src/vibenest-auth.mjs", import.meta.url), "utf8");
  assert.match(source, /code_challenge_method: "S256"/);
  assert.match(source, /expectedState: pending\.state/);
  assert.match(source, /expectedNonce: pending\.nonce/);
  assert.match(source, /delete request\.session\.oidc/);
  assert.doesNotMatch(source, /code_challenge_method: "plain"/);
  assert.doesNotMatch(source, /X-Forwarded-Host|request\.hostname/);
});

test("Payments uses the same pairwise Auth subject and requires CSRF", () => {
  const request = {
    session: { user: { subject: "pairwise-sub" }, csrf: "csrf-token" },
    get(name) {
      return { Origin: "https://reference.example", "X-CSRF-Token": "csrf-token" }[name];
    },
  };
  assert.deepEqual(vibenestSessionIdentityResolver(request, environment), { subjectKey: "pairwise-sub" });
  request.get = () => undefined;
  assert.throws(() => vibenestSessionIdentityResolver(request, environment), /csrf/);
});
