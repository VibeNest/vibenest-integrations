import "server-only";
import * as oidc from "openid-client";
import { newCsrf } from "./session.js";

let configuration;

export function settings(environment = process.env) {
  const redirectUri = new URL(required(environment, "VIBENEST_AUTH_REDIRECT_URI"));
  const issuer = new URL(required(environment, "VIBENEST_AUTH_ISSUER"));
  if (issuer.protocol !== "https:" || redirectUri.protocol !== "https:") throw new Error("OIDC issuer and callback must use HTTPS");
  return {
    issuer,
    clientId: required(environment, "VIBENEST_AUTH_CLIENT_ID"),
    clientSecret: environment.VIBENEST_AUTH_CLIENT_SECRET || undefined,
    redirectUri,
    applicationOrigin: new URL("/", redirectUri).href,
  };
}

async function config(environment) {
  if (!configuration) {
    const value = settings(environment);
    configuration = await oidc.discovery(value.issuer, value.clientId, value.clientSecret);
  }
  return configuration;
}

export async function beginLogin(session, environment = process.env, api = oidc) {
  const value = settings(environment);
  const codeVerifier = api.randomPKCECodeVerifier();
  const state = api.randomState();
  const nonce = api.randomNonce();
  const pending = { codeVerifier, state, nonce, expiresAt: Date.now() + 300_000 };
  const authorizationUrl = api.buildAuthorizationUrl(await config(environment), {
    redirect_uri: value.redirectUri.href,
    response_type: "code",
    scope: "openid profile email",
    code_challenge: await api.calculatePKCECodeChallenge(codeVerifier),
    code_challenge_method: "S256",
    state,
    nonce,
  });
  return { authorizationUrl, session: { ...session, pending, expiresAt: Date.now() + 300_000 } };
}

export async function finishLogin(request, session, environment = process.env, api = oidc) {
  const value = settings(environment);
  const pending = session.pending;
  if (!pending || pending.expiresAt < Date.now()) throw new Error("expired login");
  if (!pending.codeVerifier || !pending.state || !pending.nonce) throw new Error("incomplete login");
  const callbackUrl = new URL(value.redirectUri);
  callbackUrl.search = new URL(request.url).search;
  const tokens = await api.authorizationCodeGrant(await config(environment), callbackUrl, {
    pkceCodeVerifier: pending.codeVerifier,
    expectedState: pending.state,
    expectedNonce: pending.nonce,
    idTokenExpected: true,
  });
  const claims = tokens.claims();
  if (!claims?.sub) throw new Error("missing subject");
  let profile = {};
  if (tokens.access_token && typeof api.fetchUserInfo === "function") {
    profile = await api.fetchUserInfo(await config(environment), tokens.access_token, claims.sub);
  }
  return {
    subject: claims.sub,
    email: profile.email ?? claims.email,
    emailVerified: profile.email_verified ?? claims.email_verified,
    csrf: newCsrf(),
    expiresAt: Date.now() + 8 * 60 * 60_000,
  };
}

export function callbackUrlFromRequest(requestUrl, environment = process.env) {
  const callback = new URL(settings(environment).redirectUri);
  callback.search = new URL(requestUrl).search;
  return callback;
}

function required(environment, name) {
  const value = environment[name];
  if (typeof value !== "string" || value.trim() === "") throw new Error(`Missing ${name}`);
  return value.trim();
}
