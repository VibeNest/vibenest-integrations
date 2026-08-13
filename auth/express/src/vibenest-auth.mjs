import { randomBytes, timingSafeEqual } from "node:crypto";
import * as oidc from "openid-client";

let configuration;

export function authSettings(environment = process.env) {
  const issuer = new URL(required(environment, "VIBENEST_AUTH_ISSUER"));
  const redirectUri = new URL(
    required(environment, "VIBENEST_AUTH_REDIRECT_URI"),
  );
  if (issuer.protocol !== "https:" || redirectUri.protocol !== "https:")
    throw new Error("OIDC issuer and callback must use HTTPS");
  return {
    issuer,
    redirectUri,
    applicationOrigin: new URL("/", redirectUri).href,
    clientId: required(environment, "VIBENEST_AUTH_CLIENT_ID"),
    clientSecret: environment.VIBENEST_AUTH_CLIENT_SECRET || undefined,
  };
}

async function config(environment) {
  if (!configuration) {
    const value = authSettings(environment);
    configuration = await oidc.discovery(
      value.issuer,
      value.clientId,
      value.clientSecret,
    );
  }
  return configuration;
}

export function installVibeNestAuth(
  app,
  environment = process.env,
  api = oidc,
) {
  const value = authSettings(environment);

  app.get("/auth/vibenest/login", async (request, response, next) => {
    try {
      const codeVerifier = api.randomPKCECodeVerifier();
      const state = api.randomState();
      const nonce = api.randomNonce();
      request.session.oidc = {
        codeVerifier,
        state,
        nonce,
        expiresAt: Date.now() + 300_000,
      };
      const authorizationUrl = api.buildAuthorizationUrl(
        await config(environment),
        {
          redirect_uri: value.redirectUri.href,
          response_type: "code",
          scope: "openid profile email",
          code_challenge: await api.calculatePKCECodeChallenge(codeVerifier),
          code_challenge_method: "S256",
          state,
          nonce,
        },
      );
      request.session.save((error) =>
        error ? next(error) : response.redirect(303, authorizationUrl.href),
      );
    } catch (error) {
      next(error);
    }
  });

  app.get("/auth/vibenest/callback", async (request, response, next) => {
    try {
      const pending = request.session.oidc;
      delete request.session.oidc;
      if (
        !pending ||
        pending.expiresAt < Date.now() ||
        !pending.codeVerifier ||
        !pending.state ||
        !pending.nonce
      ) {
        return response.sendStatus(400);
      }
      const callbackUrl = callbackUrlFromRequest(
        request.originalUrl,
        environment,
      );
      const tokens = await api.authorizationCodeGrant(
        await config(environment),
        callbackUrl,
        {
          pkceCodeVerifier: pending.codeVerifier,
          expectedState: pending.state,
          expectedNonce: pending.nonce,
          idTokenExpected: true,
        },
      );
      const claims = tokens.claims();
      if (!claims?.sub) return response.sendStatus(401);
      let profile = {};
      if (tokens.access_token && typeof api.fetchUserInfo === "function") {
        profile = await api.fetchUserInfo(
          await config(environment),
          tokens.access_token,
          claims.sub,
        );
      }
      request.session.regenerate((error) => {
        if (error) return next(error);
        request.session.user = {
          subject: claims.sub,
          email: profile.email ?? claims.email,
        };
        request.session.csrf = randomBytes(24).toString("base64url");
        request.session.save((saveError) =>
          saveError
            ? next(saveError)
            : response.redirect(303, value.applicationOrigin),
        );
      });
    } catch (error) {
      next(error);
    }
  });

  app.post(
    "/auth/logout",
    requireUser,
    requireCsrf(value.applicationOrigin),
    (request, response, next) => {
      request.session.destroy((error) =>
        error ? next(error) : response.redirect(303, value.applicationOrigin),
      );
    },
  );

  app.get("/api/session", requireUser, (request, response) => {
    response.json({
      authenticated: true,
      subject: request.session.user.subject,
      email: request.session.user.email,
      csrf: request.session.csrf,
    });
  });
}

export function callbackUrlFromRequest(originalUrl, environment = process.env) {
  const incoming = new URL(originalUrl, "http://request.invalid");
  const callback = new URL(authSettings(environment).redirectUri);
  callback.search = incoming.search;
  return callback;
}

export function requireUser(request, response, next) {
  if (!request.session?.user?.subject) return response.sendStatus(401);
  next();
}

export function requireCsrf(applicationOrigin) {
  return (request, response, next) => {
    const expected = request.session?.csrf;
    const supplied = request.get("X-CSRF-Token");
    if (
      request.get("Origin") !== new URL(applicationOrigin).origin ||
      !safeEqual(expected, supplied)
    )
      return response.sendStatus(403);
    next();
  };
}

function safeEqual(left, right) {
  if (typeof left !== "string" || typeof right !== "string") return false;
  const a = Buffer.from(left);
  const b = Buffer.from(right);
  return a.length === b.length && timingSafeEqual(a, b);
}

function required(environment, name) {
  const value = environment[name];
  if (typeof value !== "string" || value.trim() === "")
    throw new Error(`Missing ${name}`);
  return value.trim();
}
