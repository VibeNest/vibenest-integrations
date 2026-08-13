import express from "express";
import session from "express-session";
import { installVibeNestAuth } from "./vibenest-auth.mjs";

export function createApp(environment = process.env, dependencies = {}) {
  const app = express();
  app.disable("x-powered-by");
  app.set("trust proxy", environment.TRUSTED_PROXY_CIDR ?? "loopback");
  app.use(
    session({
      name: "vibenest_app_session",
      secret: required(environment, "APP_SESSION_SECRET"),
      store: dependencies.sessionStore,
      resave: false,
      saveUninitialized: false,
      cookie: {
        httpOnly: true,
        secure: true,
        sameSite: "lax",
        maxAge: 8 * 60 * 60_000,
      },
    }),
  );
  installVibeNestAuth(app, environment, dependencies.oidcApi);
  app.get("/healthz", (_request, response) =>
    response.type("text").send("Healthy"),
  );
  app.get("/", (_request, response) =>
    response
      .type("html")
      .send(
        '<h1>VibeNest Auth reference</h1><a href="/auth/vibenest/login">Sign in with VibeNest</a>',
      ),
  );
  app.use((_error, _request, response, _next) => response.sendStatus(500));
  return app;
}

function required(environment, name) {
  const value = environment[name];
  if (typeof value !== "string" || value.length < 32)
    throw new Error(`${name} must contain at least 32 characters`);
  return value;
}

if (
  process.argv[1] &&
  new URL(import.meta.url).pathname.endsWith(
    process.argv[1].replaceAll("\\", "/"),
  )
) {
  createApp().listen(
    Number.parseInt(process.env.PORT ?? "8080", 10),
    "0.0.0.0",
  );
}
