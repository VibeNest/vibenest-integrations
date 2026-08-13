import { existsSync, readFileSync, readdirSync } from "node:fs";
import { join, relative } from "node:path";

const root = new URL("../", import.meta.url);
const rootPath = decodeURIComponent(root.pathname).replace(
  /^\/(?:([A-Za-z]):)/,
  "$1:",
);
const stacks = ["nextjs", "express", "aspnet-core"];
const families = ["auth", "payments", "auth-and-payments"];
const upstreamCommit = "39279c3190ac59f08354e1950ee32d59be4dd9a6";
const routes = {
  auth: [
    "/auth/vibenest/login",
    "/auth/vibenest/callback",
    "/auth/logout",
    "/api/session",
  ],
  payments: {
    nextjs: [
      "/api/project-payments/prices",
      "/api/project-payments/checkout",
      "/api/project-payments/portal",
      "/api/project-payments/webhook",
    ],
    express: [
      "/api/project-payments/prices/preview",
      "/api/project-payments/checkout",
      "/api/project-payments/portal",
      "/webhooks/project-payments",
    ],
    "aspnet-core": [
      "/api/project-payments/prices",
      "/api/project-payments/checkout",
      "/api/project-payments/portal",
      "/webhooks/project-payments",
    ],
  },
};

for (const family of families) {
  for (const stack of stacks) {
    const directory = join(rootPath, family, stack);
    for (const required of ["README.md", ".env.example", "Dockerfile"]) {
      if (!existsSync(join(directory, required))) {
        throw new Error(`${family}/${stack} is missing ${required}`);
      }
    }
    const files = walk(directory);
    if (
      !files.some(
        (file) => file === "package-lock.json" || file === "packages.lock.json",
      )
    ) {
      throw new Error(`${family}/${stack} is missing a lock file`);
    }
    const readme = readFileSync(join(directory, "README.md"), "utf8");
    for (const command of ["Install", "Run", "Test", "Routes", "Environment"]) {
      if (!readme.includes(`## ${command}`))
        throw new Error(`${family}/${stack} README is missing ${command}`);
    }
    const env = readFileSync(join(directory, ".env.example"), "utf8");
    for (const line of env
      .split(/\r?\n/)
      .filter((value) => value && !value.startsWith("#"))) {
      const value = line.slice(line.indexOf("=") + 1);
      const allowed = [
        "",
        "change-me",
        "true",
        "false",
        "simulator",
        "loopback",
        "3000",
        "8080",
      ];
      if (
        !allowed.includes(value) &&
        !value.startsWith("https://") &&
        !value.startsWith(".data/")
      ) {
        throw new Error(
          `${family}/${stack} .env.example may contain a non-placeholder value`,
        );
      }
    }
    const source = files
      .filter(
        (file) =>
          /\.(?:cs|js|mjs)$/.test(file) &&
          !file.startsWith("test") &&
          !file.includes("-tests/"),
      )
      .map((file) => readFileSync(join(directory, file), "utf8"))
      .join("\n");
    const referencedEnvironment = new Set(
      source.match(
        /\b(?:VIBENEST_[A-Z0-9_]+|APP_SESSION_SECRET|TRUSTED_PROXY_CIDR|PROJECT_PAYMENT_[A-Z0-9_]+|SOURCE_COMMIT|PORT)\b/g,
      ) ?? [],
    );
    referencedEnvironment.delete("VIBENEST_FIXTURE_AUTH_ENABLED");
    for (const name of referencedEnvironment) {
      if (!env.match(new RegExp(`^${name}=`, "m"))) {
        throw new Error(`${family}/${stack} .env.example is missing ${name}`);
      }
    }
    const expectedRoutes = [
      ...(family === "auth" || family === "auth-and-payments"
        ? routes.auth
        : []),
      ...(family === "payments" || family === "auth-and-payments"
        ? routes.payments[stack]
        : []),
    ];
    for (const route of expectedRoutes) {
      if (!readme.includes(route)) {
        throw new Error(`${family}/${stack} README is missing route ${route}`);
      }
    }
  }
}

const authFiles = walk(join(rootPath, "auth"));
for (const forbidden of [
  "payments.yaml",
  "project-payments",
  "checkout",
  "webhook",
  "entitlement",
]) {
  if (authFiles.some((file) => file.toLowerCase().includes(forbidden))) {
    throw new Error(
      `Auth-only tree contains forbidden payment artifact: ${forbidden}`,
    );
  }
}

const authSource = authFiles
  .filter((file) => /\.(?:cs|js|mjs)$/.test(file) && !file.startsWith("test"))
  .map((file) => readFileSync(join(rootPath, "auth", file), "utf8"))
  .join("\n");
if (
  /\/api\/(?:project-payments|checkout|test-checkout)|\/webhooks\/project-payments/.test(
    authSource,
  )
) {
  throw new Error("Auth-only tree contains a payment route");
}

const provenance = readFileSync(join(rootPath, "SOURCE_PROVENANCE.md"), "utf8");
if (!provenance.includes(upstreamCommit))
  throw new Error(
    "Source provenance is not pinned to the verified upstream commit",
  );

console.log(
  "Repository structure, lock files, docs, env placeholders, and Auth-only boundary: OK",
);

function walk(directory, base = directory) {
  return readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    if (["node_modules", ".next", "bin", "obj"].includes(entry.name)) return [];
    const path = join(directory, entry.name);
    return entry.isDirectory()
      ? walk(path, base)
      : [relative(base, path).replaceAll("\\", "/")];
  });
}
