import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

test("root documentation preserves consent and identity boundaries", async () => {
  const readme = await readFile(
    new URL("../README.md", import.meta.url),
    "utf8",
  );
  assert.match(readme, /do not create payment files or routes/i);
  assert.match(readme, /pairwise `sub`/i);
  assert.match(readme, /Never request a user's Personal Access Token/i);
  assert.match(readme, /Payments simulator preview/);
});

test("security policy forbids secrets and live money movement", async () => {
  const policy = await readFile(
    new URL("../SECURITY.md", import.meta.url),
    "utf8",
  );
  assert.match(policy, /Never commit/i);
  assert.match(policy, /do not perform charges/i);
});

test("root compatibility matrix includes the three additional ecosystems", async () => {
  const readme = await readFile(
    new URL("../README.md", import.meta.url),
    "utf8",
  );
  for (const stack of ["FastAPI", "Laravel", "Rails"]) {
    assert.match(readme, new RegExp(`\\| ${stack}`));
  }
});

test("real env files are ignored while examples remain trackable", async () => {
  const ignore = await readFile(
    new URL("../.gitignore", import.meta.url),
    "utf8",
  );
  assert.match(ignore, /^\*\*\/\.env$/m);
  assert.match(ignore, /^\*\*\/\.env\.\*$/m);
  assert.match(ignore, /^!\*\*\/\.env\.example$/m);
});

test("example secret values are empty and Rails has no runtime fallback", async () => {
  const families = ["auth", "payments", "auth-and-payments"];
  const stacks = [
    "nextjs",
    "express",
    "aspnet-core",
    "fastapi",
    "laravel",
    "rails",
  ];
  for (const family of families) {
    for (const stack of stacks) {
      const env = await readFile(
        new URL(`../${family}/${stack}/.env.example`, import.meta.url),
        "utf8",
      );
      for (const line of env.split(/\r?\n/)) {
        if (/^(?:.*SECRET.*|APP_KEY)=/.test(line)) assert.match(line, /=$/);
      }
    }
  }

  for (const family of families) {
    const application = await readFile(
      new URL(`../${family}/rails/config/application.rb`, import.meta.url),
      "utf8",
    );
    assert.match(application, /ENV\.fetch\("SECRET_KEY_BASE"\)/);
    assert.doesNotMatch(application, /test-(?:only-)?secret-key-base/);
  }
});
