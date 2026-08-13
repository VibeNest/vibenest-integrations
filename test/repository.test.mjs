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
