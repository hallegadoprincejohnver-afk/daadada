import test from "node:test";
import assert from "node:assert/strict";
import {
  assertInitialHostAllowed,
  getMonetizationProvider,
  isPublicAddress,
  resolveUrl,
  parseAllowedHosts,
  validateUrl
} from "../src/resolver.js";

test("accepts standard HTTPS shortener URLs", () => {
  const url = validateUrl("https://bit.ly/abc123");
  assert.equal(url.protocol, "https:");
  assert.equal(url.hostname, "bit.ly");
});

test("removes URL fragments before resolution", () => {
  const url = validateUrl("https://bit.ly/abc123#fragment");
  assert.equal(url.hash, "");
});

test("rejects non-HTTPS URLs", () => {
  assert.throws(
    () => validateUrl("http://bit.ly/abc123"),
    (error) => error.code === "UNSUPPORTED_PROTOCOL"
  );
});

test("rejects credentials in URLs", () => {
  assert.throws(
    () => validateUrl("https://user:password@bit.ly/abc123"),
    (error) => error.code === "INVALID_URL"
  );
});

test("rejects nonstandard ports", () => {
  assert.throws(
    () => validateUrl("https://bit.ly:8443/abc123"),
    (error) => error.code === "UNSUPPORTED_PORT"
  );
});

test("rejects IP-literal URLs", () => {
  assert.throws(
    () => validateUrl("https://127.0.0.1/"),
    (error) => error.code === "UNSAFE_HOST"
  );
  assert.throws(
    () => validateUrl("https://[::1]/"),
    (error) => error.code === "UNSAFE_HOST"
  );
});

test("allowlist matching is exact and case-insensitive", () => {
  const allowed = parseAllowedHosts("BIT.LY, tinyurl.com");
  assertInitialHostAllowed(validateUrl("https://bit.ly/x"), allowed);
  assert.throws(
    () => assertInitialHostAllowed(validateUrl("https://bit.ly.attacker.example/x"), allowed),
    (error) => error.code === "UNSUPPORTED_DOMAIN"
  );
});

test("blocks private, loopback, link-local and documentation addresses", () => {
  for (const address of [
    "127.0.0.1",
    "10.0.0.1",
    "172.16.0.1",
    "192.168.1.1",
    "169.254.169.254",
    "100.64.0.1",
    "192.0.2.10",
    "::1",
    "fc00::1",
    "fe80::1",
    "2001:db8::1",
    "::ffff:10.0.0.1"
  ]) {
    assert.equal(isPublicAddress(address), false, address + " must be blocked");
  }
});

test("accepts representative public IPv4 and IPv6 addresses", () => {
  assert.equal(isPublicAddress("1.1.1.1"), true);
  assert.equal(isPublicAddress("8.8.8.8"), true);
  assert.equal(isPublicAddress("2606:4700:4700::1111"), true);
});

test("rejects malformed input and overly long URLs", () => {
  assert.throws(() => validateUrl("not a URL"), (error) => error.code === "INVALID_URL");
  assert.throws(
    () => validateUrl("https://bit.ly/" + "a".repeat(2100)),
    (error) => error.code === "INVALID_URL"
  );
});


test("recognizes Linkvertise domains without claiming to resolve checkpoints", () => {
  assert.equal(getMonetizationProvider("direct-link.net"), "Linkvertise");
  assert.equal(getMonetizationProvider("linkvertise.com"), "Linkvertise");
  assert.equal(getMonetizationProvider("www.direct-link.net"), "Linkvertise");
});

test("recognizes official LootLabs link domains", () => {
  assert.equal(getMonetizationProvider("loot-link.com"), "LootLabs");
  assert.equal(getMonetizationProvider("links.lootlabs.gg"), "LootLabs");
  assert.equal(getMonetizationProvider("lootlabs.gg"), "LootLabs");
});

test("does not fetch or bypass supplied Linkvertise checkpoint URLs", async () => {
  await assert.rejects(
    resolveUrl("https://direct-link.net/1258318/BXT2zdn4PTmi?share_origin=explore&utm_source=copy_url"),
    (error) => error.code === "PROVIDER_CHECKPOINT_REQUIRED" && error.statusCode === 422
  );
});

test("does not fetch or bypass LootLabs checkpoint URLs", async () => {
  await assert.rejects(
    resolveUrl("https://loot-link.com/s?example"),
    (error) => error.code === "PROVIDER_CHECKPOINT_REQUIRED" && error.statusCode === 422
  );
});

test("does not classify unrelated hosts as monetization providers", () => {
  assert.equal(getMonetizationProvider("bit.ly"), null);
  assert.equal(getMonetizationProvider("example.org"), null);
  assert.equal(getMonetizationProvider("loot-link.com.attacker.example"), null);
});
