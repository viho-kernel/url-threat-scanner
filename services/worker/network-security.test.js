import assert from "node:assert/strict";
import test from "node:test";

import {
  isPublicAddress,
  validateScanUrl
} from "./network-security.js";

test("allows public IPv4 addresses", () => {
  assert.equal(isPublicAddress("8.8.8.8"), true);
  assert.equal(isPublicAddress("1.1.1.1"), true);
});

test("blocks private and special IPv4 addresses", () => {
  const blocked = [
    "127.0.0.1",
    "10.0.0.1",
    "172.16.0.1",
    "192.168.1.1",
    "169.254.169.254",
    "100.64.0.1",
    "0.0.0.0",
    "224.0.0.1"
  ];

  for (const address of blocked) {
    assert.equal(
      isPublicAddress(address),
      false,
      `${address} should be blocked`
    );
  }
});

test("blocks private and special IPv6 addresses", () => {
  const blocked = [
    "::1",
    "::",
    "fc00::1",
    "fd00::1",
    "fe80::1",
    "ff02::1",
    "::ffff:127.0.0.1",
    "::ffff:169.254.169.254"
  ];

  for (const address of blocked) {
    assert.equal(
      isPublicAddress(address),
      false,
      `${address} should be blocked`
    );
  }
});

test("allows only HTTP and HTTPS URLs", () => {
  assert.equal(
    validateScanUrl("https://example.com").protocol,
    "https:"
  );

  assert.throws(
    () => validateScanUrl("file:///etc/passwd"),
    /unsupported_protocol/
  );
});

test("blocks URL credentials and unexpected ports", () => {
  assert.throws(
    () => validateScanUrl("https://user:pass@example.com"),
    /url_credentials_not_allowed/
  );

  assert.throws(
    () => validateScanUrl("https://example.com:8080"),
    /port_not_allowed/
  );
});