import dns from "node:dns/promises";
import ipaddr from "ipaddr.js";

export class ScanSecurityError extends Error {
  constructor(code) {
    super(code);
    this.name = "ScanSecurityError";
    this.code = code;
  }
}

export function isPublicAddress(rawAddress) {
  let address;

  try {
    address = ipaddr.parse(rawAddress);
  } catch {
    return false;
  }

  if (
    address.kind() === "ipv6" &&
    address.isIPv4MappedAddress()
  ) {
    address = address.toIPv4Address();
  }

  return address.range() === "unicast";
}

export function validateScanUrl(rawUrl) {
  let parsedUrl;

  try {
    parsedUrl = new URL(rawUrl);
  } catch {
    throw new ScanSecurityError("invalid_url");
  }

  if (
    parsedUrl.protocol !== "http:" &&
    parsedUrl.protocol !== "https:"
  ) {
    throw new ScanSecurityError("unsupported_protocol");
  }

  if (parsedUrl.username || parsedUrl.password) {
    throw new ScanSecurityError("url_credentials_not_allowed");
  }

  const port = parsedUrl.port;

  if (
    port &&
    port !== "80" &&
    port !== "443"
  ) {
    throw new ScanSecurityError("port_not_allowed");
  }

  if (!parsedUrl.hostname) {
    throw new ScanSecurityError("hostname_required");
  }

  return parsedUrl;
}

export async function resolvePublicTarget(rawUrl) {
  const parsedUrl = validateScanUrl(rawUrl);

  let addresses;

  try {
    addresses = await dns.lookup(
      parsedUrl.hostname,
      {
        all: true,
        verbatim: true
      }
    );
  } catch (error) {
    if (error?.code === "EAI_AGAIN") {
      throw new Error("dns_temporary_failure");
    }

    throw new ScanSecurityError("dns_resolution_failed");
  }

  if (addresses.length === 0) {
    throw new ScanSecurityError("dns_no_addresses");
  }

  const blockedAddress = addresses.find(
    (record) => !isPublicAddress(record.address)
  );

  if (blockedAddress) {
    throw new ScanSecurityError(
      "dns_resolved_to_non_public_address"
    );
  }

  return {
    url: parsedUrl,
    addresses,
    selectedAddress: addresses[0]
  };
}