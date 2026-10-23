import dns from "node:dns/promises";
import https from "node:https";
import ipaddr from "ipaddr.js";

export const DEFAULT_ALLOWED_HOSTS = [
  "bit.ly",
  "tinyurl.com",
  "is.gd",
  "rb.gy",
  "t.co",
  "ow.ly",
  "buff.ly",
  "shorturl.at"
];

export class ResolverError extends Error {
  constructor(code, message, statusCode = 422) {
    super(message);
    this.name = "ResolverError";
    this.code = code;
    this.statusCode = statusCode;
  }
}

const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);
const MAX_REDIRECTS = 8;
const DNS_TIMEOUT_MS = 3000;
const REQUEST_TIMEOUT_MS = 5000;

const BLOCKED_V4 = [
  "0.0.0.0/8",
  "10.0.0.0/8",
  "100.64.0.0/10",
  "127.0.0.0/8",
  "169.254.0.0/16",
  "172.16.0.0/12",
  "192.0.0.0/24",
  "192.0.2.0/24",
  "192.88.99.0/24",
  "192.168.0.0/16",
  "198.18.0.0/15",
  "198.51.100.0/24",
  "203.0.113.0/24",
  "224.0.0.0/4",
  "240.0.0.0/4"
].map((cidr) => ipaddr.parseCIDR(cidr));

const BLOCKED_V6 = [
  "::/128",
  "::1/128",
  "fc00::/7",
  "fe80::/10",
  "ff00::/8",
  "2001:db8::/32",
  "2002::/16"
].map((cidr) => ipaddr.parseCIDR(cidr));

function normalizedHost(host) {
  return String(host || "").toLowerCase().replace(/^\[/, "").replace(/\]$/, "").replace(/\.$/, "");
}

export function parseAllowedHosts(raw = process.env.ALLOWED_HOSTS) {
  const source = raw === undefined ? DEFAULT_ALLOWED_HOSTS.join(",") : raw;
  return new Set(
    String(source)
      .split(",")
      .map((host) => normalizedHost(host.trim()))
      .filter(Boolean)
  );
}

export function isPublicAddress(address) {
  let parsed;
  try {
    parsed = ipaddr.parse(address);
  } catch {
    return false;
  }

  if (parsed.kind() === "ipv6" && parsed.isIPv4MappedAddress()) {
    return isPublicAddress(parsed.toIPv4Address().toString());
  }

  if (parsed.range() !== "unicast") {
    return false;
  }

  const blocked = parsed.kind() === "ipv4" ? BLOCKED_V4 : BLOCKED_V6;
  return !blocked.some(([network, prefix]) => parsed.match(network, prefix));
}

export function validateUrl(input) {
  if (typeof input !== "string" || input.length === 0 || input.length > 2048) {
    throw new ResolverError("INVALID_URL", "Provide a URL between 1 and 2048 characters.", 400);
  }

  let parsed;
  try {
    parsed = new URL(input);
  } catch {
    throw new ResolverError("INVALID_URL", "The URL is not valid.", 400);
  }

  if (parsed.protocol !== "https:") {
    throw new ResolverError("UNSUPPORTED_PROTOCOL", "Only HTTPS URLs are supported.", 400);
  }

  if (parsed.username || parsed.password) {
    throw new ResolverError("INVALID_URL", "URLs containing username or password fields are not supported.", 400);
  }

  if (parsed.port && parsed.port !== "443") {
    throw new ResolverError("UNSUPPORTED_PORT", "Only the standard HTTPS port is supported.", 400);
  }

  const host = normalizedHost(parsed.hostname);
  if (!host || host === "localhost" || host.endsWith(".localhost") || host.endsWith(".local")) {
    throw new ResolverError("UNSAFE_HOST", "This destination host is not allowed.", 422);
  }

  if (ipaddr.isValid(host)) {
    throw new ResolverError("UNSAFE_HOST", "IP-literal URLs are not supported.", 422);
  }

  parsed.hostname = host;
  parsed.hash = "";
  return parsed;
}

export function assertInitialHostAllowed(url, allowedHosts = parseAllowedHosts()) {
  const host = normalizedHost(url.hostname);
  if (!allowedHosts.has(host)) {
    throw new ResolverError(
      "UNSUPPORTED_DOMAIN",
      "This domain is not supported by the resolver.",
      403
    );
  }
}

async function lookupPublicAddresses(host) {
  let timeout;
  try {
    const records = await Promise.race([
      dns.lookup(host, { all: true, verbatim: true }),
      new Promise((_, reject) => {
        timeout = setTimeout(() => {
          reject(new ResolverError("DNS_TIMEOUT", "DNS lookup timed out.", 504));
        }, DNS_TIMEOUT_MS);
      })
    ]);

    if (!Array.isArray(records) || records.length === 0) {
      throw new ResolverError("DNS_LOOKUP_FAILED", "The destination host could not be resolved.", 422);
    }

    if (records.some((record) => !isPublicAddress(record.address))) {
      throw new ResolverError("UNSAFE_HOST", "The destination resolves to a non-public IP address.", 422);
    }

    return records;
  } catch (error) {
    if (error instanceof ResolverError) throw error;
    throw new ResolverError("DNS_LOOKUP_FAILED", "The destination host could not be resolved safely.", 422);
  } finally {
    if (timeout) clearTimeout(timeout);
  }
}

async function requestRedirectHeaders(url) {
  const host = normalizedHost(url.hostname);
  const addresses = await lookupPublicAddresses(host);

  return new Promise((resolve, reject) => {
    let settled = false;
    let timer;

    const finish = (callback, value) => {
      if (settled) return;
      settled = true;
      if (timer) clearTimeout(timer);
      callback(value);
    };

    const req = https.request(url, {
      method: "GET",
      agent: false,
      maxHeaderSize: 16384,
      servername: host,
      headers: {
        "User-Agent": "SecureURLResolver/1.0",
        "Accept": "*/*",
        "Connection": "close"
      },
      lookup: (_hostname, options, callback) => {
        if (typeof options === "function") {
          callback = options;
          options = {};
        }

        if (options && options.all) {
          callback(null, addresses.map((record) => ({
            address: record.address,
            family: record.family
          })));
          return;
        }

        callback(null, addresses[0].address, addresses[0].family);
      }
    }, (response) => {
      const result = {
        statusCode: response.statusCode || 0,
        location: typeof response.headers.location === "string" ? response.headers.location : null
      };
      response.destroy();
      finish(resolve, result);
    });

    req.on("error", (error) => {
      if (error && error.code === "UPSTREAM_TIMEOUT") {
        finish(reject, new ResolverError("UPSTREAM_TIMEOUT", "The destination request timed out.", 504));
        return;
      }
      finish(reject, new ResolverError("UPSTREAM_ERROR", "The destination could not be reached.", 502));
    });

    timer = setTimeout(() => {
      const error = new Error("upstream request timed out");
      error.code = "UPSTREAM_TIMEOUT";
      req.destroy(error);
    }, REQUEST_TIMEOUT_MS);

    req.end();
  });
}

export async function resolveUrl(input, options = {}) {
  const allowedHosts = options.allowedHosts || parseAllowedHosts();
  const maxRedirects = Number.isInteger(options.maxRedirects) ? options.maxRedirects : MAX_REDIRECTS;
  const original = validateUrl(input);
  assertInitialHostAllowed(original, allowedHosts);

  let current = original;
  let redirectsFollowed = 0;
  const visited = new Set();

  while (true) {
    if (visited.has(current.href)) {
      throw new ResolverError("REDIRECT_LOOP", "A redirect loop was detected.", 422);
    }
    visited.add(current.href);

    const response = await requestRedirectHeaders(current);

    if (!REDIRECT_STATUSES.has(response.statusCode) || !response.location) {
      return {
        originalUrl: original.href,
        resolvedUrl: current.href,
        redirectsFollowed,
        httpStatus: response.statusCode
      };
    }

    if (redirectsFollowed >= maxRedirects) {
      throw new ResolverError("MAX_REDIRECTS", "The URL exceeded the redirect limit.", 422);
    }

    let next;
    try {
      next = validateUrl(new URL(response.location, current).href);
    } catch (error) {
      if (error instanceof ResolverError) {
        throw new ResolverError("UNSAFE_REDIRECT", "A redirect pointed to an unsupported or unsafe URL.", 422);
      }
      throw new ResolverError("UNSAFE_REDIRECT", "A redirect pointed to an invalid URL.", 422);
    }

    current = next;
    redirectsFollowed += 1;
  }
}
