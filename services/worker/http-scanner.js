import http from "node:http";
import https from "node:https";

import {
  ScanSecurityError,
  resolvePublicTarget
} from "./network-security.js";

const REQUEST_TIMEOUT_MS = 5000;
const MAX_BODY_BYTES = 32768;
const MAX_REDIRECTS = 3;

const redirectStatuses = new Set([
  301,
  302,
  303,
  307,
  308
]);

function selectedHeaders(headers) {
  const names = [
    "content-type",
    "content-length",
    "server",
    "location",
    "strict-transport-security",
    "content-security-policy",
    "x-content-type-options",
    "x-frame-options",
    "referrer-policy",
    "permissions-policy"
  ];

  return Object.fromEntries(
    names
      .filter((name) => headers[name] !== undefined)
      .map((name) => [
        name,
        Array.isArray(headers[name])
          ? headers[name].join(", ")
          : String(headers[name])
      ])
  );
}

function pinnedLookup(record) {
  return (_hostname, options, callback) => {
    if (options && options.all) {
      callback(null, [
        {
          address: record.address,
          family: record.family
        }
      ]);
      return;
    }

    callback(
      null,
      record.address,
      record.family
    );
  };
}

async function requestOnce(rawUrl) {
  const target = await resolvePublicTarget(rawUrl);

  const transport =
    target.url.protocol === "https:"
      ? https
      : http;

  return new Promise((resolve, reject) => {
    let settled = false;

    const request = transport.request(
      target.url,
      {
        method: "GET",
        lookup: pinnedLookup(target.selectedAddress),
        family: target.selectedAddress.family,
        headers: {
          "User-Agent": "URL-Threat-Scanner/0.1",
          Accept: "*/*",
          "Accept-Encoding": "identity",
          Range: `bytes=0-${MAX_BODY_BYTES - 1}`
        }
      },
      (response) => {
        const chunks = [];
        let receivedBytes = 0;
        let truncated = false;

        const finish = () => {
          if (settled) {
            return;
          }

          settled = true;

          resolve({
            requestedUrl: target.url.toString(),
            statusCode: response.statusCode ?? 0,
            headers: selectedHeaders(response.headers),
            addresses: target.addresses,
            selectedAddress: target.selectedAddress,
            bodySample: Buffer.concat(chunks).toString(
              "utf8"
            ),
            truncated
          });
        };

        response.on("data", (chunk) => {
          if (settled) {
            return;
          }

          const remaining =
            MAX_BODY_BYTES - receivedBytes;

          if (remaining <= 0) {
            truncated = true;
            response.destroy();
            finish();
            return;
          }

          const acceptedChunk =
            chunk.length > remaining
              ? chunk.subarray(0, remaining)
              : chunk;

          chunks.push(acceptedChunk);
          receivedBytes += acceptedChunk.length;

          if (chunk.length > remaining) {
            truncated = true;
            response.destroy();
            finish();
          }
        });

        response.on("end", finish);

        response.on("error", (error) => {
          if (!settled) {
            reject(error);
          }
        });
      }
    );

    request.setTimeout(
      REQUEST_TIMEOUT_MS,
      () => {
        request.destroy(
          new Error("request_timeout")
        );
      }
    );

    request.on("error", (error) => {
      if (!settled) {
        reject(error);
      }
    });

    request.end();
  });
}

function createVerdict(finalResponse, redirects) {
  const flags = [];
  let riskScore = 0;

  const finalUrl = new URL(
    finalResponse.requestedUrl
  );

  if (finalUrl.protocol === "http:") {
    flags.push("unencrypted_http");
    riskScore += 20;
  }

  if (redirects.some(
    (redirect) =>
      new URL(redirect.from).hostname !==
      new URL(redirect.to).hostname
  )) {
    flags.push("cross_hostname_redirect");
    riskScore += 10;
  }

  if (finalResponse.statusCode >= 400) {
    flags.push("http_error_response");
    riskScore += 10;
  }

  const body = finalResponse.bodySample.toLowerCase();

  const suspiciousBodyWords = [
    "enter your password",
    "verify your account",
    "seed phrase",
    "crypto wallet"
  ];

  if (
    suspiciousBodyWords.some(
      (word) => body.includes(word)
    )
  ) {
    flags.push("suspicious_response_content");
    riskScore += 30;
  }

  riskScore = Math.min(riskScore, 100);

  let verdict = "low-risk";

  if (riskScore >= 40) {
    verdict = "suspicious";
  } else if (riskScore >= 20) {
    verdict = "review";
  }

  return {
    verdict,
    riskScore,
    flags
  };
}

export async function inspectUrl(rawUrl) {
  let currentUrl = rawUrl;
  const redirects = [];

  for (
    let redirectCount = 0;
    redirectCount <= MAX_REDIRECTS;
    redirectCount += 1
  ) {
    const response = await requestOnce(currentUrl);

    const location =
      response.headers.location;

    if (
      redirectStatuses.has(response.statusCode) &&
      location
    ) {
      if (redirectCount === MAX_REDIRECTS) {
        throw new ScanSecurityError(
          "too_many_redirects"
        );
      }

      const nextUrl = new URL(
        location,
        response.requestedUrl
      ).toString();

      redirects.push({
        from: response.requestedUrl,
        to: nextUrl,
        statusCode: response.statusCode
      });

      currentUrl = nextUrl;
      continue;
    }

    const verdict = createVerdict(
      response,
      redirects
    );

    return {
      final_url: response.requestedUrl,
      status_code: response.statusCode,
      resolved_addresses:
        response.addresses.map(
          (record) => record.address
        ),
      connected_address:
        response.selectedAddress.address,
      headers: response.headers,
      redirects,
      body_truncated: response.truncated,
      verdict: verdict.verdict,
      risk_score: verdict.riskScore,
      flags: verdict.flags,
      reputation: {
        status: "not_configured"
      }
    };
  }

  throw new ScanSecurityError(
    "too_many_redirects"
  );
}