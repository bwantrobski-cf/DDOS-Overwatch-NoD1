const CLOUDFLARE_API_BASE = "https://api.cloudflare.com/client/v4";
const CLOUDFLARE_GRAPHQL_ENDPOINT = `${CLOUDFLARE_API_BASE}/graphql`;
const UPSTREAM_FETCH_TIMEOUT_MS = 15_000;
const ACCOUNT_LOOKUP_TIMEOUT_MS = 5_000;

function calculateNearestRankPercentile(values, percentile = 95) {
  const sortedValues = values
    .map((value) => Number(value))
    .filter((value) => Number.isFinite(value) && value >= 0)
    .sort((left, right) => left - right);

  if (!sortedValues.length) {
    return 0;
  }

  const normalizedPercentile = Math.min(100, Math.max(0, Number(percentile) || 0));
  const rank = Math.max(1, Math.ceil((normalizedPercentile / 100) * sortedValues.length));
  return sortedValues[rank - 1];
}

function calculateTunnelUsageSummary({ rowsByDirection, tunnelNames, startMs, endMs }) {
  const intervalMs = 5 * 60 * 1000;
  const sampleCount = Math.max(0, Math.ceil((endMs - startMs) / intervalMs));
  const directions = ["ingress", "egress"];
  const tunnelLabelsByKey = new Map();

  for (const tunnelName of tunnelNames ?? []) {
    const label = String(tunnelName ?? "").trim();

    if (label) {
      tunnelLabelsByKey.set(label.toLowerCase(), label);
    }
  }

  for (const direction of directions) {
    for (const row of rowsByDirection?.[direction] ?? []) {
      const label = String(row?.tunnelName ?? "").trim();

      if (label && !tunnelLabelsByKey.has(label.toLowerCase())) {
        tunnelLabelsByKey.set(label.toLowerCase(), label);
      }
    }
  }

  const valuesByDirection = {
    ingress: new Map(),
    egress: new Map(),
  };

  for (const direction of directions) {
    for (const tunnelKey of tunnelLabelsByKey.keys()) {
      valuesByDirection[direction].set(tunnelKey, new Float64Array(sampleCount));
    }

    for (const row of rowsByDirection?.[direction] ?? []) {
      const tunnelKey = String(row?.tunnelName ?? "").trim().toLowerCase();
      const timestampMs = Number.isFinite(row?.timestampMs)
        ? row.timestampMs
        : Date.parse(String(row?.datetimeIso ?? ""));
      const bitRateBps = Number(row?.bitRateBps);
      const bucketIndex = Math.floor((timestampMs - startMs) / intervalMs);

      if (
        !tunnelKey ||
        !valuesByDirection[direction].has(tunnelKey) ||
        !Number.isFinite(timestampMs) ||
        bucketIndex < 0 ||
        bucketIndex >= sampleCount ||
        !Number.isFinite(bitRateBps) ||
        bitRateBps < 0
      ) {
        continue;
      }

      valuesByDirection[direction].get(tunnelKey)[bucketIndex] += bitRateBps;
    }
  }

  const aggregateValues = {
    ingress: new Float64Array(sampleCount),
    egress: new Float64Array(sampleCount),
  };
  const tunnels = [...tunnelLabelsByKey.entries()].map(([tunnelKey, tunnelName]) => {
    const result = { tunnelName };

    for (const direction of directions) {
      const values = valuesByDirection[direction].get(tunnelKey) ?? new Float64Array(sampleCount);
      const numericValues = Array.from(values);

      numericValues.forEach((value, index) => {
        aggregateValues[direction][index] += value;
      });
      result[direction + "P95Bps"] = calculateNearestRankPercentile(numericValues, 95);
      result[direction + "PeakBps"] = numericValues.length ? Math.max(...numericValues) : 0;
    }

    result.combinedP95Bps = result.ingressP95Bps + result.egressP95Bps;
    return result;
  });

  tunnels.sort((left, right) => {
    if (right.combinedP95Bps !== left.combinedP95Bps) {
      return right.combinedP95Bps - left.combinedP95Bps;
    }

    return left.tunnelName.localeCompare(right.tunnelName);
  });

  return {
    sampleCount,
    tunnels,
    totals: {
      ingressP95Bps: tunnels.reduce((total, tunnel) => total + tunnel.ingressP95Bps, 0),
      egressP95Bps: tunnels.reduce((total, tunnel) => total + tunnel.egressP95Bps, 0),
      concurrentIngressP95Bps: calculateNearestRankPercentile(
        Array.from(aggregateValues.ingress),
        95,
      ),
      concurrentEgressP95Bps: calculateNearestRankPercentile(
        Array.from(aggregateValues.egress),
        95,
      ),
    },
  };
}

const ADVANCED_TCP_PROTECTION_PATH = "/magic/advanced_tcp_protection/configs";

function resolveAdvancedTcpProtectionRoute(segments) {
  if (segments[1] !== "ddos-protection") {
    return null;
  }

  const routeSegments = segments.slice(2);

  if (routeSegments.length === 1 && routeSegments[0] === "status") {
    return {
      cloudflarePath: ADVANCED_TCP_PROTECTION_PATH + "/tcp_protection_status",
      allowedMethods: ["GET", "PATCH"],
      bodyType: "status",
    };
  }

  if (routeSegments[0] === "prefixes") {
    if (routeSegments.length === 1) {
      return {
        cloudflarePath: ADVANCED_TCP_PROTECTION_PATH + "/prefixes",
        allowedMethods: ["GET", "POST", "DELETE"],
        bodyType: "prefix",
      };
    }

    if (routeSegments.length === 2 && routeSegments[1] === "bulk") {
      return {
        cloudflarePath: ADVANCED_TCP_PROTECTION_PATH + "/prefixes/bulk",
        allowedMethods: ["POST"],
        bodyType: "prefixBulk",
      };
    }

    if (routeSegments.length === 2 && routeSegments[1]) {
      return {
        cloudflarePath:
          ADVANCED_TCP_PROTECTION_PATH + "/prefixes/" + encodeURIComponent(routeSegments[1]),
        allowedMethods: ["GET", "PATCH", "DELETE"],
        bodyType: "prefix",
      };
    }
  }

  if (routeSegments[0] === "allowlist") {
    if (routeSegments.length === 1) {
      return {
        cloudflarePath: ADVANCED_TCP_PROTECTION_PATH + "/allowlist",
        allowedMethods: ["GET", "POST", "DELETE"],
        bodyType: "allowlist",
      };
    }

    if (routeSegments.length === 2 && routeSegments[1]) {
      return {
        cloudflarePath:
          ADVANCED_TCP_PROTECTION_PATH + "/allowlist/" + encodeURIComponent(routeSegments[1]),
        allowedMethods: ["GET", "PATCH", "DELETE"],
        bodyType: "allowlist",
      };
    }
  }

  const protectionPathByKey = {
    syn: "syn_protection",
    "tcp-flow": "tcp_flow_protection",
  };
  const protectionPath = protectionPathByKey[routeSegments[0]];
  const collection = routeSegments[1];

  if (protectionPath && (collection === "rules" || collection === "filters")) {
    const bodyType =
      collection === "filters"
        ? "filter"
        : protectionPath === "syn_protection"
          ? "synRule"
          : "tcpRule";
    const collectionPath =
      ADVANCED_TCP_PROTECTION_PATH + "/" + protectionPath + "/" + collection;

    if (routeSegments.length === 2) {
      return {
        cloudflarePath: collectionPath,
        allowedMethods: ["GET", "POST", "DELETE"],
        bodyType,
      };
    }

    if (routeSegments.length === 3 && routeSegments[2]) {
      return {
        cloudflarePath: collectionPath + "/" + encodeURIComponent(routeSegments[2]),
        allowedMethods: ["GET", "PATCH", "DELETE"],
        bodyType,
      };
    }
  }

  return null;
}

function normalizeAdvancedTcpProtectionBody(bodyType, body, partial = false) {
  if (bodyType === "prefixBulk") {
    if (!Array.isArray(body) || !body.length || body.length > 300) {
      throw new HttpError(400, "Bulk prefix requests must contain between 1 and 300 entries.");
    }

    return body.map((entry) => normalizeAdvancedTcpProtectionBody("prefix", entry, false));
  }

  if (!body || typeof body !== "object" || Array.isArray(body)) {
    throw new HttpError(400, "Advanced TCP Protection request body must be a JSON object.");
  }

  const normalized = {};
  const has = (field) => Object.prototype.hasOwnProperty.call(body, field);
  const readString = (field, { maxLength = 8192, optional = false } = {}) => {
    if (!has(field)) {
      if (!partial && !optional) {
        throw new HttpError(400, "Advanced TCP Protection field `" + field + "` is required.");
      }

      return;
    }

    if (typeof body[field] !== "string") {
      throw new HttpError(400, "Advanced TCP Protection field `" + field + "` must be a string.");
    }

    const value = body[field].trim();

    if (!value && !optional) {
      throw new HttpError(400, "Advanced TCP Protection field `" + field + "` cannot be empty.");
    }

    if (value.length > maxLength) {
      throw new HttpError(
        400,
        "Advanced TCP Protection field `" + field + "` exceeds " + maxLength + " characters.",
      );
    }

    normalized[field] = value;
  };
  const readBoolean = (field) => {
    if (!has(field)) {
      if (!partial) {
        throw new HttpError(400, "Advanced TCP Protection field `" + field + "` is required.");
      }

      return;
    }

    if (typeof body[field] !== "boolean") {
      throw new HttpError(400, "Advanced TCP Protection field `" + field + "` must be boolean.");
    }

    normalized[field] = body[field];
  };
  const readEnum = (field, supportedValues) => {
    if (!has(field)) {
      if (!partial) {
        throw new HttpError(400, "Advanced TCP Protection field `" + field + "` is required.");
      }

      return;
    }

    const value = typeof body[field] === "string" ? body[field].trim().toLowerCase() : "";

    if (!supportedValues.includes(value)) {
      throw new HttpError(
        400,
        "Advanced TCP Protection field `" + field + "` must be one of: " +
          supportedValues.join(", ") +
          ".",
      );
    }

    normalized[field] = value;
  };

  if (bodyType === "status") {
    readBoolean("enabled");
  } else if (bodyType === "prefix") {
    readString("prefix");
    readString("comment", { optional: true, maxLength: 500 });
    readBoolean("excluded");
  } else if (bodyType === "allowlist") {
    readString("prefix");
    readString("comment", { optional: true, maxLength: 500 });
    readBoolean("enabled");
  } else if (bodyType === "filter") {
    readString("expression", { maxLength: 8192 });
    readEnum("mode", ["enabled", "disabled", "monitoring"]);
  } else if (bodyType === "synRule" || bodyType === "tcpRule") {
    readEnum("scope", ["global", "region", "datacenter"]);
    readString("name", { maxLength: 100 });
    readEnum("mode", ["enabled", "disabled", "monitoring"]);
    readEnum("rate_sensitivity", ["low", "medium", "high"]);
    readEnum("burst_sensitivity", ["low", "medium", "high"]);

    if (bodyType === "synRule" && has("mitigation_type")) {
      readEnum("mitigation_type", ["challenge", "retransmit"]);
    }

    const scope = normalized.scope ?? body.scope;
    const name = normalized.name ?? body.name;

    if (scope === "global" && String(name ?? "").trim().toLowerCase() !== "global") {
      throw new HttpError(400, "Global Advanced TCP Protection rules must use `global` as the name.");
    }
  } else {
    throw new HttpError(400, "Unsupported Advanced TCP Protection request body.");
  }

  if (partial && !Object.keys(normalized).length) {
    throw new HttpError(400, "Advanced TCP Protection update body cannot be empty.");
  }

  return normalized;
}

function parseAdvancedTcpProtectionStatus(payload) {
  const rawValue =
    payload && typeof payload === "object" && !Array.isArray(payload)
      ? payload.result && typeof payload.result === "object" && !Array.isArray(payload.result)
        ? payload.result.enabled
        : payload.result ?? payload.enabled
      : payload;

  if (typeof rawValue === "boolean") {
    return rawValue;
  }

  if (typeof rawValue === "string") {
    const normalizedValue = rawValue.trim().toLowerCase();

    if (normalizedValue === "true" || normalizedValue === "enabled") {
      return true;
    }

    if (normalizedValue === "false" || normalizedValue === "disabled") {
      return false;
    }
  }

  return null;
}

export default {
  async fetch(request, env) {
    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: corsHeaders() });
    }

    try {
      const url = new URL(request.url);

      if (request.method === "GET" && url.pathname === "/") {
        return new Response(renderUi(), {
          headers: {
            "content-type": "text/html; charset=utf-8",
            "cache-control": "no-store",
          },
        });
      }

      if (request.method === "GET" && url.pathname === "/api/config") {
        const accountId = (env.ACCOUNT_ID ?? "").trim();
        const token = resolveBearerToken(env);
        let accountName = "";
        let accountLookupError = "";

        if (accountId && token) {
          try {
            accountName = await fetchCloudflareAccountName(accountId, token);
          } catch (error) {
            accountLookupError = error instanceof Error ? error.message : String(error);
          }
        }

        return jsonResponse({
          accountId,
          accountName,
          hasBearerToken: Boolean(token),
          bearerSource: token ? "API_BEARER" : "",
          accountLookupError,
        });
      }

      if (request.method === "POST" && url.pathname === "/api/graphql") {
        return await handleGraphqlProxy(request, env);
      }

      if (url.pathname.startsWith("/api/")) {
        return await handleCloudflareApiProxy(request, env, url);
      }

      return jsonResponse({ success: false, error: "Not found" }, 404);
    } catch (error) {
      if (error instanceof HttpError) {
        return jsonResponse({ success: false, error: error.message }, error.status);
      }

      return jsonResponse(
        {
          success: false,
          error: "Unexpected error",
          detail: error instanceof Error ? error.message : String(error),
        },
        500,
      );
    }
  },
};

async function handleCloudflareApiProxy(request, env, url) {
  const token = requireBearerToken(env);
  const method = request.method.toUpperCase();
  const accountId = resolveAccountId(request, env, url);
  const accountIdEncoded = encodeURIComponent(accountId);
  const segments = url.pathname.split("/").filter(Boolean);

  let cloudflarePath = "";
  let allowedMethods = [];
  let requestBodyType = "";

  if (segments[1] === "mnm" && segments[2] === "rules") {
    if (segments.length === 3) {
      allowedMethods = ["GET", "POST", "PUT"];
      cloudflarePath = `/accounts/${accountIdEncoded}/mnm/rules`;
    }

    if (segments.length === 4) {
      const ruleId = encodeURIComponent(segments[3]);
      allowedMethods = ["GET", "PATCH", "DELETE"];
      cloudflarePath = `/accounts/${accountIdEncoded}/mnm/rules/${ruleId}`;
    }
  }

  if (segments[1] === "magic") {
    const resource = segments[2];
    const supportedResources = new Set([
      "gre_tunnels",
      "ipsec_tunnels",
      "routes",
      "cf_interconnects",
    ]);

    if (supportedResources.has(resource)) {
      if (segments.length === 3) {
        allowedMethods = ["GET"];
        cloudflarePath = `/accounts/${accountIdEncoded}/magic/${resource}`;
      }

      if (segments.length === 4) {
        const resourceId = encodeURIComponent(segments[3]);
        allowedMethods = ["GET"];
        cloudflarePath = `/accounts/${accountIdEncoded}/magic/${resource}/${resourceId}`;
      }
    }
  }

  if (segments[1] === "addressing" && segments[2] === "prefixes") {
    if (segments.length === 3) {
      allowedMethods = ["GET"];
      cloudflarePath = `/accounts/${accountIdEncoded}/addressing/prefixes`;
    }

    if (segments.length === 4) {
      const prefixId = encodeURIComponent(segments[3]);
      allowedMethods = ["GET"];
      cloudflarePath = `/accounts/${accountIdEncoded}/addressing/prefixes/${prefixId}`;
    }

    if (segments.length === 6 && segments[4] === "bgp" && segments[5] === "prefixes") {
      const prefixId = encodeURIComponent(segments[3]);
      allowedMethods = ["GET", "POST"];
      cloudflarePath =
        `/accounts/${accountIdEncoded}/addressing/prefixes/${prefixId}/bgp/prefixes`;
    }

    if (segments.length === 7 && segments[4] === "bgp" && segments[5] === "prefixes") {
      const prefixId = encodeURIComponent(segments[3]);
      const bgpPrefixId = encodeURIComponent(segments[6]);
      allowedMethods = ["GET", "PATCH", "DELETE"];
      cloudflarePath =
        `/accounts/${accountIdEncoded}/addressing/prefixes/${prefixId}/bgp/prefixes/${bgpPrefixId}`;
    }
  }

  const advancedTcpProtectionRoute = resolveAdvancedTcpProtectionRoute(segments);

  if (advancedTcpProtectionRoute) {
    cloudflarePath =
      `/accounts/${accountIdEncoded}` + advancedTcpProtectionRoute.cloudflarePath;
    allowedMethods = advancedTcpProtectionRoute.allowedMethods;
    requestBodyType = advancedTcpProtectionRoute.bodyType;
  }

  if (!cloudflarePath) {
    throw new HttpError(404, `Unsupported API path: ${url.pathname}`);
  }

  if (!allowedMethods.includes(method)) {
    return jsonResponse(
      {
        success: false,
        error: `Method ${method} is not allowed for ${url.pathname}.`,
      },
      405,
      { Allow: allowedMethods.join(", ") },
    );
  }

  const requestInit = {
    method,
    headers: {
      Authorization: `Bearer ${token}`,
    },
  };

  if (method === "POST" || method === "PUT" || method === "PATCH") {
    requestInit.headers["content-type"] = "application/json";
    const parsedBody = await readJsonBody(request);
    let normalizedBody = parsedBody;

    if (method === "POST" && segments[1] === "mnm" && segments[2] === "rules" && segments.length === 3) {
      normalizedBody = normalizeMnmCreateRuleBody(parsedBody);
    }

    if (requestBodyType) {
      normalizedBody = normalizeAdvancedTcpProtectionBody(
        requestBodyType,
        parsedBody,
        method === "PATCH",
      );
    }

    requestInit.body = JSON.stringify(normalizedBody);
  }

  const upstreamSearchParams = new URLSearchParams();

  for (const [key, value] of url.searchParams.entries()) {
    if (key.toLowerCase() !== "accountid") {
      upstreamSearchParams.append(key, value);
    }
  }

  const upstreamQuery = upstreamSearchParams.toString();
  const upstreamUrl = `${CLOUDFLARE_API_BASE}${cloudflarePath}${
    upstreamQuery ? `?${upstreamQuery}` : ""
  }`;

  const cloudflareResponse = await fetchWithTimeout(
    upstreamUrl,
    requestInit,
    UPSTREAM_FETCH_TIMEOUT_MS,
  );

  return forwardResponse(cloudflareResponse);
}

async function handleGraphqlProxy(request, env) {
  const token = requireBearerToken(env);
  const payload = await readJsonBody(request);

  if (typeof payload.query !== "string" || !payload.query.trim()) {
    throw new HttpError(
      400,
      "GraphQL body must include a non-empty `query` string.",
    );
  }

  if (
    payload.variables !== undefined &&
    (typeof payload.variables !== "object" ||
      payload.variables === null ||
      Array.isArray(payload.variables))
  ) {
    throw new HttpError(400, "GraphQL `variables` must be a JSON object.");
  }

  const cloudflareResponse = await fetchWithTimeout(
    CLOUDFLARE_GRAPHQL_ENDPOINT,
    {
      method: "POST",
      headers: {
        Authorization: `Bearer ${token}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({
        query: payload.query,
        variables: payload.variables ?? {},
        operationName: payload.operationName,
      }),
    },
    UPSTREAM_FETCH_TIMEOUT_MS,
  );

  return forwardResponse(cloudflareResponse);
}

function resolveAccountId(request, env, url) {
  const headerAccountId = (request.headers.get("x-account-id") ?? "").trim();
  const queryAccountId = (url.searchParams.get("accountId") ?? "").trim();
  const envAccountId = (env.ACCOUNT_ID ?? "").trim();

  const accountId = headerAccountId || queryAccountId || envAccountId;

  if (!accountId) {
    throw new HttpError(
      400,
      "Missing account id. Set ACCOUNT_ID or provide X-Account-ID.",
    );
  }

  return accountId;
}

function requireBearerToken(env) {
  const token = resolveBearerToken(env);

  if (!token) {
    throw new HttpError(500, "Missing bearer token secret. Set `API_BEARER`.");
  }

  return token;
}

function resolveBearerToken(env) {
  return (env.API_BEARER ?? "").trim();
}

async function fetchWithTimeout(url, init = {}, timeoutMs = UPSTREAM_FETCH_TIMEOUT_MS) {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

  try {
    return await fetch(url, {
      ...init,
      signal: controller.signal,
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    const lower = message.toLowerCase();
    const isAbort =
      (error instanceof Error && error.name === "AbortError") || lower.includes("abort");

    if (isAbort) {
      throw new Error("Upstream request timed out.");
    }

    throw error;
  } finally {
    clearTimeout(timeoutId);
  }
}

async function fetchCloudflareAccountName(accountId, token) {
  const upstreamUrl = `${CLOUDFLARE_API_BASE}/accounts/${encodeURIComponent(accountId)}`;
  const response = await fetchWithTimeout(
    upstreamUrl,
    {
      method: "GET",
      headers: {
        Authorization: `Bearer ${token}`,
      },
    },
    ACCOUNT_LOOKUP_TIMEOUT_MS,
  );

  if (!response.ok) {
    throw new Error(`Account lookup failed (${response.status} ${response.statusText}).`);
  }

  const payload = await response.json();

  if (!payload || payload.success === false) {
    throw new Error("Account lookup returned an invalid response.");
  }

  const name = payload.result?.name;
  return typeof name === "string" ? name : "";
}

function normalizeMnmCreateRuleBody(body) {
  if (!body || typeof body !== "object" || Array.isArray(body)) {
    throw new HttpError(400, "Rule create body must be a JSON object.");
  }

  if (!Array.isArray(body.rules)) {
    return body;
  }

  if (body.rules.length !== 1) {
    throw new HttpError(
      400,
      "Create rules currently supports a single rule. Provide exactly one rule in `rules`.",
    );
  }

  const [singleRule] = body.rules;

  if (!singleRule || typeof singleRule !== "object" || Array.isArray(singleRule)) {
    throw new HttpError(400, "The provided rule must be a JSON object.");
  }

  return singleRule;
}

async function readJsonBody(request) {
  const rawBody = await request.text();

  if (!rawBody.trim()) {
    return {};
  }

  try {
    return JSON.parse(rawBody);
  } catch {
    throw new HttpError(400, "Request body must be valid JSON.");
  }
}

async function forwardResponse(cloudflareResponse) {
  const bodyText = await cloudflareResponse.text();
  const contentType =
    cloudflareResponse.headers.get("content-type") ||
    "application/json; charset=utf-8";

  return new Response(bodyText, {
    status: cloudflareResponse.status,
    headers: {
      ...corsHeaders(),
      "content-type": contentType,
    },
  });
}

function jsonResponse(payload, status = 200, additionalHeaders = {}) {
  return new Response(JSON.stringify(payload, null, 2), {
    status,
    headers: {
      ...corsHeaders(),
      "content-type": "application/json; charset=utf-8",
      ...additionalHeaders,
    },
  });
}

function corsHeaders() {
  return {
    "access-control-allow-origin": "*",
    "access-control-allow-methods": "GET,POST,PUT,PATCH,DELETE,OPTIONS",
    "access-control-allow-headers": "content-type,x-account-id",
  };
}

class HttpError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

function renderUi() {
  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>DDOS Overwatch</title>
    <style>
      :root {
        color-scheme: light;
        --bg: #1a110a;
        --panel: #2a1a10;
        --panel-2: #3a2414;
        --line: #7a4a24;
        --text: #ffe8d4;
        --muted: #d4ad8a;
        --good: #22c55e;
        --bad: #fb7185;
        --accent: #f38020;
        --accent-2: #f38020;
      }

      * {
        box-sizing: border-box;
      }

      body {
        margin: 0;
        min-height: 100vh;
        font-family: "IBM Plex Sans", "Segoe UI", sans-serif;
        color: var(--text);
        background: radial-gradient(
            circle at 10% 10%,
            rgba(243, 128, 32, 0.45) 0%,
            var(--bg) 46%
          ),
          radial-gradient(circle at 80% 20%, rgba(243, 128, 32, 0.28) 0%, transparent 42%),
          var(--bg);
      }

      .app {
        width: min(1200px, 100% - 2rem);
        margin: 1rem auto 2rem;
        padding: 1rem;
      }

      .header {
        border: 1px solid var(--line);
        border-radius: 16px;
        padding: 1rem;
        background: linear-gradient(145deg, rgba(42, 26, 16, 0.95), rgba(58, 36, 20, 0.9));
      }

      h1 {
        margin: 0;
        font-size: clamp(1.5rem, 2.5vw, 2.2rem);
        letter-spacing: 0.02em;
      }

      .subtitle {
        margin: 0.4rem 0 0;
        color: var(--muted);
      }

      .config {
        margin-top: 0.75rem;
        display: flex;
        flex-wrap: wrap;
        align-items: center;
        gap: 0.45rem 1rem;
      }

      .config-item {
        display: inline-flex;
        align-items: center;
        gap: 0.35rem;
        min-width: 0;
      }

      .config-item-label {
        color: var(--muted);
        font-size: 0.84rem;
        font-weight: 600;
        letter-spacing: 0.02em;
      }

      .config-item-value {
        font-weight: 700;
        word-break: break-word;
      }

      .label {
        display: block;
        font-size: 0.78rem;
        color: var(--muted);
        margin-bottom: 0.35rem;
        letter-spacing: 0.03em;
        text-transform: uppercase;
      }

      input,
      textarea,
      select,
      button {
        width: 100%;
        font: inherit;
        border-radius: 10px;
      }

      input,
      textarea,
      select {
        border: 1px solid var(--line);
        background: rgba(20, 12, 7, 0.88);
        color: var(--text);
        padding: 0.65rem;
      }

      textarea {
        resize: vertical;
        min-height: 110px;
      }

      button {
        border: 0;
        cursor: pointer;
        padding: 0.62rem 0.75rem;
        background: linear-gradient(135deg, var(--accent), var(--accent-2));
        color: #03131d;
        font-weight: 700;
      }

      button:hover {
        filter: brightness(1.08);
      }

      .tabs {
        display: flex;
        flex-wrap: wrap;
        gap: 0.5rem;
        margin-top: 1rem;
      }

      .tab-button {
        width: auto;
        border: 1px solid var(--line);
        background: rgba(26, 17, 10, 0.8);
        color: var(--text);
        padding: 0.55rem 0.9rem;
      }

      .tab-button.active {
        border-color: var(--accent);
        background: rgba(243, 128, 32, 0.22);
      }

      .tab-panel {
        display: none;
        margin-top: 1rem;
      }

      .tab-panel.active {
        display: block;
      }

      .card-grid {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
        gap: 0.8rem;
      }

      .card {
        border: 1px solid var(--line);
        border-radius: 12px;
        background: rgba(26, 17, 10, 0.84);
        padding: 0.75rem;
      }

      h2,
      h3 {
        margin-top: 0;
      }

      h2 {
        margin-bottom: 0.8rem;
        color: #f9c194;
        font-size: 1.1rem;
      }

      h3 {
        font-size: 0.95rem;
        margin-bottom: 0.6rem;
      }

      .inline {
        display: grid;
        grid-template-columns: 1fr auto;
        gap: 0.5rem;
        align-items: end;
      }

      .inline button {
        width: auto;
        min-width: 92px;
      }

      .output {
        margin-top: 1rem;
        border: 1px solid var(--line);
        border-radius: 12px;
        background: rgba(26, 17, 10, 0.84);
        overflow: hidden;
      }

      .output-head {
        display: flex;
        flex-wrap: wrap;
        justify-content: space-between;
        gap: 0.5rem;
        border-bottom: 1px solid var(--line);
        padding: 0.6rem 0.75rem;
      }

      .output summary {
        cursor: pointer;
      }

      .output-meta {
        display: inline-flex;
        flex-wrap: wrap;
        gap: 0.8rem;
        align-items: center;
      }

      .status.ok {
        color: var(--good);
      }

      .status.err {
        color: var(--bad);
      }

      pre {
        margin: 0;
        padding: 0.8rem;
        max-height: 420px;
        overflow: auto;
        font-family: "IBM Plex Mono", "SFMono-Regular", monospace;
        font-size: 0.83rem;
        line-height: 1.45;
      }

      .hint {
        margin-top: 0.4rem;
        color: var(--muted);
        font-size: 0.82rem;
      }

      .hint.err {
        color: var(--bad);
      }

      .table-wrap {
        width: 100%;
        overflow-x: auto;
        border: 1px solid var(--line);
        border-radius: 10px;
      }

      .data-table {
        width: 100%;
        min-width: 920px;
        border-collapse: collapse;
        font-size: 0.82rem;
      }

      .data-table th,
      .data-table td {
        padding: 0.5rem 0.55rem;
        text-align: left;
        vertical-align: top;
        border-bottom: 1px solid rgba(122, 74, 36, 0.45);
      }

      .data-table th {
        color: #ffd7b3;
        background: rgba(243, 128, 32, 0.18);
      }

      .collection-output {
        margin: 0;
        padding: 0.8rem;
        max-height: 320px;
        overflow: auto;
        border: 1px solid var(--line);
        border-radius: 10px;
        background: rgba(20, 12, 7, 0.72);
        font-family: "IBM Plex Mono", "SFMono-Regular", monospace;
        font-size: 0.8rem;
      }

      .editable-cell {
        display: flex;
        align-items: flex-start;
        gap: 0.35rem;
      }

      .editable-cell-value {
        flex: 1;
        min-width: 110px;
        white-space: pre-wrap;
        word-break: break-word;
      }

      .icon-button,
      .mini-button {
        width: auto;
        min-width: 0;
        border: 1px solid var(--line);
        border-radius: 8px;
        background: rgba(26, 17, 10, 0.82);
        color: var(--text);
        font-weight: 600;
      }

      .icon-button {
        padding: 0.15rem 0.45rem;
        line-height: 1.1;
      }

      .mini-button {
        padding: 0.22rem 0.48rem;
      }

      .icon-button:disabled,
      .mini-button:disabled {
        opacity: 0.5;
        cursor: not-allowed;
      }

      .disabled-icon-hint {
        display: inline-flex;
        cursor: not-allowed;
      }

      .disabled-icon-hint .icon-button {
        pointer-events: none;
      }

      .inline-editor {
        display: flex;
        align-items: center;
        gap: 0.35rem;
        flex-wrap: wrap;
      }

      .inline-editor input,
      .inline-editor select,
      .inline-editor textarea {
        width: auto;
        min-width: 150px;
      }

      .inline-editor textarea {
        min-height: 64px;
      }

      .rule-input {
        width: auto;
        min-width: 135px;
        padding: 0.36rem 0.44rem;
        border-radius: 8px;
      }

      .rule-input[type="number"] {
        min-width: 120px;
      }

      textarea.rule-input {
        min-height: 52px;
        resize: vertical;
      }

      .rule-input:disabled {
        opacity: 0.6;
      }

      .table-action-cell {
        min-width: 130px;
      }

      .hidden {
        display: none !important;
      }

      .filters-grid {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
        gap: 0.65rem;
      }

      .filter-block {
        display: flex;
        flex-direction: column;
        gap: 0.35rem;
      }

      .filter-block .label {
        margin-bottom: 0;
      }

      .filter-inline {
        display: grid;
        grid-template-columns: 1fr 1fr;
        gap: 0.55rem;
      }

      .api-filter-actions {
        grid-template-columns: minmax(90px, 1fr) minmax(120px, 1fr) auto;
        align-items: end;
      }

      .overview-health-actions {
        grid-template-columns: minmax(90px, 1fr) minmax(120px, 1fr) auto;
        align-items: end;
      }

      .ddos-search-actions {
        grid-template-columns: minmax(90px, 1fr) minmax(120px, 1fr) auto;
        align-items: end;
      }

      .schema-explorer-actions {
        grid-template-columns: minmax(180px, 1fr) minmax(180px, 1fr) auto auto;
        align-items: end;
      }

      .schema-explorer-editor {
        display: grid;
        gap: 0.75rem;
        margin-top: 0.75rem;
      }

      .schema-explorer-editor textarea {
        min-height: 140px;
      }

      .api-tunnel-selector {
        margin-top: 0.45rem;
        border: 1px solid var(--line);
        border-radius: 10px;
        background: rgba(20, 12, 7, 0.62);
        padding: 0.55rem;
      }

      .api-tunnel-selector-list {
        margin-top: 0.45rem;
        display: flex;
        flex-wrap: wrap;
        gap: 0.35rem 0.7rem;
        max-height: 180px;
        overflow: auto;
      }

      .api-tunnel-option {
        display: inline-flex;
        align-items: center;
        gap: 0.35rem;
        font-size: 0.78rem;
        color: var(--text);
      }

      .api-tunnel-option.disabled {
        opacity: 0.5;
      }

      .api-tunnel-option input {
        width: auto;
        margin: 0;
      }

      .api-tunnel-swatch {
        width: 10px;
        height: 10px;
        border-radius: 999px;
        border: 1px solid rgba(255, 255, 255, 0.24);
        background: rgba(122, 74, 36, 0.5);
      }

      .api-line-chart {
        margin-top: 0.6rem;
        border: 1px solid var(--line);
        border-radius: 10px;
        background: rgba(20, 12, 7, 0.62);
        padding: 0.4rem;
      }

      .api-line-chart svg {
        display: block;
        width: 100%;
        height: 350px;
      }

      .api-line-chart-legend {
        margin-top: 0.45rem;
        display: flex;
        flex-wrap: wrap;
        gap: 0.35rem 0.7rem;
      }

      .api-line-chart-legend-item {
        display: inline-flex;
        align-items: center;
        gap: 0.35rem;
        font-size: 0.76rem;
        color: var(--muted);
      }

      .dashboard-note {
        margin-top: 0.5rem;
        color: var(--muted);
        font-size: 0.82rem;
      }

      .metric-grid {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(190px, 1fr));
        gap: 0.55rem;
      }

      .metric-card {
        border: 1px solid var(--line);
        border-radius: 10px;
        background: rgba(20, 12, 7, 0.7);
        padding: 0.55rem 0.65rem;
      }

      .metric-label {
        color: var(--muted);
        font-size: 0.74rem;
        letter-spacing: 0.03em;
        text-transform: uppercase;
      }

      .metric-value {
        margin-top: 0.15rem;
        font-size: 1.12rem;
        font-weight: 700;
        word-break: break-word;
      }

      .chart-list {
        margin-top: 0.45rem;
        display: flex;
        flex-direction: column;
        gap: 0.45rem;
      }

      .chart-row {
        display: grid;
        grid-template-columns: minmax(110px, 1.8fr) 4fr auto;
        align-items: center;
        gap: 0.45rem;
      }

      .chart-label {
        color: var(--muted);
        font-size: 0.78rem;
        white-space: normal;
        word-break: break-word;
      }

      .chart-track {
        height: 11px;
        border-radius: 999px;
        background: rgba(122, 74, 36, 0.35);
        overflow: hidden;
      }

      .chart-fill {
        height: 100%;
        min-width: 2px;
        background: linear-gradient(90deg, var(--accent), #ffb36e);
      }

      .chart-value {
        color: #ffd7b3;
        font-size: 0.78rem;
        font-family: "IBM Plex Mono", "SFMono-Regular", monospace;
      }

      .analytics-results-note {
        margin-top: 0.5rem;
        color: var(--muted);
        font-size: 0.78rem;
      }

      .timeline-chart .chart-row {
        grid-template-columns: minmax(170px, 2.3fr) 6fr auto;
      }

      .timeline-chart .chart-track {
        height: 14px;
      }

      .recent-alerts-grid {
        margin-top: 0.75rem;
        display: flex;
        flex-direction: column;
        gap: 0.7rem;
      }

      .recent-alerts-grid .card {
        background: rgba(26, 17, 10, 0.72);
      }

      .recent-alerts-grid .table-wrap {
        overflow-x: hidden;
      }

      .recent-alerts-grid .data-table {
        min-width: 0;
        table-layout: fixed;
      }

      .recent-alerts-grid .data-table th,
      .recent-alerts-grid .data-table td {
        white-space: normal;
        word-break: break-word;
      }

      .bgp-prefix-groups {
        display: flex;
        flex-direction: column;
        gap: 0.6rem;
      }

      .bgp-prefix-group {
        border: 1px solid var(--line);
        border-radius: 10px;
        background: rgba(20, 12, 7, 0.62);
        padding: 0.55rem 0.65rem;
      }

      .bgp-prefix-parent {
        display: flex;
        align-items: center;
        justify-content: space-between;
        flex-wrap: wrap;
        gap: 0.45rem;
      }

      .bgp-prefix-parent-cidr,
      .bgp-prefix-cidr {
        font-family: "IBM Plex Mono", "SFMono-Regular", monospace;
      }

      .bgp-prefix-list {
        list-style: none;
        margin: 0.5rem 0 0;
        padding: 0;
        display: flex;
        flex-direction: column;
        gap: 0.35rem;
      }

      .bgp-prefix-item {
        display: flex;
        align-items: center;
        justify-content: space-between;
        flex-wrap: wrap;
        gap: 0.45rem;
      }

      .bgp-status {
        display: inline-flex;
        align-items: center;
        border-radius: 999px;
        padding: 0.14rem 0.5rem;
        border: 1px solid transparent;
        font-size: 0.72rem;
        font-weight: 700;
        letter-spacing: 0.02em;
        text-transform: uppercase;
      }

      .bgp-status.advertised {
        color: var(--good);
        border-color: rgba(34, 197, 94, 0.5);
        background: rgba(34, 197, 94, 0.12);
      }

      .bgp-status.withdrawn {
        color: var(--bad);
        border-color: rgba(251, 113, 133, 0.5);
        background: rgba(251, 113, 133, 0.12);
      }

      .bgp-create-row {
        margin-top: 0.65rem;
        border: 1px solid var(--line);
        border-radius: 10px;
        background: rgba(20, 12, 7, 0.6);
        padding: 0.65rem;
      }

      .bgp-create-grid {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
        gap: 0.6rem;
      }

      .bgp-create-actions {
        grid-column: 1 / -1;
        display: flex;
        gap: 0.45rem;
        justify-content: flex-end;
      }

      .bgp-create-actions .mini-button {
        width: auto;
      }

      @media (max-width: 700px) {
        .inline {
          grid-template-columns: 1fr;
        }

        .inline button {
          width: 100%;
        }

        .filter-inline {
          grid-template-columns: 1fr;
        }
      }

      :root {
        color-scheme: dark;
        --bg: #070707;
        --panel: #111111;
        --panel-2: #171717;
        --line: #2c2c2c;
        --line-strong: #4a301d;
        --text: #f7f7f7;
        --muted: #9b9b9b;
        --good: #54d98c;
        --bad: #ff6b78;
        --accent: #f6821f;
        --accent-2: #ff9f43;
        --accent-soft: rgba(246, 130, 31, 0.12);
        --shadow: 0 18px 50px rgba(0, 0, 0, 0.34);
      }

      body {
        font-family: Inter, ui-sans-serif, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
        line-height: 1.5;
        background-color: var(--bg);
        background-image:
          radial-gradient(circle at 12% -8%, rgba(246, 130, 31, 0.2), transparent 34rem),
          radial-gradient(circle at 92% 12%, rgba(246, 130, 31, 0.08), transparent 28rem),
          linear-gradient(rgba(255, 255, 255, 0.018) 1px, transparent 1px),
          linear-gradient(90deg, rgba(255, 255, 255, 0.018) 1px, transparent 1px);
        background-size: auto, auto, 32px 32px, 32px 32px;
        background-attachment: fixed;
      }

      body::before {
        content: "";
        position: fixed;
        inset: 0 0 auto;
        height: 3px;
        z-index: 20;
        background: linear-gradient(90deg, transparent, var(--accent) 25%, var(--accent-2) 75%, transparent);
      }

      .app {
        width: min(1440px, 100% - 3rem);
        margin: 0 auto 3rem;
        padding: 1.75rem 0;
      }

      .header {
        position: relative;
        overflow: hidden;
        border: 1px solid var(--line);
        border-radius: 22px;
        padding: 1.35rem 1.4rem 0;
        background: linear-gradient(145deg, rgba(20, 20, 20, 0.97), rgba(10, 10, 10, 0.98));
        box-shadow: var(--shadow);
      }

      .header::after {
        content: "";
        position: absolute;
        width: 320px;
        height: 320px;
        top: -220px;
        right: -80px;
        border: 1px solid rgba(246, 130, 31, 0.24);
        border-radius: 50%;
        box-shadow: 0 0 80px rgba(246, 130, 31, 0.08);
        pointer-events: none;
      }

      .hero-row {
        position: relative;
        z-index: 1;
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: 1.5rem;
      }

      .brand-lockup {
        display: flex;
        align-items: center;
        gap: 0.95rem;
        min-width: 0;
      }

      .brand-mark {
        display: grid;
        place-items: center;
        flex: 0 0 auto;
        width: 48px;
        height: 48px;
        border: 1px solid rgba(246, 130, 31, 0.55);
        border-radius: 14px;
        color: #090909;
        background: linear-gradient(145deg, var(--accent-2), var(--accent));
        box-shadow: 0 10px 28px rgba(246, 130, 31, 0.2);
        font-size: 0.8rem;
        font-weight: 900;
        letter-spacing: -0.05em;
      }

      .eyebrow {
        margin: 0 0 0.12rem;
        color: var(--accent-2);
        font-size: 0.69rem;
        font-weight: 800;
        letter-spacing: 0.16em;
        text-transform: uppercase;
      }

      h1 {
        font-size: clamp(1.55rem, 2.5vw, 2.3rem);
        line-height: 1.1;
        letter-spacing: -0.035em;
      }

      .subtitle {
        max-width: 680px;
        margin-top: 0.42rem;
        color: var(--muted);
        font-size: 0.9rem;
      }

      .config {
        justify-content: flex-end;
        margin: 0;
        gap: 0.5rem;
      }

      .config-item {
        display: flex;
        flex-direction: column;
        align-items: flex-start;
        gap: 0.06rem;
        min-width: 150px;
        border: 1px solid var(--line);
        border-radius: 12px;
        padding: 0.55rem 0.72rem;
        background: rgba(255, 255, 255, 0.025);
      }

      .config-item::before {
        content: "";
        position: absolute;
      }

      .config-item-label {
        color: #777;
        font-size: 0.64rem;
        font-weight: 750;
        letter-spacing: 0.1em;
        text-transform: uppercase;
      }

      .config-item-value {
        max-width: 270px;
        overflow: hidden;
        color: #e9e9e9;
        font-size: 0.78rem;
        font-weight: 650;
        text-overflow: ellipsis;
        white-space: nowrap;
      }

      .tabs {
        position: relative;
        z-index: 1;
        flex-wrap: nowrap;
        gap: 0;
        margin: 1.3rem -1.4rem 0;
        padding: 0 1.4rem;
        overflow-x: auto;
        border-top: 1px solid var(--line);
        scrollbar-width: thin;
      }

      .tab-button {
        position: relative;
        flex: 0 0 auto;
        border: 0;
        border-radius: 0;
        padding: 0.88rem 0.95rem 0.82rem;
        color: #8f8f8f;
        background: transparent;
        font-size: 0.79rem;
        font-weight: 700;
        letter-spacing: 0.01em;
      }

      .tab-button::after {
        content: "";
        position: absolute;
        right: 0.85rem;
        bottom: 0;
        left: 0.85rem;
        height: 2px;
        border-radius: 99px 99px 0 0;
        background: transparent;
      }

      .tab-button:hover {
        color: #fff;
        filter: none;
        background: rgba(255, 255, 255, 0.025);
      }

      .tab-button.active {
        color: #fff;
        border: 0;
        background: var(--accent-soft);
      }

      .tab-button.active::after {
        background: var(--accent);
        box-shadow: 0 0 16px rgba(246, 130, 31, 0.6);
      }

      .tab-panel {
        margin-top: 1.65rem;
      }

      .tab-panel > h2 {
        margin: 0 0 1rem;
        color: #fff;
        font-size: 1.15rem;
        letter-spacing: -0.02em;
      }

      .card-grid {
        gap: 1rem;
      }

      .card,
      .output {
        border-color: var(--line);
        border-radius: 16px;
        background: linear-gradient(145deg, rgba(19, 19, 19, 0.96), rgba(13, 13, 13, 0.97));
        box-shadow: 0 10px 36px rgba(0, 0, 0, 0.16);
      }

      .card {
        padding: 1rem;
      }

      .card:hover {
        border-color: #383838;
      }

      .card h3 {
        margin-bottom: 0.8rem;
        color: #efefef;
        font-size: 0.91rem;
        font-weight: 750;
        letter-spacing: -0.01em;
      }

      .label {
        color: #888;
        font-size: 0.67rem;
        font-weight: 750;
        letter-spacing: 0.09em;
      }

      input,
      textarea,
      select {
        border-color: #333;
        border-radius: 10px;
        background: #0a0a0a;
        color: #eee;
        outline: none;
        transition: border-color 140ms ease, box-shadow 140ms ease;
      }

      input:focus,
      textarea:focus,
      select:focus {
        border-color: var(--accent);
        box-shadow: 0 0 0 3px rgba(246, 130, 31, 0.12);
      }

      button {
        border: 1px solid #ff9b45;
        border-radius: 10px;
        color: #111;
        background: linear-gradient(135deg, #ff9a3d, #f6821f);
        box-shadow: 0 8px 20px rgba(246, 130, 31, 0.13);
        transition: transform 140ms ease, filter 140ms ease, box-shadow 140ms ease;
      }

      button:hover {
        transform: translateY(-1px);
        filter: brightness(1.07);
        box-shadow: 0 10px 24px rgba(246, 130, 31, 0.2);
      }

      button:active {
        transform: translateY(0);
      }

      .icon-button,
      .mini-button {
        border-color: #3b3b3b;
        color: #ddd;
        background: #171717;
        box-shadow: none;
      }

      .icon-button:hover,
      .mini-button:hover {
        border-color: var(--accent);
        color: #fff;
        background: #20160e;
      }

      .hint,
      .dashboard-note,
      .analytics-results-note {
        color: var(--muted);
      }

      .hint.err {
        color: var(--bad);
      }

      .table-wrap,
      .collection-output,
      .api-tunnel-selector,
      .api-line-chart,
      .bgp-prefix-group,
      .bgp-create-row {
        border-color: var(--line);
        border-radius: 12px;
        background: rgba(5, 5, 5, 0.58);
      }

      .data-table th,
      .data-table td {
        padding: 0.66rem 0.72rem;
        border-color: #292929;
      }

      .data-table th {
        position: sticky;
        top: 0;
        z-index: 1;
        color: #a6a6a6;
        background: #17130f;
        font-size: 0.68rem;
        letter-spacing: 0.06em;
        text-transform: uppercase;
      }

      .data-table tbody tr {
        transition: background 120ms ease;
      }

      .data-table tbody tr:hover {
        background: rgba(246, 130, 31, 0.055);
      }

      .metric-grid {
        gap: 0.75rem;
      }

      .metric-card {
        position: relative;
        overflow: hidden;
        min-height: 96px;
        border-color: var(--line);
        border-radius: 14px;
        padding: 0.8rem;
        background: linear-gradient(145deg, #171717, #0d0d0d);
      }

      .metric-card::after {
        content: "";
        position: absolute;
        right: -22px;
        bottom: -30px;
        width: 76px;
        height: 76px;
        border: 1px solid rgba(246, 130, 31, 0.16);
        border-radius: 50%;
      }

      .metric-label {
        color: #828282;
        font-size: 0.66rem;
        font-weight: 750;
        letter-spacing: 0.08em;
      }

      .metric-value {
        position: relative;
        z-index: 1;
        margin-top: 0.35rem;
        color: #fff;
        font-size: clamp(1.15rem, 2vw, 1.55rem);
        letter-spacing: -0.035em;
      }

      .chart-track {
        background: #27211c;
      }

      .chart-fill {
        background: linear-gradient(90deg, #d85d00, var(--accent-2));
        box-shadow: 0 0 12px rgba(246, 130, 31, 0.2);
      }

      .chart-value {
        color: #ffc28d;
      }

      .usage-hero {
        display: grid;
        grid-template-columns: minmax(0, 1.5fr) minmax(260px, 0.5fr);
        gap: 1rem;
        align-items: stretch;
        margin-bottom: 1rem;
      }

      .usage-intro {
        display: flex;
        flex-direction: column;
        justify-content: center;
        min-height: 160px;
        border: 1px solid var(--line-strong);
        border-radius: 18px;
        padding: 1.2rem 1.3rem;
        background:
          radial-gradient(circle at 100% 0%, rgba(246, 130, 31, 0.2), transparent 50%),
          linear-gradient(135deg, #1a120c, #101010 72%);
      }

      .usage-intro h2 {
        margin: 0.18rem 0 0.45rem;
        color: #fff;
        font-size: clamp(1.35rem, 2.4vw, 2rem);
        letter-spacing: -0.04em;
      }

      .usage-intro p:last-child {
        max-width: 680px;
        margin: 0;
        color: #aaa;
      }

      .usage-controls {
        display: flex;
        flex-direction: column;
        justify-content: center;
        border: 1px solid var(--line);
        border-radius: 18px;
        padding: 1rem;
        background: #111;
      }

      .usage-controls button {
        margin-top: 0.65rem;
      }

      .usage-metric-card.primary {
        border-color: rgba(246, 130, 31, 0.48);
        background: linear-gradient(145deg, rgba(246, 130, 31, 0.16), #111 60%);
      }

      .usage-card-subtitle {
        margin: -0.45rem 0 0.8rem;
        color: var(--muted);
        font-size: 0.78rem;
      }

      .usage-bars {
        display: flex;
        flex-direction: column;
        gap: 0.65rem;
      }

      .usage-bar-row {
        display: grid;
        grid-template-columns: minmax(130px, 1.4fr) minmax(180px, 4fr) minmax(90px, auto);
        gap: 0.75rem;
        align-items: center;
      }

      .usage-bar-label {
        overflow: hidden;
        color: #d8d8d8;
        font-size: 0.8rem;
        text-overflow: ellipsis;
        white-space: nowrap;
      }

      .usage-bar-track {
        display: grid;
        gap: 0.22rem;
      }

      .usage-bar-segment {
        height: 7px;
        min-width: 2px;
        border-radius: 99px;
      }

      .usage-bar-segment.ingress {
        background: linear-gradient(90deg, #d85d00, var(--accent));
      }

      .usage-bar-segment.egress {
        background: linear-gradient(90deg, #704426, #ffb16c);
      }

      .usage-bar-value {
        color: #aaa;
        font-family: "SFMono-Regular", Consolas, monospace;
        font-size: 0.72rem;
        text-align: right;
        white-space: nowrap;
      }

      .usage-legend {
        display: flex;
        flex-wrap: wrap;
        gap: 0.85rem;
        margin-bottom: 0.8rem;
        color: var(--muted);
        font-size: 0.72rem;
      }

      .usage-legend span {
        display: inline-flex;
        align-items: center;
        gap: 0.35rem;
      }

      .usage-legend i {
        width: 18px;
        height: 5px;
        border-radius: 99px;
      }

      .flowtrackd-hero {
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: 1rem;
        margin-bottom: 1rem;
        border: 1px solid var(--line-strong);
        border-radius: 18px;
        padding: 1.1rem 1.2rem;
        background:
          radial-gradient(circle at 100% 0%, rgba(246, 130, 31, 0.16), transparent 45%),
          linear-gradient(135deg, #17110c, #101010 68%);
      }

      .flowtrackd-hero h2 {
        margin: 0.15rem 0 0.3rem;
        color: #fff;
        font-size: clamp(1.3rem, 2.3vw, 1.9rem);
        letter-spacing: -0.035em;
      }

      .flowtrackd-hero p:last-child {
        max-width: 760px;
        margin: 0;
        color: var(--muted);
      }

      .flowtrackd-status-panel {
        display: flex;
        align-items: center;
        gap: 0.55rem;
        flex: 0 0 auto;
      }

      .flowtrackd-status-panel select,
      .flowtrackd-status-panel button {
        width: auto;
        min-width: 120px;
      }

      .flowtrackd-status-pill {
        display: inline-flex;
        align-items: center;
        gap: 0.38rem;
        border: 1px solid var(--line);
        border-radius: 999px;
        padding: 0.36rem 0.62rem;
        color: #bbb;
        background: #0b0b0b;
        font-size: 0.72rem;
        font-weight: 750;
        white-space: nowrap;
      }

      .flowtrackd-status-pill::before {
        content: "";
        width: 7px;
        height: 7px;
        border-radius: 50%;
        background: #777;
      }

      .flowtrackd-status-pill.enabled::before {
        background: var(--good);
        box-shadow: 0 0 9px rgba(84, 217, 140, 0.6);
      }

      .flowtrackd-status-pill.disabled::before {
        background: var(--bad);
      }

      .flowtrackd-section-head {
        display: flex;
        align-items: flex-start;
        justify-content: space-between;
        gap: 1rem;
        margin-bottom: 0.8rem;
      }

      .flowtrackd-section-head h3 {
        margin-bottom: 0.16rem;
      }

      .flowtrackd-section-head p {
        margin: 0;
        color: var(--muted);
        font-size: 0.76rem;
      }

      .flowtrackd-delete-all {
        width: auto;
        border-color: rgba(255, 107, 120, 0.38);
        color: #ff9ca6;
        background: rgba(255, 107, 120, 0.06);
      }

      .flowtrackd-create-form {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
        gap: 0.55rem;
        align-items: end;
        margin-bottom: 0.8rem;
        border: 1px solid var(--line);
        border-radius: 12px;
        padding: 0.72rem;
        background: rgba(0, 0, 0, 0.23);
      }

      .flowtrackd-create-form .wide {
        grid-column: span 2;
      }

      .flowtrackd-create-form button {
        min-height: 40px;
      }

      .flowtrackd-table .data-table {
        min-width: 1080px;
      }

      .flowtrackd-table input,
      .flowtrackd-table select,
      .flowtrackd-table textarea {
        min-width: 112px;
        padding: 0.42rem 0.48rem;
        font-size: 0.77rem;
      }

      .flowtrackd-table textarea {
        min-width: 280px;
        min-height: 58px;
      }

      .flowtrackd-table input[type="checkbox"] {
        min-width: 0;
        width: auto;
      }

      .flowtrackd-actions {
        display: flex;
        gap: 0.36rem;
      }

      .flowtrackd-actions button {
        width: auto;
        white-space: nowrap;
      }

      .flowtrackd-danger {
        border-color: rgba(255, 107, 120, 0.4);
        color: #ff9ca6;
        background: rgba(255, 107, 120, 0.08);
      }

      .flowtrackd-bulk {
        margin: 0.75rem 0;
        border: 1px solid var(--line);
        border-radius: 12px;
        padding: 0.7rem;
        background: rgba(255, 255, 255, 0.015);
      }

      .flowtrackd-bulk summary {
        cursor: pointer;
        color: #d6d6d6;
        font-size: 0.8rem;
        font-weight: 700;
      }

      .output {
        margin-top: 1.25rem;
      }

      .output-head {
        padding: 0.78rem 0.9rem;
        border-color: var(--line);
      }

      @media (max-width: 900px) {
        .hero-row {
          align-items: flex-start;
          flex-direction: column;
        }

        .config {
          width: 100%;
          justify-content: flex-start;
        }

        .config-item {
          flex: 1 1 220px;
        }

        .usage-hero {
          grid-template-columns: 1fr;
        }

        .flowtrackd-hero {
          align-items: flex-start;
          flex-direction: column;
        }

        .flowtrackd-status-panel {
          width: 100%;
          flex-wrap: wrap;
        }
      }

      @media (max-width: 700px) {
        .app {
          width: min(100% - 1.25rem, 1440px);
          padding-top: 0.85rem;
        }

        .header {
          border-radius: 16px;
          padding: 1rem 1rem 0;
        }

        .brand-mark {
          width: 42px;
          height: 42px;
        }

        .tabs {
          margin-right: -1rem;
          margin-left: -1rem;
          padding: 0 1rem;
        }

        .tab-button {
          padding-right: 0.75rem;
          padding-left: 0.75rem;
        }

        .card {
          padding: 0.82rem;
        }

        .usage-bar-row {
          grid-template-columns: 1fr auto;
        }

        .usage-bar-track {
          grid-column: 1 / -1;
          grid-row: 2;
        }
      }
    </style>
  </head>
  <body>
    <main class="app">
      <section class="header">
        <div class="hero-row">
          <div class="brand-lockup">
            <div class="brand-mark" aria-hidden="true">D/O</div>
            <div>
              <p class="eyebrow">Network defense console</p>
              <h1>DDOS Overwatch</h1>
              <p class="subtitle">
                Visibility and control for Cloudflare Network Flow and Magic Transit.
              </p>
            </div>
          </div>

          <div class="config">
            <div class="config-item">
              <span class="config-item-label">Account</span>
              <span id="envAccountName" class="config-item-value">Loading...</span>
            </div>
            <div class="config-item">
              <span class="config-item-label">Account ID</span>
              <span id="envAccountId" class="config-item-value">Loading...</span>
            </div>
          </div>
        </div>

        <nav class="tabs" aria-label="Primary navigation">
          <button class="tab-button active" data-tab="overview">Overview</button>
          <button class="tab-button" data-tab="analytics-api">Analytics (API)</button>
          <button class="tab-button" data-tab="network">Magic Transit</button>
          <button class="tab-button" data-tab="rules">Network Flow</button>
          <button class="tab-button" data-tab="flowtrackd">FlowtrackD</button>
          <button class="tab-button" data-tab="usage">Usage</button>
        </nav>
      </section>

      <section class="tab-panel active" id="tab-overview">
        <h2>Overview</h2>

        <div class="card-grid">
          <article class="card" style="grid-column: 1 / -1">
            <h3>BGP Prefix Advertisement Status</h3>
            <div id="overviewBgpPrefixes"><p class="hint">No data loaded.</p></div>
            <p id="bgpOverviewStatus" class="hint">No data loaded.</p>
          </article>
        </div>

        <div class="recent-alerts-grid">
          <article class="card">
            <h3>Recent DDoS Events from Cloudflare GraphQL (Last 24h)</h3>
            <div id="recentDdosEventsTable">
              <p class="hint">Loading recent DDoS attack events...</p>
            </div>
            <p id="recentDdosStatus" class="hint">Loading recent DDoS attack events...</p>
          </article>

          <article class="card">
            <h3>Tunnel Health Checks</h3>
            <div class="filters-grid">
              <div class="filter-block">
                <label class="label" for="overviewTunnelHealthRelativeValue">Relative Range</label>
                <div class="filter-inline overview-health-actions">
                  <input id="overviewTunnelHealthRelativeValue" type="number" min="1" value="60" />
                  <select id="overviewTunnelHealthRelativeUnit">
                    <option value="minutes">Minutes</option>
                    <option value="hours">Hours</option>
                    <option value="days">Days</option>
                  </select>
                  <button id="btnRunOverviewTunnelHealth" class="mini-button" type="button">Query</button>
                </div>
              </div>
            </div>
            <p id="overviewTunnelHealthStatus" class="hint">No health check query run yet.</p>
            <div id="overviewTunnelHealthChart" class="timeline-chart">
              <p class="hint">Run a query to view tunnel health status over time.</p>
            </div>
            <div id="overviewTunnelHealthTable" style="margin-top: 0.75rem">
              <p class="hint">Run a query to view tunnel health summary rows.</p>
            </div>
          </article>
        </div>
      </section>

      <section class="tab-panel" id="tab-analytics-api">
        <h2>Analytics (API)</h2>
        <div class="card-grid">
          <article class="card" style="grid-column: 1 / -1">
            <h3>Tunnel Bandwidth Inputs</h3>
            <div class="filters-grid">
              <div class="filter-block">
                <label class="label" for="apiDirectionInput">Direction</label>
                <select id="apiDirectionInput">
                  <option value="ingress">Ingress</option>
                  <option value="egress">Egress</option>
                </select>
              </div>

              <div class="filter-block">
                <label class="label" for="apiRelativeValue">Relative Range</label>
                <div class="filter-inline api-filter-actions">
                  <input id="apiRelativeValue" type="number" min="1" value="60" />
                  <select id="apiRelativeUnit">
                    <option value="minutes">Minutes</option>
                    <option value="hours">Hours</option>
                    <option value="days">Days</option>
                  </select>
                  <button id="btnRunApiAnalytics" class="mini-button" type="button">Query</button>
                </div>
              </div>
            </div>
            <p id="apiAnalyticsStatus" class="hint">No API query run yet.</p>
          </article>

          <article class="card" style="grid-column: 1 / -1">
            <h3>Tunnel Bandwidth Results</h3>
            <div id="apiTunnelSeriesSelector" class="api-tunnel-selector">
              <p class="hint">Run a query to select tunnel lines (up to 10).</p>
            </div>
            <div id="apiTunnelBandwidthChart" class="timeline-chart">
              <p class="hint">Run a query to view tunnel bandwidth chart.</p>
            </div>
            <div id="apiTunnelBandwidthTable" style="margin-top: 0.75rem">
              <p class="hint">Run a query to view tunnel bandwidth rows.</p>
            </div>
          </article>

          <article class="card" style="grid-column: 1 / -1">
            <h3>DDoS GraphQL Inputs</h3>
            <div class="filters-grid">
              <div class="filter-block">
                <label class="label" for="ddosGraphDataset">Dataset</label>
                <select id="ddosGraphDataset">
                  <option value="attack">Attack Events</option>
                  <option value="network">Packet Samples</option>
                </select>
              </div>

              <div class="filter-block">
                <label class="label" for="ddosGraphSearchField">Search By</label>
                <select id="ddosGraphSearchField"></select>
              </div>

              <div class="filter-block" style="grid-column: 1 / -1">
                <label class="label" for="ddosGraphSearchValue">Attack ID / IP Search</label>
                <input
                  id="ddosGraphSearchValue"
                  type="text"
                  placeholder="Attack ID or IP address. Use commas for multiple exact matches."
                />
              </div>

              <div class="filter-block">
                <label class="label" for="ddosGraphTimeMode">Time Range Mode</label>
                <select id="ddosGraphTimeMode">
                  <option value="relative">Relative</option>
                  <option value="absolute">Start / End</option>
                </select>
              </div>

              <div
                class="filter-block filter-relative"
                data-time-mode-target="ddosGraph"
              >
                <label class="label" for="ddosGraphRelativeValue">Relative Range</label>
                <div class="filter-inline ddos-search-actions">
                  <input id="ddosGraphRelativeValue" type="number" min="1" value="60" />
                  <select id="ddosGraphRelativeUnit">
                    <option value="minutes">Minutes</option>
                    <option value="hours">Hours</option>
                    <option value="days">Days</option>
                  </select>
                </div>
              </div>

              <div
                class="filter-block filter-absolute hidden"
                data-time-mode-target="ddosGraph"
              >
                <label class="label" for="ddosGraphStartTime">Start Time</label>
                <input id="ddosGraphStartTime" type="datetime-local" />
              </div>

              <div
                class="filter-block filter-absolute hidden"
                data-time-mode-target="ddosGraph"
              >
                <label class="label" for="ddosGraphEndTime">End Time</label>
                <input id="ddosGraphEndTime" type="datetime-local" />
              </div>

              <div class="filter-block">
                <label class="label" for="btnRunDdosGraph">Run Query</label>
                <button id="btnRunDdosGraph" class="mini-button" type="button">Query</button>
              </div>
            </div>
            <p class="dashboard-note">
              Confirmed search fields: attack IDs and IP addresses. Attack Events use
              <code>sourceIp</code> / <code>destinationIp</code>; Packet Samples use
              <code>ipSourceAddress</code> / <code>ipDestinationAddress</code>.
            </p>
            <p id="ddosGraphStatus" class="hint">No DDoS GraphQL query run yet.</p>
          </article>

          <article class="card" style="grid-column: 1 / -1">
            <h3>DDoS GraphQL Results</h3>
            <div id="ddosGraphChart" class="timeline-chart">
              <p class="hint">Run a query to view DDoS activity over time.</p>
            </div>
            <div id="ddosGraphMetrics" class="metric-grid" style="margin-top: 0.75rem">
              <p class="hint">Run a query to view DDoS summary metrics.</p>
            </div>
            <div id="ddosGraphTable" style="margin-top: 0.75rem">
              <p class="hint">Run a query to view DDoS rows.</p>
            </div>
          </article>

          <article class="card" style="grid-column: 1 / -1">
            <details>
              <summary><strong>GraphQL Schema Explorer</strong></summary>
              <div class="filters-grid" style="margin-top: 0.85rem">
                <div class="filter-block">
                  <label class="label" for="graphqlSchemaPreset">Preset</label>
                  <div class="filter-inline schema-explorer-actions">
                    <select id="graphqlSchemaPreset">
                      <option value="query-root">Query Root Fields</option>
                      <option value="account-fields">Account Fields</option>
                      <option value="health-check-dimensions">Tunnel Health Dimensions</option>
                      <option value="custom-type">Inspect Type</option>
                    </select>
                    <input
                      id="graphqlSchemaTypeName"
                      type="text"
                      value="Account"
                      placeholder="Type name for inspection presets"
                    />
                    <button id="btnApplyGraphqlSchemaPreset" class="mini-button" type="button">
                      Load Preset
                    </button>
                    <button id="btnRunGraphqlSchemaQuery" class="mini-button" type="button">
                      Run Query
                    </button>
                  </div>
                </div>
              </div>
              <div class="schema-explorer-editor">
                <div class="filter-block">
                  <label class="label" for="graphqlSchemaQuery">Query</label>
                  <textarea id="graphqlSchemaQuery"></textarea>
                </div>
                <div class="filter-block">
                  <label class="label" for="graphqlSchemaVariables">Variables (JSON)</label>
                  <textarea id="graphqlSchemaVariables">{}</textarea>
                </div>
              </div>
              <p id="graphqlSchemaStatus" class="hint">
                Load a preset or paste a query to inspect the GraphQL schema.
              </p>
              <pre id="graphqlSchemaResults" class="collection-output">
Load a preset or run a query to view schema results.</pre
              >
            </details>
          </article>
        </div>
      </section>

      <section class="tab-panel" id="tab-rules">
        <h2>Network Flow</h2>
        <div class="card-grid">
          <article class="card" style="grid-column: 1 / -1">
            <h3>Network Flow Rules</h3>
            <button id="btnRefreshNetworkFlow" type="button">Refresh Network Flow Rules</button>
            <p id="networkFlowStatus" class="hint">No data loaded.</p>
          </article>

          <article class="card" style="grid-column: 1 / -1">
            <h3>Static Rules</h3>
            <div id="staticRulesTable"><p class="hint">No data loaded.</p></div>
            <button id="btnAddStaticRuleRow" type="button" style="margin-top: 0.65rem">
              Add Static Rule Row
            </button>
          </article>

          <article class="card" style="grid-column: 1 / -1">
            <h3>Dynamic Rules</h3>
            <div id="dynamicRulesTable"><p class="hint">No data loaded.</p></div>
            <button id="btnAddDynamicRuleRow" type="button" style="margin-top: 0.65rem">
              Add Dynamic Rule Row
            </button>
          </article>

          <article class="card" style="grid-column: 1 / -1">
            <h3>sFlow Advertisement Rules</h3>
            <div id="sflowRulesTable"><p class="hint">No data loaded.</p></div>
            <button id="btnAddSflowRuleRow" type="button" style="margin-top: 0.65rem">
              Add sFlow Rule Row
            </button>
          </article>
        </div>
      </section>

      <section class="tab-panel" id="tab-network">
        <h2>Magic Transit</h2>
        <div class="card-grid">
          <article class="card" style="grid-column: 1 / -1">
            <h3>Transit Overview</h3>
            <button id="btnLoadMagicTransit" type="button">
              Refresh GRE, IPSEC, Routes, CNIs, and BGP Prefixes
            </button>
            <p id="magicTransitStatus" class="hint">No data loaded.</p>
          </article>

          <article class="card" style="grid-column: 1 / -1">
            <h3>BGP Prefixes</h3>
            <div id="magicBgpPrefixesTable"><p class="hint">No data loaded.</p></div>
            <button id="btnCreateBgpPrefix" type="button" style="margin-top: 0.65rem">
              Create BGP Prefix
            </button>
            <div id="magicBgpCreateRow" class="bgp-create-row hidden"></div>
            <p id="magicBgpStatus" class="hint">No data loaded.</p>
          </article>

          <article class="card" style="grid-column: 1 / -1">
            <h3>GRE Tunnels</h3>
            <div id="greTunnelTable"><p class="hint">No data loaded.</p></div>
          </article>

          <article class="card" style="grid-column: 1 / -1">
            <h3>IPSEC Tunnels</h3>
            <div id="ipsecTunnelTable"><p class="hint">No data loaded.</p></div>
          </article>

          <article class="card" style="grid-column: 1 / -1">
            <h3>CNIs</h3>
            <div id="cnisTable"><p class="hint">No data loaded.</p></div>
          </article>

          <article class="card" style="grid-column: 1 / -1">
            <h3>Routes</h3>
            <div id="routesTable"><p class="hint">No data loaded.</p></div>
          </article>
        </div>
      </section>

      <section class="tab-panel" id="tab-flowtrackd">
        <div class="flowtrackd-hero">
          <div>
            <p class="eyebrow">Advanced DDoS protection</p>
            <h2>FlowtrackD control plane</h2>
            <p>
              Manage account-wide Advanced TCP Protection status, protected prefixes,
              allowlists, SYN flood protection, and out-of-state TCP protection. API tokens need
              DDoS Protection Read or Write permission for the requested operation.
            </p>
          </div>
          <div class="flowtrackd-status-panel">
            <span id="flowtrackdProtectionStatus" class="flowtrackd-status-pill">Global status unknown</span>
            <select id="flowtrackdStatusInput" aria-label="Advanced TCP Protection status">
              <option value="true">Enabled</option>
              <option value="false">Disabled</option>
            </select>
            <button id="btnApplyFlowtrackdStatus" class="mini-button" type="button">Apply status</button>
            <button id="btnRefreshFlowtrackd" class="mini-button" type="button">Refresh</button>
          </div>
        </div>
        <p id="flowtrackdStatus" class="hint">Open FlowtrackD to load account configuration.</p>

        <div class="card-grid" style="margin-top: 1rem">
          <article class="card" style="grid-column: 1 / -1">
            <div class="flowtrackd-section-head">
              <div>
                <h3>Protected prefixes</h3>
                <p>Add Magic Transit prefixes to Advanced TCP Protection or exclude sub-prefixes.</p>
              </div>
              <button class="mini-button flowtrackd-delete-all" type="button" data-action="flowtrackd-delete-all" data-resource="prefixes">Delete all</button>
            </div>
            <div class="flowtrackd-create-form" data-flowtrackd-create-form="prefixes">
              <div class="filter-block">
                <label class="label">Prefix / CIDR</label>
                <input data-flowtrackd-field="prefix" placeholder="192.0.2.0/24" />
              </div>
              <div class="filter-block wide">
                <label class="label">Comment</label>
                <input data-flowtrackd-field="comment" placeholder="Protected application range" />
              </div>
              <div class="filter-block">
                <label class="label">Protection</label>
                <select data-flowtrackd-field="excluded">
                  <option value="false">Protected</option>
                  <option value="true">Excluded</option>
                </select>
              </div>
              <button type="button" data-action="flowtrackd-create" data-resource="prefixes">Add prefix</button>
            </div>
            <details class="flowtrackd-bulk">
              <summary>Bulk add prefixes</summary>
              <div class="flowtrackd-create-form" data-flowtrackd-create-form="prefixBulk" style="margin-top: 0.7rem; margin-bottom: 0">
                <div class="filter-block wide">
                  <label class="label">Prefixes, one per line</label>
                  <textarea data-flowtrackd-field="prefixes" placeholder="192.0.2.0/24&#10;198.51.100.0/24"></textarea>
                </div>
                <div class="filter-block wide">
                  <label class="label">Comment applied to each prefix</label>
                  <input data-flowtrackd-field="comment" placeholder="Bulk protected ranges" />
                </div>
                <div class="filter-block">
                  <label class="label">Protection</label>
                  <select data-flowtrackd-field="excluded">
                    <option value="false">Protected</option>
                    <option value="true">Excluded</option>
                  </select>
                </div>
                <button type="button" data-action="flowtrackd-create" data-resource="prefixBulk">Add prefixes</button>
              </div>
            </details>
            <div id="flowtrackdPrefixesTable" class="flowtrackd-table"><p class="hint">No data loaded.</p></div>
          </article>

          <article class="card" style="grid-column: 1 / -1">
            <div class="flowtrackd-section-head">
              <div>
                <h3>Advanced TCP allowlist</h3>
                <p>Allowlisted source prefixes bypass all Advanced TCP Protection rules.</p>
              </div>
              <button class="mini-button flowtrackd-delete-all" type="button" data-action="flowtrackd-delete-all" data-resource="allowlist">Delete all</button>
            </div>
            <div class="flowtrackd-create-form" data-flowtrackd-create-form="allowlist">
              <div class="filter-block">
                <label class="label">Prefix / CIDR</label>
                <input data-flowtrackd-field="prefix" placeholder="203.0.113.0/26" />
              </div>
              <div class="filter-block wide">
                <label class="label">Comment</label>
                <input data-flowtrackd-field="comment" placeholder="Trusted partner range" />
              </div>
              <div class="filter-block">
                <label class="label">State</label>
                <select data-flowtrackd-field="enabled">
                  <option value="true">Enabled</option>
                  <option value="false">Disabled</option>
                </select>
              </div>
              <button type="button" data-action="flowtrackd-create" data-resource="allowlist">Add allowlist entry</button>
            </div>
            <div id="flowtrackdAllowlistTable" class="flowtrackd-table"><p class="hint">No data loaded.</p></div>
          </article>

          <article class="card" style="grid-column: 1 / -1">
            <div class="flowtrackd-section-head">
              <div>
                <h3>SYN flood protection rules</h3>
                <p>Set global, regional, or data-center behavior and sensitivities.</p>
              </div>
              <div class="flowtrackd-actions">
                <button class="mini-button" type="button" data-action="flowtrackd-toggle-create" aria-expanded="false" data-resource="synRules" data-create-label="Create SYN rule">Create SYN rule</button>
                <button class="mini-button flowtrackd-delete-all" type="button" data-action="flowtrackd-delete-all" data-resource="synRules">Delete all</button>
              </div>
            </div>
            <div class="flowtrackd-create-form hidden" data-flowtrackd-create-form="synRules">
              <div class="filter-block">
                <label class="label">Scope</label>
                <select data-flowtrackd-field="scope">
                  <option value="global">Global</option>
                  <option value="region">Region</option>
                  <option value="datacenter">Data center / colo</option>
                </select>
              </div>
              <div class="filter-block">
                <label class="label">Scope name</label>
                <input data-flowtrackd-field="name" value="global" placeholder="global, WEUR, or lax" />
              </div>
              <div class="filter-block">
                <label class="label">Mode</label>
                <select data-flowtrackd-field="mode">
                  <option value="monitoring">Monitoring</option>
                  <option value="enabled">Enabled</option>
                  <option value="disabled">Disabled</option>
                </select>
              </div>
              <div class="filter-block">
                <label class="label">Rate sensitivity</label>
                <select data-flowtrackd-field="rate_sensitivity">
                  <option value="low">Low</option>
                  <option value="medium" selected>Medium</option>
                  <option value="high">High</option>
                </select>
              </div>
              <div class="filter-block">
                <label class="label">Burst sensitivity</label>
                <select data-flowtrackd-field="burst_sensitivity">
                  <option value="low">Low</option>
                  <option value="medium" selected>Medium</option>
                  <option value="high">High</option>
                </select>
              </div>
              <div class="filter-block">
                <label class="label">Mitigation</label>
                <select data-flowtrackd-field="mitigation_type">
                  <option value="challenge">Challenge</option>
                  <option value="retransmit">Retransmit</option>
                </select>
              </div>
              <button type="button" data-action="flowtrackd-create" data-resource="synRules">Create rule</button>
            </div>
            <div id="flowtrackdSynRulesTable" class="flowtrackd-table"><p class="hint">No data loaded.</p></div>
          </article>

          <article class="card" style="grid-column: 1 / -1">
            <div class="flowtrackd-section-head">
              <div>
                <h3>SYN flood protection filters</h3>
                <p>Override SYN protection mode for matching TCP traffic.</p>
              </div>
              <div class="flowtrackd-actions">
                <button class="mini-button" type="button" data-action="flowtrackd-toggle-create" aria-expanded="false" data-resource="synFilters" data-create-label="Create SYN filter">Create SYN filter</button>
                <button class="mini-button flowtrackd-delete-all" type="button" data-action="flowtrackd-delete-all" data-resource="synFilters">Delete all</button>
              </div>
            </div>
            <div class="flowtrackd-create-form hidden" data-flowtrackd-create-form="synFilters">
              <div class="filter-block wide">
                <label class="label">Rules expression</label>
                <textarea data-flowtrackd-field="expression" placeholder="ip.dst in { 192.0.2.0/24 } and tcp.dstport in { 443 }"></textarea>
              </div>
              <div class="filter-block">
                <label class="label">Mode</label>
                <select data-flowtrackd-field="mode">
                  <option value="monitoring">Monitoring</option>
                  <option value="enabled">Enabled</option>
                  <option value="disabled">Disabled</option>
                </select>
              </div>
              <button type="button" data-action="flowtrackd-create" data-resource="synFilters">Create filter</button>
            </div>
            <div id="flowtrackdSynFiltersTable" class="flowtrackd-table"><p class="hint">No data loaded.</p></div>
          </article>

          <article class="card" style="grid-column: 1 / -1">
            <div class="flowtrackd-section-head">
              <div>
                <h3>Out-of-state TCP protection rules</h3>
                <p>Configure FlowtrackD sensitivity per global, region, or data-center scope.</p>
              </div>
              <div class="flowtrackd-actions">
                <button class="mini-button" type="button" data-action="flowtrackd-toggle-create" aria-expanded="false" data-resource="tcpRules" data-create-label="Create TCP flow rule">Create TCP flow rule</button>
                <button class="mini-button flowtrackd-delete-all" type="button" data-action="flowtrackd-delete-all" data-resource="tcpRules">Delete all</button>
              </div>
            </div>
            <div class="flowtrackd-create-form hidden" data-flowtrackd-create-form="tcpRules">
              <div class="filter-block">
                <label class="label">Scope</label>
                <select data-flowtrackd-field="scope">
                  <option value="global">Global</option>
                  <option value="region">Region</option>
                  <option value="datacenter">Data center / colo</option>
                </select>
              </div>
              <div class="filter-block">
                <label class="label">Scope name</label>
                <input data-flowtrackd-field="name" value="global" placeholder="global, WEUR, or lax" />
              </div>
              <div class="filter-block">
                <label class="label">Mode</label>
                <select data-flowtrackd-field="mode">
                  <option value="monitoring">Monitoring</option>
                  <option value="enabled">Enabled</option>
                  <option value="disabled">Disabled</option>
                </select>
              </div>
              <div class="filter-block">
                <label class="label">Rate sensitivity</label>
                <select data-flowtrackd-field="rate_sensitivity">
                  <option value="low">Low</option>
                  <option value="medium" selected>Medium</option>
                  <option value="high">High</option>
                </select>
              </div>
              <div class="filter-block">
                <label class="label">Burst sensitivity</label>
                <select data-flowtrackd-field="burst_sensitivity">
                  <option value="low">Low</option>
                  <option value="medium" selected>Medium</option>
                  <option value="high">High</option>
                </select>
              </div>
              <button type="button" data-action="flowtrackd-create" data-resource="tcpRules">Create rule</button>
            </div>
            <div id="flowtrackdTcpRulesTable" class="flowtrackd-table"><p class="hint">No data loaded.</p></div>
          </article>

          <article class="card" style="grid-column: 1 / -1">
            <div class="flowtrackd-section-head">
              <div>
                <h3>Out-of-state TCP protection filters</h3>
                <p>Override out-of-state TCP protection mode for matching traffic.</p>
              </div>
              <div class="flowtrackd-actions">
                <button class="mini-button" type="button" data-action="flowtrackd-toggle-create" aria-expanded="false" data-resource="tcpFilters" data-create-label="Create TCP flow filter">Create TCP flow filter</button>
                <button class="mini-button flowtrackd-delete-all" type="button" data-action="flowtrackd-delete-all" data-resource="tcpFilters">Delete all</button>
              </div>
            </div>
            <div class="flowtrackd-create-form hidden" data-flowtrackd-create-form="tcpFilters">
              <div class="filter-block wide">
                <label class="label">Rules expression</label>
                <textarea data-flowtrackd-field="expression" placeholder="ip.dst in { 203.0.113.0/24 } and tcp.dstport in { 8000..8081 }"></textarea>
              </div>
              <div class="filter-block">
                <label class="label">Mode</label>
                <select data-flowtrackd-field="mode">
                  <option value="monitoring">Monitoring</option>
                  <option value="enabled">Enabled</option>
                  <option value="disabled">Disabled</option>
                </select>
              </div>
              <button type="button" data-action="flowtrackd-create" data-resource="tcpFilters">Create filter</button>
            </div>
            <div id="flowtrackdTcpFiltersTable" class="flowtrackd-table"><p class="hint">No data loaded.</p></div>
          </article>
        </div>
      </section>

      <section class="tab-panel" id="tab-usage">
        <div class="usage-hero">
          <div class="usage-intro">
            <p class="eyebrow">Capacity planning</p>
            <h2>5-minute P95 throughput</h2>
            <p>
              Review ingress and egress independently across every GRE and IPsec tunnel. Account
              totals are the sum of each tunnel's nearest-rank P95 for the selected window.
            </p>
          </div>
          <div class="usage-controls">
            <label class="label" for="usageLookbackDays">Measurement window</label>
            <select id="usageLookbackDays">
              <option value="1">Last 24 hours</option>
              <option value="7">Last 7 days</option>
              <option value="30" selected>Last 30 days</option>
            </select>
            <button id="btnRunUsage" type="button">Calculate P95 usage</button>
            <p id="usageStatus" class="hint">Open Usage to load the 30-day report.</p>
          </div>
        </div>

        <div id="usageSummaryCards" class="metric-grid">
          <div class="metric-card usage-metric-card primary">
            <div class="metric-label">Total ingress P95</div>
            <div class="metric-value">—</div>
          </div>
          <div class="metric-card usage-metric-card primary">
            <div class="metric-label">Total egress P95</div>
            <div class="metric-value">—</div>
          </div>
          <div class="metric-card usage-metric-card">
            <div class="metric-label">Tunnels measured</div>
            <div class="metric-value">—</div>
          </div>
          <div class="metric-card usage-metric-card">
            <div class="metric-label">5-minute intervals</div>
            <div class="metric-value">—</div>
          </div>
        </div>

        <div class="card-grid" style="margin-top: 1rem">
          <article class="card" style="grid-column: 1 / -1">
            <h3>Per-tunnel P95 profile</h3>
            <p class="usage-card-subtitle">
              Relative P95 capacity by tunnel. Orange is ingress; light orange is egress.
            </p>
            <div id="usageP95Chart">
              <p class="hint">Calculate usage to compare tunnel throughput.</p>
            </div>
          </article>

          <article class="card" style="grid-column: 1 / -1">
            <h3>Tunnel usage details</h3>
            <p class="usage-card-subtitle">
              Missing 5-minute intervals are counted as zero. Values use decimal network units.
            </p>
            <div id="usageP95Table">
              <p class="hint">Calculate usage to view per-tunnel P95 values.</p>
            </div>
          </article>
        </div>
      </section>

      <section class="output">
        <details>
          <summary class="output-head">
            <strong>Response</strong>
            <span class="output-meta">
              <span id="responseStatus" class="status">No request yet</span>
              <span id="responseEndpoint" style="color: var(--muted)"></span>
            </span>
          </summary>
          <pre id="responseBody">Run an action to view API output.</pre>
        </details>
      </section>
    </main>

    <script>
      ${calculateNearestRankPercentile.toString()}
      ${calculateTunnelUsageSummary.toString()}
      ${parseAdvancedTcpProtectionStatus.toString()}

      const tabButtons = document.querySelectorAll(".tab-button");
      const tabPanels = document.querySelectorAll(".tab-panel");
      const statusEl = document.getElementById("responseStatus");
      const endpointEl = document.getElementById("responseEndpoint");
      const bodyEl = document.getElementById("responseBody");
      const envAccountName = document.getElementById("envAccountName");
      const envAccountId = document.getElementById("envAccountId");
      const recentDdosStatus = document.getElementById("recentDdosStatus");
      const bgpOverviewStatus = document.getElementById("bgpOverviewStatus");
      const overviewTunnelHealthStatus = document.getElementById("overviewTunnelHealthStatus");
      const apiAnalyticsStatus = document.getElementById("apiAnalyticsStatus");
      const usageStatus = document.getElementById("usageStatus");
      const ddosGraphStatus = document.getElementById("ddosGraphStatus");
      const graphqlSchemaStatus = document.getElementById("graphqlSchemaStatus");
      const networkFlowStatus = document.getElementById("networkFlowStatus");
      const flowtrackdStatus = document.getElementById("flowtrackdStatus");
      const magicTransitStatus = document.getElementById("magicTransitStatus");
      const magicBgpStatus = document.getElementById("magicBgpStatus");
      const CLIENT_API_TIMEOUT_MS = 15_000;
      const ANALYTICS_TIME_UNIT_TO_MS = {
        minutes: 60 * 1000,
        hours: 60 * 60 * 1000,
        days: 24 * 60 * 60 * 1000,
      };
      const ANALYTICS_TIMESTAMP_FIELDS = [
        "event_datetime",
        "received_at",
        "Datetime",
        "timestamp",
        "time",
        "event_time",
        "event_timestamp",
        "datetime",
        "created_at",
        "createdAt",
        "observed_at",
        "date",
        "ts",
      ];
      const ANALYTICS_TYPE_FIELDS = [
        "AttackVector",
        "MitigationScope",
        "MitigationSystem",
        "Outcome",
        "Verdict",
        "RuleName",
        "type",
        "event_type",
        "traffic_type",
        "attack_type",
        "category",
        "signal_type",
        "rule_type",
      ];
      const ANALYTICS_PREFIX_FIELDS = [
        "IPDestinationSubnet",
        "IPDestinationAddress",
        "IPSourceSubnet",
        "IPSourceAddress",
        "ipdestinationsubnet",
        "ipdestinationaddress",
        "ipsourcesubnet",
        "ipsourceaddress",
        "matched_prefix",
        "prefix",
        "prefix_match",
        "destination_prefix",
        "target_prefix",
        "cidr",
      ];
      const ANALYTICS_SOURCE_FIELDS = [
        "IPSourceAddress",
        "ipsourceaddress",
        "source_address",
        "src_address",
        "source_ip",
        "src_ip",
        "client_ip",
        "source",
        "src",
        "origin_ip",
      ];
      const NETWORK_FLOW_TIMEFRAMES = ["1m", "5m", "10m", "15m", "20m", "30m", "45m", "60m"];
      const NETWORK_FLOW_BOOLEAN_OPTIONS = [
        { value: "true", label: "True" },
        { value: "false", label: "False" },
      ];
      const NETWORK_FLOW_THRESHOLD_MODE_OPTIONS = [
        { value: "bandwidth", label: "Bandwidth" },
        { value: "packets", label: "Packets Per Second" },
      ];
      const NETWORK_FLOW_DYNAMIC_TYPE_OPTIONS = [
        { value: "bits", label: "Bandwidth" },
        { value: "packets", label: "Packets Per Second" },
      ];
      const NETWORK_FLOW_SENSITIVITY_OPTIONS = [
        { value: "low", label: "Low" },
        { value: "medium", label: "Medium" },
        { value: "high", label: "High" },
      ];
      const NETWORK_FLOW_PREFIX_MATCH_OPTIONS = [
        { value: "exact", label: "exact" },
        { value: "subnet", label: "subnet" },
        { value: "supernet", label: "supernet" },
      ];
      const FLOWTRACKD_SCOPE_OPTIONS = ["global", "region", "datacenter"];
      const FLOWTRACKD_MODE_OPTIONS = ["enabled", "disabled", "monitoring"];
      const FLOWTRACKD_SENSITIVITY_OPTIONS = ["low", "medium", "high"];
      const FLOWTRACKD_RESOURCES = {
        prefixes: {
          label: "protected prefixes",
          path: "/api/ddos-protection/prefixes",
          targetId: "flowtrackdPrefixesTable",
          kind: "prefix",
        },
        allowlist: {
          label: "allowlist entries",
          path: "/api/ddos-protection/allowlist",
          targetId: "flowtrackdAllowlistTable",
          kind: "allowlist",
        },
        synRules: {
          label: "SYN protection rules",
          path: "/api/ddos-protection/syn/rules",
          targetId: "flowtrackdSynRulesTable",
          kind: "synRule",
        },
        synFilters: {
          label: "SYN protection filters",
          path: "/api/ddos-protection/syn/filters",
          targetId: "flowtrackdSynFiltersTable",
          kind: "filter",
        },
        tcpRules: {
          label: "TCP flow protection rules",
          path: "/api/ddos-protection/tcp-flow/rules",
          targetId: "flowtrackdTcpRulesTable",
          kind: "tcpRule",
        },
        tcpFilters: {
          label: "TCP flow protection filters",
          path: "/api/ddos-protection/tcp-flow/filters",
          targetId: "flowtrackdTcpFiltersTable",
          kind: "filter",
        },
      };
      const MAGIC_TRANSIT_TUNNEL_BANDWIDTH_QUERY = [
        "query GetMagicTransitTunnelBandwidth($accountTag: string, $datetimeStart: string, $datetimeEnd: string, $direction: string) {",
        "  viewer {",
        "    accounts(filter: { accountTag: $accountTag }) {",
        "      magicTransitTunnelTrafficAdaptiveGroups(",
        "        limit: 1000,",
        "        filter: { datetime_geq: $datetimeStart, datetime_lt: $datetimeEnd, direction: $direction }",
        "      ) {",
        "        avg {",
        "          bitRateFiveMinutes",
        "        }",
        "        dimensions {",
        "          tunnelName",
        "          datetimeFiveMinutes",
        "        }",
        "      }",
        "    }",
        "  }",
        "}",
      ].join("\\n");
      const USAGE_QUERY_ROW_LIMIT = 10000;
      const USAGE_INTERVAL_MS = 5 * 60 * 1000;
      const USAGE_MAX_CHUNK_MS = 7 * 24 * 60 * 60 * 1000;
      const USAGE_TUNNEL_BANDWIDTH_QUERY = [
        "query GetMagicTransitP95Usage($accountTag: string, $datetimeStart: string, $datetimeEnd: string, $direction: string) {",
        "  viewer {",
        "    accounts(filter: { accountTag: $accountTag }) {",
        "      magicTransitTunnelTrafficAdaptiveGroups(",
        "        limit: 10000,",
        "        filter: { datetime_geq: $datetimeStart, datetime_lt: $datetimeEnd, direction: $direction }",
        "      ) {",
        "        avg {",
        "          bitRateFiveMinutes",
        "        }",
        "        dimensions {",
        "          tunnelName",
        "          datetimeFiveMinutes",
        "        }",
        "      }",
        "    }",
        "  }",
        "}",
      ].join("\\n");
      const MAGIC_TRANSIT_TUNNEL_HEALTH_DIMENSIONS_INTROSPECTION_QUERY = [
        "query GetMagicTransitTunnelHealthDimensionsType {",
        '  __type(name: "AccountMagicTransitTunnelHealthChecksAdaptiveGroupsDimensions") {',
        "    fields {",
        "      name",
        "    }",
        "  }",
        "}",
      ].join("\\n");
      const TUNNEL_HEALTH_DATETIME_FIELD_CANDIDATES = [
        "datetimeFiveMinutes",
        "datetimeFiveMinute",
        "datetimeMinute",
        "datetimeHour",
        "datetime",
      ];
      const RECENT_DDOS_ROW_LIMIT = 5;
      const DDOS_GRAPH_TABLE_ROW_LIMIT = 200;
      const DDOS_GRAPH_DATASET_OPTIONS = {
        attack: {
          label: "Attack Events",
          nodeName: "dosdAttackAnalyticsGroups",
          dimensionsTypeName: "AccountDosdAttackAnalyticsGroupsDimensions",
          datetimeCandidates: ["startDatetime", "endDatetime"],
          searchFields: [
            {
              value: "attackId",
              label: "Attack ID",
              placeholder: "example_attack_id",
            },
            {
              value: "sourceIp",
              label: "Source IP",
              placeholder: "198.51.100.10",
            },
            {
              value: "destinationIp",
              label: "Destination IP",
              placeholder: "203.0.113.20",
            },
          ],
        },
        network: {
          label: "Packet Samples",
          nodeName: "dosdNetworkAnalyticsAdaptiveGroups",
          dimensionsTypeName: "AccountDosdNetworkAnalyticsAdaptiveGroupsDimensions",
          datetimeCandidates: [
            "datetimeMinute",
            "datetimeFiveMinutes",
            "datetimeFifteenMinutes",
            "datetimeHour",
            "datetime",
          ],
          searchFields: [
            {
              value: "attackId",
              label: "Attack ID",
              placeholder: "example_attack_id",
            },
            {
              value: "ipSourceAddress",
              label: "Source IP",
              placeholder: "198.51.100.10",
            },
            {
              value: "ipDestinationAddress",
              label: "Destination IP",
              placeholder: "203.0.113.20",
            },
            {
              value: "outcome",
              label: "Outcome",
              placeholder: "drop",
            },
          ],
        },
      };
      const API_MAX_TUNNEL_SERIES = 10;
      const API_TUNNEL_SERIES_COLORS = [
        "#60a5fa",
        "#34d399",
        "#f59e0b",
        "#f472b6",
        "#22d3ee",
        "#f97316",
        "#a78bfa",
        "#84cc16",
        "#ef4444",
        "#38bdf8",
      ];
      const API_AGGREGATE_SERIES_COLOR = "#f9c74f";
      const networkFlowRuleMap = new Map();
      const networkFlowDraftMap = new Map();
      const networkFlowDraftRows = {
        static: [],
        dynamic: [],
        sflow: [],
      };
      let apiTunnelTimelineBuckets = [];
      let apiTunnelSummaryEntries = [];
      let apiSelectedTunnelNames = [];
      let apiLatestSummaryMessage = "No API query run yet.";
      let usageLoading = false;
      let usageLoaded = false;
      let ddosGraphLatestSummaryMessage = "No DDoS GraphQL query run yet.";
      let ddosGraphLoading = false;
      let ddosGraphDatetimeFieldByDataset = {
        attack: "",
        network: "",
      };
      let overviewTunnelHealthTimelineBuckets = [];
      let overviewTunnelHealthTunnelNames = [];
      let overviewTunnelHealthLatestSummaryMessage = "No health check query run yet.";
      let overviewTunnelHealthDatetimeField = "";
      let overviewTunnelHealthLoading = false;
      let graphqlSchemaExplorerLoading = false;
      let networkFlowLoadedRules = [];
      let networkFlowDraftCounter = 0;
      let flowtrackdLoading = false;
      let flowtrackdLoaded = false;

      for (const button of tabButtons) {
        button.addEventListener("click", () => {
          const tab = button.getAttribute("data-tab");

          for (const candidate of tabButtons) {
            candidate.classList.toggle("active", candidate === button);
          }

          for (const panel of tabPanels) {
            panel.classList.toggle("active", panel.id === "tab-" + tab);
          }

          if (tab === "rules") {
            loadNetworkFlowRules();
          }

          if (tab === "overview") {
            loadRecentDdosEvents();
            loadOverviewBgpPrefixes().catch((error) => {
              const message = error instanceof Error ? error.message : String(error);
              setHintMessage(bgpOverviewStatus, message, true);
              setClientError(message);
            });

            if (!overviewTunnelHealthTimelineBuckets.length) {
              runOverviewTunnelHealthQuery();
            }
          }

          if (tab === "network") {
            loadMagicTransitOverview();
          }

          if (tab === "flowtrackd" && !flowtrackdLoaded && !flowtrackdLoading) {
            loadFlowtrackdDashboard();
          }

          if (tab === "analytics-api" && !apiTunnelTimelineBuckets.length) {
            runApiAnalyticsQuery();
          }

          if (tab === "usage" && !usageLoaded && !usageLoading) {
            runUsageQuery();
          }
        });
      }

      function setOutput(ok, status, endpoint, payload) {
        statusEl.textContent = status;
        statusEl.classList.toggle("ok", ok);
        statusEl.classList.toggle("err", !ok);
        endpointEl.textContent = endpoint;

        if (typeof payload === "string") {
          bodyEl.textContent = payload;
          return;
        }

        bodyEl.textContent = JSON.stringify(payload, null, 2);
      }

      function setClientError(message) {
        setOutput(false, "Client error", "UI validation", { error: message });
      }

      function readJsonInput(id) {
        const raw = document.getElementById(id).value.trim();

        if (!raw) {
          return {};
        }

        try {
          return JSON.parse(raw);
        } catch (error) {
          throw new Error("Invalid JSON in " + id + ": " + error.message);
        }
      }

      function readRequiredInput(id, label) {
        const value = document.getElementById(id).value.trim();

        if (!value) {
          throw new Error(label + " is required.");
        }

        return value;
      }

      async function callApi(path, options = {}) {
        const method = options.method || "GET";
        const headers = {};
        const showOutput = options.showOutput !== false;
        const timeoutMsRaw = Number(options.timeoutMs);
        const timeoutMs =
          Number.isFinite(timeoutMsRaw) && timeoutMsRaw > 0
            ? timeoutMsRaw
            : CLIENT_API_TIMEOUT_MS;
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

        let body;
        if (options.body !== undefined) {
          headers["Content-Type"] = "application/json";
          body = JSON.stringify(options.body);
        }

        let response;
        try {
          response = await fetch(path, {
            method,
            headers,
            body,
            signal: controller.signal,
          });
        } catch (error) {
          const rawMessage = error instanceof Error ? error.message : String(error);
          const lower = rawMessage.toLowerCase();
          const isAbort =
            (error instanceof Error && error.name === "AbortError") || lower.includes("abort");
          const payload = {
            error: isAbort
              ? "Request timed out after " + Math.round(timeoutMs / 1000) + "s."
              : rawMessage,
          };

          if (showOutput) {
            setOutput(false, "Network error", method + " " + path, payload);
          }

          return {
            ok: false,
            status: 0,
            statusText: "Network error",
            payload,
          };
        } finally {
          clearTimeout(timeoutId);
        }

        const responseText = await response.text();
        let payload = responseText;

        try {
          payload = JSON.parse(responseText);
        } catch {
          payload = responseText;
        }

        if (showOutput) {
          setOutput(
            response.ok,
            response.status + " " + response.statusText,
            method + " " + path,
            payload,
          );
        }

        return {
          ok: response.ok,
          status: response.status,
          statusText: response.statusText,
          payload,
        };
      }

      function extractResultArray(payload) {
        if (Array.isArray(payload)) {
          return payload;
        }

        if (!payload || typeof payload !== "object") {
          return [];
        }

        if (Array.isArray(payload.result)) {
          return payload.result;
        }

        if (payload.result && typeof payload.result === "object") {
          for (const value of Object.values(payload.result)) {
            if (Array.isArray(value)) {
              return value;
            }
          }
        }

        return [];
      }

      function toDisplayValue(value) {
        if (value === null || value === undefined || value === "") {
          return "—";
        }

        if (typeof value === "object") {
          return JSON.stringify(value);
        }

        return String(value);
      }

      function escapeHtml(value) {
        return value
          .replaceAll("&", "&amp;")
          .replaceAll("<", "&lt;")
          .replaceAll(">", "&gt;")
          .replaceAll('"', "&quot;")
          .replaceAll("'", "&#39;");
      }

      function renderDataTable(targetId, rows, columns) {
        const target = document.getElementById(targetId);

        if (!rows.length) {
          target.innerHTML = '<p class="hint">No records returned.</p>';
          return;
        }

        const headerHtml = columns
          .map((column) => "<th>" + escapeHtml(column.label) + "</th>")
          .join("");

        const rowsHtml = rows
          .map((row) => {
            const cells = columns
              .map((column) => {
                if (typeof column.render === "function") {
                  return "<td>" + column.render(row) + "</td>";
                }

                const value = toDisplayValue(column.value(row));
                return "<td>" + escapeHtml(value) + "</td>";
              })
              .join("");

            return "<tr>" + cells + "</tr>";
          })
          .join("");

        target.innerHTML =
          '<div class="table-wrap"><table class="data-table"><thead><tr>' +
          headerHtml +
          "</tr></thead><tbody>" +
          rowsHtml +
          "</tbody></table></div>";
      }

      function renderCollection(targetId, rows) {
        const target = document.getElementById(targetId);
        target.textContent = rows.length
          ? JSON.stringify(rows, null, 2)
          : "No records returned.";
      }

      function setHintMessage(element, message, isError = false) {
        if (!element) {
          return;
        }

        element.textContent = message;
        element.classList.toggle("err", Boolean(isError));
      }

      function toLocalDateTimeInputValue(date) {
        const year = date.getFullYear();
        const month = String(date.getMonth() + 1).padStart(2, "0");
        const day = String(date.getDate()).padStart(2, "0");
        const hours = String(date.getHours()).padStart(2, "0");
        const minutes = String(date.getMinutes()).padStart(2, "0");

        return year + "-" + month + "-" + day + "T" + hours + ":" + minutes;
      }

      function ensureDefaultAbsoluteRange(prefix) {
        const startInput = document.getElementById(prefix + "StartTime");
        const endInput = document.getElementById(prefix + "EndTime");

        if (!startInput || !endInput) {
          return;
        }

        const now = new Date();

        if (!endInput.value) {
          endInput.value = toLocalDateTimeInputValue(now);
        }

        if (!startInput.value) {
          const prior = new Date(now.getTime() - 60 * 60 * 1000);
          startInput.value = toLocalDateTimeInputValue(prior);
        }
      }

      function updateAnalyticsTimeModeVisibility(prefix) {
        const modeInput = document.getElementById(prefix + "TimeMode");

        if (!modeInput) {
          return;
        }

        const mode = modeInput.value === "absolute" ? "absolute" : "relative";
        const sections = document.querySelectorAll(
          "[data-time-mode-target='" + prefix + "']",
        );

        for (const section of sections) {
          const isRelative = section.classList.contains("filter-relative");
          const shouldShow = mode === "relative" ? isRelative : !isRelative;
          section.classList.toggle("hidden", !shouldShow);
        }

        if (mode === "absolute") {
          ensureDefaultAbsoluteRange(prefix);
        }
      }

      function splitAnalyticsFilterTokens(rawValue) {
        if (rawValue === null || rawValue === undefined) {
          return [];
        }

        return String(rawValue)
          .split(/[\\n,]+/)
          .map((token) => token.trim())
          .filter(Boolean);
      }

      function parseAnalyticsAddressDescriptor(token) {
        const cleaned = cleanAddressValue(token).trim();

        if (!cleaned) {
          return null;
        }

        const cidr = parseCidr(cleaned);

        if (cidr) {
          return {
            raw: cleaned,
            kind: "cidr",
            normalized: cleaned.toLowerCase(),
            cidr,
          };
        }

        const ip = parseIpAddress(cleaned);

        if (ip) {
          return {
            raw: cleaned,
            kind: "ip",
            normalized: normalizeEndpointToken(cleaned),
            ip,
          };
        }

        return null;
      }

      function parseAnalyticsPrefixFilters(rawValue) {
        const tokens = splitAnalyticsFilterTokens(rawValue);
        const descriptors = [];
        const invalidTokens = [];

        for (const token of tokens) {
          const descriptor = parseAnalyticsAddressDescriptor(token);

          if (!descriptor) {
            invalidTokens.push(token);
            continue;
          }

          descriptors.push(descriptor);
        }

        if (invalidTokens.length) {
          throw new Error(
            "Invalid IP/CIDR entries: " + invalidTokens.join(", ") + ".",
          );
        }

        return {
          tokens,
          descriptors,
        };
      }

      function readAnalyticsTimeRange(prefix) {
        const modeInput = document.getElementById(prefix + "TimeMode");
        const mode = modeInput && modeInput.value === "absolute" ? "absolute" : "relative";

        if (mode === "relative") {
          const rawValue = Number(
            document.getElementById(prefix + "RelativeValue")?.value ?? "",
          );
          const unitInput = document.getElementById(prefix + "RelativeUnit");
          const unit = unitInput?.value ?? "minutes";
          const unitMs = ANALYTICS_TIME_UNIT_TO_MS[unit];

          if (!Number.isFinite(rawValue) || rawValue < 1) {
            throw new Error("Relative range value must be a number greater than zero.");
          }

          if (!unitMs) {
            throw new Error("Relative range unit must be minutes, hours, or days.");
          }

          const nowMs = Date.now();
          const startMs = nowMs - rawValue * unitMs;

          return {
            mode,
            relativeValue: rawValue,
            relativeUnit: unit,
            startMs,
            endMs: nowMs,
            startIso: new Date(startMs).toISOString(),
            endIso: new Date(nowMs).toISOString(),
            label: "Last " + rawValue + " " + unit,
          };
        }

        ensureDefaultAbsoluteRange(prefix);
        const startRaw = document.getElementById(prefix + "StartTime")?.value ?? "";
        const endRaw = document.getElementById(prefix + "EndTime")?.value ?? "";

        if (!startRaw || !endRaw) {
          throw new Error("Start Time and End Time are required in absolute mode.");
        }

        const startMs = Date.parse(startRaw);
        const endMs = Date.parse(endRaw);

        if (!Number.isFinite(startMs) || !Number.isFinite(endMs)) {
          throw new Error("Start Time and End Time must be valid timestamps.");
        }

        if (startMs > endMs) {
          throw new Error("Start Time cannot be later than End Time.");
        }

        return {
          mode,
          startMs,
          endMs,
          startIso: new Date(startMs).toISOString(),
          endIso: new Date(endMs).toISOString(),
          label:
            new Date(startMs).toLocaleString() +
            " to " +
            new Date(endMs).toLocaleString(),
        };
      }

      function readAnalyticsFilters(prefix) {
        const typeValue =
          (document.getElementById(prefix + "TypeInput")?.value ?? "ddos").toLowerCase();

        if (typeValue !== "ddos" && typeValue !== "fw") {
          throw new Error("Type must be either DDOS or FW.");
        }

        const prefixesRaw = document.getElementById(prefix + "PrefixInput")?.value ?? "";
        const parsedPrefixes = parseAnalyticsPrefixFilters(prefixesRaw);

        return {
          type: typeValue,
          prefixTokens: parsedPrefixes.tokens,
          prefixDescriptors: parsedPrefixes.descriptors,
          timeRange: readAnalyticsTimeRange(prefix),
        };
      }

      function buildAnalyticsFilterSnapshot(filters) {
        return {
          type: filters.type.toUpperCase(),
          prefixes: filters.prefixTokens,
          timeRange: {
            mode: filters.timeRange.mode,
            startIso: filters.timeRange.startIso,
            endIso: filters.timeRange.endIso,
            label: filters.timeRange.label,
            relativeValue: filters.timeRange.relativeValue,
            relativeUnit: filters.timeRange.relativeUnit,
          },
        };
      }

      function getRowFieldValue(row, candidateKeys) {
        if (!row || typeof row !== "object" || Array.isArray(row)) {
          return undefined;
        }

        for (const key of candidateKeys) {
          if (Object.prototype.hasOwnProperty.call(row, key)) {
            return row[key];
          }
        }

        const entries = Object.entries(row);

        for (const candidate of candidateKeys) {
          const wanted = candidate.toLowerCase();

          for (const [key, value] of entries) {
            if (key.toLowerCase() === wanted) {
              return value;
            }
          }
        }

        return undefined;
      }

      function toAnalyticsText(value) {
        if (value === null || value === undefined) {
          return "";
        }

        if (typeof value === "string") {
          return value.trim();
        }

        if (typeof value === "number" || typeof value === "boolean") {
          return String(value);
        }

        return "";
      }

      function toAnalyticsNumber(value) {
        if (typeof value === "number") {
          return Number.isFinite(value) ? value : 0;
        }

        if (typeof value === "string") {
          const cleaned = value.replaceAll(",", "").trim();
          const numeric = Number(cleaned);
          return Number.isFinite(numeric) ? numeric : 0;
        }

        return 0;
      }

      function buildAnalyticsColoLabel(row) {
        const city = toAnalyticsText(getRowFieldValue(row, ["ColoCity", "colocity", "colo_city"]));
        const country = toAnalyticsText(
          getRowFieldValue(row, ["ColoCountry", "colocountry", "colo_country"]),
        );

        if (city && country) {
          return city + " (" + country + ")";
        }

        if (city) {
          return city;
        }

        if (country) {
          return "Unknown City (" + country + ")";
        }

        return "Unknown";
      }

      function buildAnalyticsSourceAsnLabel(row) {
        const asn = toAnalyticsText(getRowFieldValue(row, ["SourceASN", "sourceasn", "source_asn"]));
        const asnName = toAnalyticsText(
          getRowFieldValue(row, ["SourceASNName", "sourceasnname", "source_asn_name"]),
        );

        if (asn && asnName) {
          return asn + " - " + asnName;
        }

        if (asn) {
          return asn;
        }

        if (asnName) {
          return asnName;
        }

        return "Unknown";
      }

      function normalizeAnalyticsType(value) {
        const normalized = String(value ?? "").trim().toLowerCase();

        if (normalized.includes("ddos")) {
          return "ddos";
        }

        if (normalized.includes("firewall") || normalized.includes("fw")) {
          return "fw";
        }

        return "unknown";
      }

      function inferAnalyticsType(row) {
        const directType = normalizeAnalyticsType(getRowFieldValue(row, ANALYTICS_TYPE_FIELDS));

        if (directType !== "unknown") {
          return directType;
        }

        const hasAttackSignals = ["AttackID", "AttackCampaignID", "AttackVector"].some((field) => {
          const value = toAnalyticsText(getRowFieldValue(row, [field]));
          return Boolean(value);
        });

        if (hasAttackSignals) {
          return "ddos";
        }

        const hasFirewallSignals = [
          "RuleID",
          "RuleName",
          "RulesetID",
          "RulesetOverrideID",
          "Verdict",
          "ProtocolState",
          "MitigationScope",
          "MitigationSystem",
        ].some((field) => {
          const value = toAnalyticsText(getRowFieldValue(row, [field]));
          return Boolean(value);
        });

        if (hasFirewallSignals) {
          return "fw";
        }

        return "unknown";
      }

      function parseAnalyticsTimestamp(value) {
        if (value === null || value === undefined || value === "") {
          return null;
        }

        if (typeof value === "number" && Number.isFinite(value)) {
          if (value > 10_000_000_000) {
            return value;
          }

          if (value > 1_000_000_000) {
            return value * 1000;
          }

          return null;
        }

        const raw = String(value).trim();

        if (!raw) {
          return null;
        }

        if (/^\\d+$/.test(raw)) {
          const numeric = Number(raw);

          if (numeric > 10_000_000_000) {
            return numeric;
          }

          if (numeric > 1_000_000_000) {
            return numeric * 1000;
          }
        }

        const parsed = Date.parse(raw);

        if (Number.isFinite(parsed)) {
          return parsed;
        }

        return null;
      }

      function getAnalyticsTimestampMs(row) {
        for (const field of ANALYTICS_TIMESTAMP_FIELDS) {
          const value = getRowFieldValue(row, [field]);
          const parsed = parseAnalyticsTimestamp(value);

          if (parsed !== null) {
            return parsed;
          }
        }

        return null;
      }

      function collectAnalyticsAddressTokenDescriptors(
        value,
        descriptors = [],
        seen = new Set(),
      ) {
        if (value === null || value === undefined) {
          return descriptors;
        }

        if (Array.isArray(value)) {
          for (const item of value) {
            collectAnalyticsAddressTokenDescriptors(item, descriptors, seen);
          }

          return descriptors;
        }

        if (typeof value === "object") {
          for (const item of Object.values(value)) {
            collectAnalyticsAddressTokenDescriptors(item, descriptors, seen);
          }

          return descriptors;
        }

        const segments = String(value)
          .split(/[\\s,;]+/)
          .map((segment) => segment.trim())
          .filter(Boolean);

        for (const segment of segments) {
          const descriptor = parseAnalyticsAddressDescriptor(segment);

          if (!descriptor) {
            continue;
          }

          const signature = descriptor.kind + ":" + descriptor.normalized;

          if (seen.has(signature)) {
            continue;
          }

          seen.add(signature);
          descriptors.push(descriptor);
        }

        return descriptors;
      }

      function collectDestinationAddressTokens(row) {
        const rawValue = getRowFieldValue(row, [
          "IPDestinationAddress",
          "ipdestinationaddress",
          "destination_address",
          "destinationaddress",
        ]);

        return [...collectAddressTokens(rawValue)];
      }

      function collectDestinationSubnetDescriptors(row) {
        const rawValue = getRowFieldValue(row, [
          "IPDestinationSubnet",
          "ipdestinationsubnet",
          "destination_subnet",
          "destinationsubnet",
        ]);
        const descriptors = collectAnalyticsAddressTokenDescriptors(rawValue, [], new Set());

        return descriptors.filter((descriptor) => descriptor.kind === "cidr");
      }

      function collectAnalyticsAddressDescriptors(row) {
        if (!row || typeof row !== "object" || Array.isArray(row)) {
          return [];
        }

        const descriptors = [];
        const seen = new Set();

        for (const [key, value] of Object.entries(row)) {
          const keyLower = key.toLowerCase();

          if (
            keyLower.includes("ip") ||
            keyLower.includes("prefix") ||
            keyLower.includes("cidr") ||
            keyLower.includes("address") ||
            keyLower.includes("src") ||
            keyLower.includes("dst")
          ) {
            collectAnalyticsAddressTokenDescriptors(value, descriptors, seen);
          }
        }

        return descriptors;
      }

      function cidrContainsCidr(outer, inner) {
        if (!outer || !inner || outer.version !== inner.version) {
          return false;
        }

        if (outer.prefix > inner.prefix) {
          return false;
        }

        return ipInCidr(
          {
            version: inner.version,
            bytes: inner.bytes,
          },
          outer,
        );
      }

      function analyticsDescriptorMatches(filterDescriptor, rowDescriptor) {
        if (!filterDescriptor || !rowDescriptor) {
          return false;
        }

        if (filterDescriptor.kind === "ip" && rowDescriptor.kind === "ip") {
          return filterDescriptor.normalized === rowDescriptor.normalized;
        }

        if (filterDescriptor.kind === "cidr" && rowDescriptor.kind === "ip") {
          return ipInCidr(rowDescriptor.ip, filterDescriptor.cidr);
        }

        if (filterDescriptor.kind === "ip" && rowDescriptor.kind === "cidr") {
          return ipInCidr(filterDescriptor.ip, rowDescriptor.cidr);
        }

        if (filterDescriptor.kind === "cidr" && rowDescriptor.kind === "cidr") {
          if (filterDescriptor.normalized === rowDescriptor.normalized) {
            return true;
          }

          return (
            cidrContainsCidr(filterDescriptor.cidr, rowDescriptor.cidr) ||
            cidrContainsCidr(rowDescriptor.cidr, filterDescriptor.cidr)
          );
        }

        return false;
      }

      function matchesAnalyticsPrefixFilters(filterDescriptors, derivedRow) {
        if (!filterDescriptors.length) {
          return true;
        }

        const destinationAddressTokens = Array.isArray(derivedRow.destinationAddressTokens)
          ? derivedRow.destinationAddressTokens
          : [];
        const destinationSubnetDescriptors = Array.isArray(derivedRow.destinationSubnetDescriptors)
          ? derivedRow.destinationSubnetDescriptors
          : [];

        for (const filterDescriptor of filterDescriptors) {
          if (filterDescriptor.kind === "ip") {
            if (destinationAddressTokens.includes(filterDescriptor.normalized)) {
              return true;
            }

            continue;
          }

          if (filterDescriptor.kind === "cidr") {
            for (const subnetDescriptor of destinationSubnetDescriptors) {
              if (analyticsDescriptorMatches(filterDescriptor, subnetDescriptor)) {
                return true;
              }
            }
          }
        }

        return false;
      }

      function buildAnalyticsDerivedRows(rows) {
        if (!Array.isArray(rows)) {
          return [];
        }

        return rows.map((row) => {
          const matchedPrefix = toAnalyticsText(
            getRowFieldValue(row, ANALYTICS_PREFIX_FIELDS),
          );
          const sourceIp = toAnalyticsText(
            getRowFieldValue(row, ANALYTICS_SOURCE_FIELDS),
          );
          const ipTotalLength = toAnalyticsNumber(
            getRowFieldValue(row, ["IPTotalLength", "iptotallength", "ip_total_length"]),
          );
          const fallbackBytes = toAnalyticsNumber(
            getRowFieldValue(row, ["bytes", "byte_count", "total_bytes", "bits", "bps"]),
          );

          return {
            row,
            type: inferAnalyticsType(row),
            timestampMs: getAnalyticsTimestampMs(row),
            matchedPrefix: matchedPrefix || "Unknown",
            sourceIp: sourceIp || "Unknown",
            bytes: ipTotalLength > 0 ? ipTotalLength : fallbackBytes,
            ipTotalLength,
            packets: toAnalyticsNumber(
              getRowFieldValue(row, ["packets", "packet_count", "pps", "total_packets"]),
            ),
            sourcePort: toAnalyticsNumber(
              getRowFieldValue(row, ["SourcePort", "sourceport", "source_port"]),
            ),
            destinationPort: toAnalyticsNumber(
              getRowFieldValue(row, ["DestinationPort", "destinationport", "destination_port"]),
            ),
            attackVector:
              toAnalyticsText(
                getRowFieldValue(row, ["AttackVector", "attackvector", "attack_vector"]),
              ) || "Unknown",
            protocolName:
              toAnalyticsText(
                getRowFieldValue(row, ["IPProtocolName", "ipprotocolname", "ip_protocol_name"]),
              ) || "Unknown",
            mitigationSystem:
              toAnalyticsText(
                getRowFieldValue(row, ["MitigationSystem", "mitigationsystem", "mitigation_system"]),
              ) || "Unknown",
            ruleName:
              toAnalyticsText(
                getRowFieldValue(row, ["RuleName", "Rulename", "rule_name", "rulename"]),
              ) || "Unknown",
            coloLocation: buildAnalyticsColoLabel(row),
            sourceAsn: buildAnalyticsSourceAsnLabel(row),
            destinationAddressTokens: collectDestinationAddressTokens(row),
            destinationSubnetDescriptors: collectDestinationSubnetDescriptors(row),
          };
        });
      }

      function analyticsRowMatchesFilters(derivedRow, filters) {
        if (filters.type && derivedRow.type !== filters.type) {
          return false;
        }

        if (derivedRow.timestampMs === null) {
          return false;
        }

        if (
          derivedRow.timestampMs < filters.timeRange.startMs ||
          derivedRow.timestampMs > filters.timeRange.endMs
        ) {
          return false;
        }

        return matchesAnalyticsPrefixFilters(filters.prefixDescriptors, derivedRow);
      }

      function filterAnalyticsRows(derivedRows, filters) {
        return derivedRows.filter((row) => analyticsRowMatchesFilters(row, filters));
      }

      function countAnalyticsValues(items, valueSelector) {
        const counts = new Map();

        for (const item of items) {
          const value = valueSelector(item);

          if (value === null || value === undefined || value === "") {
            continue;
          }

          const key = String(value);
          counts.set(key, (counts.get(key) ?? 0) + 1);
        }

        return counts;
      }

      function sortCountMap(countMap, limit = 8, alpha = false) {
        const entries = [...countMap.entries()]
          .sort((left, right) => {
            if (right[1] !== left[1]) {
              return right[1] - left[1];
            }

            return alpha ? left[0].localeCompare(right[0]) : 0;
          })
          .slice(0, limit);

        return entries.map(([label, value]) => ({ label, value }));
      }

      function formatAnalyticsNumber(value) {
        return new Intl.NumberFormat().format(Math.round(value));
      }

      function formatAnalyticsCompactNumber(value) {
        return new Intl.NumberFormat(undefined, {
          notation: "compact",
          maximumFractionDigits: 1,
        }).format(value);
      }

      function getTopCountEntry(countMap) {
        if (!(countMap instanceof Map) || !countMap.size) {
          return null;
        }

        return [...countMap.entries()].sort((left, right) => {
          if (right[1] !== left[1]) {
            return right[1] - left[1];
          }

          return String(left[0]).localeCompare(String(right[0]));
        })[0];
      }

      function formatTopMetricValue(countMap, options = {}) {
        const topEntry = getTopCountEntry(countMap);

        if (!topEntry) {
          return "—";
        }

        const [rawLabel, count] = topEntry;
        const formatter =
          typeof options.formatLabel === "function" ? options.formatLabel : (label) => String(label);
        const label = formatter(rawLabel, count);

        if (!label) {
          return "—";
        }

        return label + " (" + formatAnalyticsNumber(count) + ")";
      }

      function buildTimelineEntries(rows) {
        const buckets = new Map();
        const hourMs = 60 * 60 * 1000;

        for (const row of rows) {
          if (row.timestampMs === null) {
            continue;
          }

          const bucketMs = Math.floor(row.timestampMs / hourMs) * hourMs;
          buckets.set(bucketMs, (buckets.get(bucketMs) ?? 0) + 1);
        }

        return [...buckets.entries()]
          .sort((left, right) => {
            if (right[1] !== left[1]) {
              return right[1] - left[1];
            }

            return right[0] - left[0];
          })
          .slice(0, 10)
          .sort((left, right) => left[0] - right[0])
          .map(([bucketMs, value]) => ({
            label: new Date(bucketMs).toLocaleString(undefined, {
              month: "short",
              day: "numeric",
              hour: "2-digit",
              minute: "2-digit",
              hour12: false,
            }),
            value,
          }));
      }

      function renderMetricCards(targetId, metrics) {
        const target = document.getElementById(targetId);

        if (!target) {
          return;
        }

        if (!metrics.length) {
          target.innerHTML = '<p class="hint">No summary metrics available.</p>';
          return;
        }

        target.innerHTML = metrics
          .map(
            (metric) =>
              '<div class="metric-card"><div class="metric-label">' +
              escapeHtml(metric.label) +
              '</div><div class="metric-value">' +
              escapeHtml(metric.value) +
              "</div></div>",
          )
          .join("");
      }

      function renderBarChart(targetId, entries, emptyMessage) {
        const target = document.getElementById(targetId);

        if (!target) {
          return;
        }

        if (!entries.length) {
          target.innerHTML = '<p class="hint">' + escapeHtml(emptyMessage) + "</p>";
          return;
        }

        const maxValue = Math.max(
          ...entries.map((entry) => entry.value),
          1,
        );

        const rowsHtml = entries
          .map((entry) => {
            const widthPct = ((entry.value / maxValue) * 100).toFixed(2);

            return (
              '<div class="chart-row"><div class="chart-label">' +
              escapeHtml(entry.label) +
              '</div><div class="chart-track"><div class="chart-fill" style="width:' +
              widthPct +
              '%"></div></div><div class="chart-value">' +
              escapeHtml(formatAnalyticsCompactNumber(entry.value)) +
              "</div></div>"
            );
          })
          .join("");

        target.innerHTML = '<div class="chart-list">' + rowsHtml + "</div>";
      }

      function readApiAnalyticsFilters() {
        const direction =
          (document.getElementById("apiDirectionInput")?.value ?? "ingress").toLowerCase();

        if (direction !== "ingress" && direction !== "egress") {
          throw new Error("Direction must be ingress or egress.");
        }

        return {
          direction,
          timeRange: readAnalyticsTimeRange("api"),
        };
      }

      function buildApiFilterSnapshot(filters, accountTag, variables) {
        return {
          accountTag,
          direction: filters.direction,
          timeRange: {
            mode: filters.timeRange.mode,
            startIso: filters.timeRange.startIso,
            endIso: filters.timeRange.endIso,
            label: filters.timeRange.label,
            relativeValue: filters.timeRange.relativeValue,
            relativeUnit: filters.timeRange.relativeUnit,
          },
          variables,
        };
      }

      function getDdosGraphDatasetConfig(datasetKey) {
        const normalizedKey = typeof datasetKey === "string" ? datasetKey.trim().toLowerCase() : "";
        const config = DDOS_GRAPH_DATASET_OPTIONS[normalizedKey];

        if (!config) {
          throw new Error("Select a supported DDoS dataset.");
        }

        return config;
      }

      function buildDdosGraphSearchFieldOptions() {
        const datasetInput = document.getElementById("ddosGraphDataset");
        const searchFieldInput = document.getElementById("ddosGraphSearchField");

        if (!datasetInput || !searchFieldInput) {
          return;
        }

        const datasetConfig = getDdosGraphDatasetConfig(datasetInput.value || "attack");
        const currentValue = toAnalyticsText(searchFieldInput.value);
        const preferredValue =
          datasetConfig.searchFields.find(
            (field) => field.value === "destinationIp" || field.value === "ipDestinationAddress",
          )?.value ?? "";

        searchFieldInput.innerHTML = datasetConfig.searchFields
          .map(
            (field) =>
              '<option value="' +
              escapeHtml(field.value) +
              '">' +
              escapeHtml(field.label) +
              "</option>",
          )
          .join("");

        const nextValue = datasetConfig.searchFields.some((field) => field.value === currentValue)
          ? currentValue
          : preferredValue || datasetConfig.searchFields[0]?.value || "";

        if (nextValue) {
          searchFieldInput.value = nextValue;
        }

        updateDdosGraphSearchPlaceholder();
      }

      function updateDdosGraphSearchPlaceholder() {
        const datasetInput = document.getElementById("ddosGraphDataset");
        const searchFieldInput = document.getElementById("ddosGraphSearchField");
        const searchValueInput = document.getElementById("ddosGraphSearchValue");

        if (!datasetInput || !searchFieldInput || !searchValueInput) {
          return;
        }

        const datasetConfig = getDdosGraphDatasetConfig(datasetInput.value || "attack");
        const selectedField =
          datasetConfig.searchFields.find((field) => field.value === searchFieldInput.value) ??
          datasetConfig.searchFields[0];

        searchValueInput.placeholder = selectedField
          ? selectedField.placeholder
          : "Attack ID or IP address. Use commas for multiple exact matches.";
      }

      function initializeDdosGraphDefaults() {
        const datasetInput = document.getElementById("ddosGraphDataset");
        const timeModeInput = document.getElementById("ddosGraphTimeMode");
        const relativeValueInput = document.getElementById("ddosGraphRelativeValue");
        const relativeUnitInput = document.getElementById("ddosGraphRelativeUnit");
        const searchValueInput = document.getElementById("ddosGraphSearchValue");

        if (datasetInput) {
          datasetInput.value = "attack";
        }

        if (timeModeInput) {
          timeModeInput.value = "relative";
        }

        if (relativeValueInput) {
          relativeValueInput.value = "60";
        }

        if (relativeUnitInput) {
          relativeUnitInput.value = "minutes";
        }

        if (searchValueInput) {
          searchValueInput.value = "";
        }

        buildDdosGraphSearchFieldOptions();
      }

      function readDdosGraphFilters() {
        const dataset = (document.getElementById("ddosGraphDataset")?.value ?? "attack").toLowerCase();
        const datasetConfig = getDdosGraphDatasetConfig(dataset);
        const searchField = toAnalyticsText(document.getElementById("ddosGraphSearchField")?.value);

        if (!datasetConfig.searchFields.some((field) => field.value === searchField)) {
          throw new Error("Select a supported DDoS search field.");
        }

        const rawTokens = splitAnalyticsFilterTokens(
          document.getElementById("ddosGraphSearchValue")?.value ?? "",
        );
        const searchTokens = [];

        for (const token of rawTokens) {
          if (!searchTokens.includes(token)) {
            searchTokens.push(token);
          }
        }

        return {
          dataset,
          searchField,
          searchTokens,
          timeRange: readAnalyticsTimeRange("ddosGraph"),
        };
      }

      function buildDdosGraphFilterSnapshot(filters, accountTag, datetimeField, variables) {
        const datasetConfig = getDdosGraphDatasetConfig(filters.dataset);
        const searchFieldLabel =
          datasetConfig.searchFields.find((field) => field.value === filters.searchField)?.label ??
          filters.searchField;

        return {
          accountTag,
          dataset: datasetConfig.nodeName,
          datasetLabel: datasetConfig.label,
          datetimeField,
          searchField: filters.searchField,
          searchFieldLabel,
          searchValues: filters.searchTokens,
          timeRange: {
            mode: filters.timeRange.mode,
            startIso: filters.timeRange.startIso,
            endIso: filters.timeRange.endIso,
            label: filters.timeRange.label,
            relativeValue: filters.timeRange.relativeValue,
            relativeUnit: filters.timeRange.relativeUnit,
          },
          variables,
        };
      }

      function buildDdosGraphSearchFilter(filters) {
        if (!filters.searchTokens.length) {
          return {
            variableDefinitions: "",
            filterClause: "",
            variables: {},
          };
        }

        if (filters.searchTokens.length === 1) {
          return {
            variableDefinitions: ", $searchValue: string",
            filterClause: ", " + filters.searchField + ": $searchValue",
            variables: {
              searchValue: filters.searchTokens[0],
            },
          };
        }

        return {
          variableDefinitions: ", $searchValues: [string!]",
          filterClause: ", " + filters.searchField + "_in: $searchValues",
          variables: {
            searchValues: filters.searchTokens,
          },
        };
      }

      function buildDosdAttackAnalyticsGraphQuery(filters, datetimeField) {
        const searchFilter = buildDdosGraphSearchFilter(filters);

        return [
          "query GetDosdAttackAnalyticsGraph($accountTag: string, $datetimeStart: string, $datetimeEnd: string" +
            searchFilter.variableDefinitions +
            ") {",
          "  viewer {",
          "    accounts(filter: { accountTag: $accountTag }) {",
          "      dosdAttackAnalyticsGroups(",
          "        limit: 1000,",
          "        filter: { " +
            datetimeField +
            "_geq: $datetimeStart, " +
            datetimeField +
            "_lt: $datetimeEnd" +
            searchFilter.filterClause +
            " }",
          "      ) {",
          "        attackId",
          "        attackType",
          "        attackVector",
          "        sourceIp",
          "        destinationIp",
          "        sourcePort",
          "        destinationPort",
          "        " + datetimeField,
          "      }",
          "    }",
          "  }",
          "}",
        ].join("\\n");
      }

      function buildDosdNetworkAnalyticsGraphQuery(filters, datetimeField) {
        const searchFilter = buildDdosGraphSearchFilter(filters);

        return [
          "query GetDosdNetworkAnalyticsGraph($accountTag: string, $datetimeStart: string, $datetimeEnd: string" +
            searchFilter.variableDefinitions +
            ") {",
          "  viewer {",
          "    accounts(filter: { accountTag: $accountTag }) {",
          "      dosdNetworkAnalyticsAdaptiveGroups(",
          "        limit: 1000,",
          "        filter: { datetime_geq: $datetimeStart, datetime_lt: $datetimeEnd" +
            searchFilter.filterClause +
            " }",
          "      ) {",
          "        dimensions {",
          "          " + datetimeField,
          "          attackId",
          "          attackVector",
          "          ipSourceAddress",
          "          ipDestinationAddress",
          "          sourcePort",
          "          destinationPort",
          "          direction",
          "        }",
          "      }",
          "    }",
          "  }",
          "}",
        ].join("\\n");
      }

      function buildDdosGraphRequest(filters, accountTag, datetimeField) {
        const searchFilter = buildDdosGraphSearchFilter(filters);
        const query =
          filters.dataset === "network"
            ? buildDosdNetworkAnalyticsGraphQuery(filters, datetimeField)
            : buildDosdAttackAnalyticsGraphQuery(filters, datetimeField);

        return {
          query,
          variables: {
            accountTag,
            datetimeStart: filters.timeRange.startIso,
            datetimeEnd: filters.timeRange.endIso,
            ...searchFilter.variables,
          },
        };
      }

      async function loadDdosGraphDatetimeFieldCandidates(datasetKey) {
        const datasetConfig = getDdosGraphDatasetConfig(datasetKey);
        const cachedField =
          ddosGraphDatetimeFieldByDataset && typeof ddosGraphDatetimeFieldByDataset === "object"
            ? ddosGraphDatetimeFieldByDataset[datasetKey]
            : "";
        const fallback = [...datasetConfig.datetimeCandidates];

        if (cachedField) {
          return [cachedField, ...fallback.filter((candidate) => candidate !== cachedField)];
        }

        try {
          const response = await callApi("/api/graphql", {
            method: "POST",
            body: {
              query: [
                "query InspectDdosDimensionsType {",
                "  __type(name: " + JSON.stringify(datasetConfig.dimensionsTypeName) + ") {",
                "    fields {",
                "      name",
                "    }",
                "  }",
                "}",
              ].join("\\n"),
              variables: {},
            },
            showOutput: false,
            timeoutMs: 8_000,
          });

          if (!response || !response.ok) {
            return fallback;
          }

          const graphqlErrors = Array.isArray(response.payload?.errors)
            ? response.payload.errors
            : [];

          if (graphqlErrors.length) {
            return fallback;
          }

          const fields = Array.isArray(response.payload?.data?.__type?.fields)
            ? response.payload.data.__type.fields
                .map((entry) => (typeof entry?.name === "string" ? entry.name.trim() : ""))
                .filter(Boolean)
            : [];
          const datetimeFields = fields.filter((field) => field.toLowerCase().startsWith("datetime"));

          if (!datetimeFields.length) {
            return fallback;
          }

          const ordered = [
            ...fallback.filter((candidate) => datetimeFields.includes(candidate)),
            ...datetimeFields,
            ...fallback,
          ];
          const deduped = [];

          for (const field of ordered) {
            if (!deduped.includes(field)) {
              deduped.push(field);
            }
          }

          return deduped;
        } catch {
          return fallback;
        }
      }

      function getDdosGraphRowSource(group) {
        if (group?.dimensions && typeof group.dimensions === "object" && !Array.isArray(group.dimensions)) {
          return group.dimensions;
        }

        return group && typeof group === "object" && !Array.isArray(group) ? group : {};
      }

      function extractDosdAttackAnalyticsRows(payload, datetimeField) {
        const accounts = Array.isArray(payload?.data?.viewer?.accounts)
          ? payload.data.viewer.accounts
          : [];
        const rows = [];

        for (const account of accounts) {
          const groups = Array.isArray(account?.dosdAttackAnalyticsGroups)
            ? account.dosdAttackAnalyticsGroups
            : [];

          for (const group of groups) {
            const source = getDdosGraphRowSource(group);
            const datetimeIso = toAnalyticsText(source?.[datetimeField]);
            const timestampMsRaw = Date.parse(datetimeIso);

            rows.push({
              datasetLabel: DDOS_GRAPH_DATASET_OPTIONS.attack.label,
              datetimeIso,
              timestampMs: Number.isFinite(timestampMsRaw) ? timestampMsRaw : null,
              attackId: toAnalyticsText(source?.attackId),
              attackVector: toAnalyticsText(source?.attackVector),
              sourceIp: toAnalyticsText(source?.sourceIp),
              destinationIp: toAnalyticsText(source?.destinationIp),
              sourcePort: toAnalyticsText(source?.sourcePort),
              destinationPort: toAnalyticsText(source?.destinationPort),
              context: toAnalyticsText(source?.attackType),
            });
          }
        }

        return rows.sort((left, right) => {
          const leftMs = left.timestampMs ?? 0;
          const rightMs = right.timestampMs ?? 0;

          if (leftMs !== rightMs) {
            return leftMs - rightMs;
          }

          return left.attackId.localeCompare(right.attackId);
        });
      }

      function extractDosdNetworkAnalyticsRows(payload, datetimeField) {
        const accounts = Array.isArray(payload?.data?.viewer?.accounts)
          ? payload.data.viewer.accounts
          : [];
        const rows = [];

        for (const account of accounts) {
          const groups = Array.isArray(account?.dosdNetworkAnalyticsAdaptiveGroups)
            ? account.dosdNetworkAnalyticsAdaptiveGroups
            : [];

          for (const group of groups) {
            const source = getDdosGraphRowSource(group);
            const datetimeIso = toAnalyticsText(source?.[datetimeField]);
            const timestampMsRaw = Date.parse(datetimeIso);

            rows.push({
              datasetLabel: DDOS_GRAPH_DATASET_OPTIONS.network.label,
              datetimeIso,
              timestampMs: Number.isFinite(timestampMsRaw) ? timestampMsRaw : null,
              attackId: toAnalyticsText(source?.attackId),
              attackVector: toAnalyticsText(source?.attackVector),
              sourceIp: toAnalyticsText(source?.ipSourceAddress),
              destinationIp: toAnalyticsText(source?.ipDestinationAddress),
              sourcePort: toAnalyticsText(source?.sourcePort),
              destinationPort: toAnalyticsText(source?.destinationPort),
              context: toAnalyticsText(source?.direction),
            });
          }
        }

        return rows.sort((left, right) => {
          const leftMs = left.timestampMs ?? 0;
          const rightMs = right.timestampMs ?? 0;

          if (leftMs !== rightMs) {
            return leftMs - rightMs;
          }

          return left.attackId.localeCompare(right.attackId);
        });
      }

      function extractDdosGraphRows(datasetKey, payload, datetimeField) {
        return datasetKey === "network"
          ? extractDosdNetworkAnalyticsRows(payload, datetimeField)
          : extractDosdAttackAnalyticsRows(payload, datetimeField);
      }

      function getDdosGraphBucketConfig(timeRange) {
        const parsedStartMs = Date.parse(timeRange?.startIso ?? "");
        const parsedEndMs = Date.parse(timeRange?.endIso ?? "");
        const fallbackEndMs = Date.now();
        const startMs = Number.isFinite(parsedStartMs)
          ? parsedStartMs
          : fallbackEndMs - ANALYTICS_TIME_UNIT_TO_MS.hours;
        const endMs = Number.isFinite(parsedEndMs) && parsedEndMs > startMs
          ? parsedEndMs
          : startMs + ANALYTICS_TIME_UNIT_TO_MS.hours;
        const durationMs = Math.max(1, endMs - startMs);

        if (durationMs < 4 * ANALYTICS_TIME_UNIT_TO_MS.hours) {
          return {
            startMs,
            endMs,
            bucketSizeMs: ANALYTICS_TIME_UNIT_TO_MS.minutes,
            label: "1 minute",
          };
        }

        if (durationMs < 7 * ANALYTICS_TIME_UNIT_TO_MS.days) {
          return {
            startMs,
            endMs,
            bucketSizeMs: ANALYTICS_TIME_UNIT_TO_MS.hours,
            label: "1 hour",
          };
        }

        if (durationMs <= 14 * ANALYTICS_TIME_UNIT_TO_MS.days) {
          return {
            startMs,
            endMs,
            bucketSizeMs: 4 * ANALYTICS_TIME_UNIT_TO_MS.hours,
            label: "4 hours",
          };
        }

        return {
          startMs,
          endMs,
          bucketSizeMs: ANALYTICS_TIME_UNIT_TO_MS.days,
          label: "1 day",
        };
      }

      function floorDdosGraphBucketTimestamp(timestampMs, bucketSizeMs) {
        if (!Number.isFinite(timestampMs) || !Number.isFinite(bucketSizeMs) || bucketSizeMs <= 0) {
          return null;
        }

        return Math.floor(timestampMs / bucketSizeMs) * bucketSizeMs;
      }

      function formatDdosGraphTimelineLabel(timestampMs, bucketConfig) {
        if (!Number.isFinite(timestampMs)) {
          return "Unknown";
        }

        const options =
          bucketConfig && bucketConfig.bucketSizeMs >= ANALYTICS_TIME_UNIT_TO_MS.days
            ? {
                month: "2-digit",
                day: "2-digit",
              }
            : bucketConfig && bucketConfig.bucketSizeMs >= ANALYTICS_TIME_UNIT_TO_MS.hours
              ? {
                  month: "2-digit",
                  day: "2-digit",
                  hour: "2-digit",
                }
              : {
                  month: "2-digit",
                  day: "2-digit",
                  hour: "2-digit",
                  minute: "2-digit",
                };

        return new Date(timestampMs).toLocaleString([], options);
      }

      function buildDdosGraphTimelineBuckets(rows, timeRange) {
        const bucketConfig = getDdosGraphBucketConfig(timeRange);
        const aggregateByTimestamp = new Map();
        const alignedStartMs =
          floorDdosGraphBucketTimestamp(bucketConfig.startMs, bucketConfig.bucketSizeMs) ?? bucketConfig.startMs;
        const alignedEndExclusiveMs =
          (floorDdosGraphBucketTimestamp(
            Math.max(bucketConfig.startMs, bucketConfig.endMs - 1),
            bucketConfig.bucketSizeMs,
          ) ?? bucketConfig.endMs) + bucketConfig.bucketSizeMs;

        for (
          let timestampMs = alignedStartMs;
          timestampMs < alignedEndExclusiveMs;
          timestampMs += bucketConfig.bucketSizeMs
        ) {
          aggregateByTimestamp.set(timestampMs, {
            timestampMs,
            datetimeIso: new Date(timestampMs).toISOString(),
            count: 0,
          });
        }

        for (const row of rows) {
          const datetimeIso = toAnalyticsText(row.datetimeIso);
          const timestampMs = Number.isFinite(row.timestampMs) ? row.timestampMs : Date.parse(datetimeIso);
          const bucketTimestampMs = floorDdosGraphBucketTimestamp(timestampMs, bucketConfig.bucketSizeMs);

          if (!Number.isFinite(bucketTimestampMs)) {
            continue;
          }

          const existing = aggregateByTimestamp.get(bucketTimestampMs) ?? {
            timestampMs: bucketTimestampMs,
            datetimeIso: new Date(bucketTimestampMs).toISOString(),
            count: 0,
          };

          existing.count += 1;

          aggregateByTimestamp.set(bucketTimestampMs, existing);
        }

        return {
          bucketConfig,
          buckets: [...aggregateByTimestamp.values()].sort((left, right) => {
            const leftMs = left.timestampMs ?? 0;
            const rightMs = right.timestampMs ?? 0;

            if (leftMs !== rightMs) {
              return leftMs - rightMs;
            }

            return String(left.datetimeIso).localeCompare(String(right.datetimeIso));
          }),
        };
      }

      function buildDdosGraphCountMap(rows, selector) {
        const countMap = new Map();

        for (const row of rows) {
          const value = toAnalyticsText(selector(row));

          if (!value) {
            continue;
          }

          countMap.set(value, (countMap.get(value) ?? 0) + 1);
        }

        return countMap;
      }

      function renderDdosGraphLineChart(timelineData, datasetLabel) {
        const target = document.getElementById("ddosGraphChart");
        const timelineBuckets = Array.isArray(timelineData?.buckets) ? timelineData.buckets : [];
        const bucketConfig = timelineData?.bucketConfig ?? null;

        if (!target) {
          return;
        }

        if (!timelineBuckets.length) {
          target.innerHTML = '<p class="hint">No DDoS rows are available for charting.</p>';
          return;
        }

        const maxValue = Math.max(
          1,
          ...timelineBuckets.map((bucket) => (Number.isFinite(bucket.count) && bucket.count > 0 ? bucket.count : 0)),
        );
        const chartWidth = 1200;
        const chartHeight = 360;
        const margin = {
          top: 14,
          right: 16,
          bottom: 52,
          left: 88,
        };
        const plotWidth = chartWidth - margin.left - margin.right;
        const plotHeight = chartHeight - margin.top - margin.bottom;
        const pointCount = timelineBuckets.length;
        const yTickCount = 5;

        const computeX = (index) => {
          if (pointCount <= 1) {
            return margin.left + plotWidth / 2;
          }

          return margin.left + (index / (pointCount - 1)) * plotWidth;
        };

        const computeY = (value) => {
          const numeric = Number.isFinite(value) && value > 0 ? value : 0;
          return margin.top + (1 - numeric / maxValue) * plotHeight;
        };

        const gridAndYLabelHtml = [];

        for (let index = 0; index < yTickCount; index += 1) {
          const ratio = index / (yTickCount - 1);
          const y = margin.top + ratio * plotHeight;
          const value = maxValue * (1 - ratio);

          gridAndYLabelHtml.push(
            '<line x1="' +
              margin.left.toFixed(2) +
              '" y1="' +
              y.toFixed(2) +
              '" x2="' +
              (margin.left + plotWidth).toFixed(2) +
              '" y2="' +
              y.toFixed(2) +
              '" stroke="rgba(255, 255, 255, 0.12)" stroke-width="1" />',
          );
          gridAndYLabelHtml.push(
            '<text x="' +
              (margin.left - 10).toFixed(2) +
              '" y="' +
              (y + 4).toFixed(2) +
              '" fill="rgba(255, 215, 179, 0.75)" font-size="11" text-anchor="end">' +
              escapeHtml(formatAnalyticsNumber(value)) +
              "</text>",
          );
        }

        const xTickIndexes = buildApiLineChartTickIndexes(pointCount, 7);
        const xTickHtml = xTickIndexes
          .map((index) => {
            const x = computeX(index);
            const bucket = timelineBuckets[index];
            const label = formatDdosGraphTimelineLabel(bucket.timestampMs, bucketConfig);

            return (
              '<line x1="' +
              x.toFixed(2) +
              '" y1="' +
              (margin.top + plotHeight).toFixed(2) +
              '" x2="' +
              x.toFixed(2) +
              '" y2="' +
              (margin.top + plotHeight + 4).toFixed(2) +
              '" stroke="rgba(255, 255, 255, 0.25)" stroke-width="1" />' +
              '<text x="' +
              x.toFixed(2) +
              '" y="' +
              (margin.top + plotHeight + 18).toFixed(2) +
              '" fill="rgba(255, 215, 179, 0.75)" font-size="11" text-anchor="middle">' +
              escapeHtml(label) +
              "</text>"
            );
          })
          .join("");

        const polylineHtml =
          '<polyline points="' +
          timelineBuckets
            .map((bucket, index) => computeX(index).toFixed(2) + "," + computeY(bucket.count).toFixed(2))
            .join(" ") +
          '" fill="none" stroke="' +
          escapeHtml(API_AGGREGATE_SERIES_COLOR) +
          '" stroke-width="2.8" stroke-linejoin="round" stroke-linecap="round" />';
        const legendHtml =
          '<span class="api-line-chart-legend-item"><span class="api-tunnel-swatch" style="background:' +
          escapeHtml(API_AGGREGATE_SERIES_COLOR) +
          '"></span>' +
          escapeHtml(datasetLabel + (bucketConfig ? " (" + bucketConfig.label + ")" : "")) +
          "</span>";

        target.innerHTML =
          '<div class="api-line-chart"><svg viewBox="0 0 ' +
          chartWidth +
          " " +
          chartHeight +
          '" role="img" aria-label="DDoS activity over time">' +
          '<rect x="' +
          margin.left.toFixed(2) +
          '" y="' +
          margin.top.toFixed(2) +
          '" width="' +
          plotWidth.toFixed(2) +
          '" height="' +
          plotHeight.toFixed(2) +
          '" fill="rgba(0, 0, 0, 0.08)" />' +
          gridAndYLabelHtml.join("") +
          '<line x1="' +
          margin.left.toFixed(2) +
          '" y1="' +
          margin.top.toFixed(2) +
          '" x2="' +
          margin.left.toFixed(2) +
          '" y2="' +
          (margin.top + plotHeight).toFixed(2) +
          '" stroke="rgba(255, 255, 255, 0.38)" stroke-width="1" />' +
          '<line x1="' +
          margin.left.toFixed(2) +
          '" y1="' +
          (margin.top + plotHeight).toFixed(2) +
          '" x2="' +
          (margin.left + plotWidth).toFixed(2) +
          '" y2="' +
          (margin.top + plotHeight).toFixed(2) +
          '" stroke="rgba(255, 255, 255, 0.38)" stroke-width="1" />' +
          xTickHtml +
          polylineHtml +
          "</svg><div class='api-line-chart-legend'>" +
          legendHtml +
          "</div></div>";
      }

      function renderDdosGraphMetrics(filters, rows, timelineData) {
        const datasetConfig = getDdosGraphDatasetConfig(filters.dataset);
        const timelineBuckets = Array.isArray(timelineData?.buckets) ? timelineData.buckets : [];
        const bucketConfig = timelineData?.bucketConfig ?? null;
        const searchFieldLabel =
          datasetConfig.searchFields.find((field) => field.value === filters.searchField)?.label ??
          filters.searchField;
        const searchSummary = filters.searchTokens.length
          ? searchFieldLabel + ": " + filters.searchTokens.join(", ")
          : "No search filter";
        const attackVectorCounts = buildDdosGraphCountMap(rows, (row) => row.attackVector);
        const sourceIpCounts = buildDdosGraphCountMap(rows, (row) => row.sourceIp);
        const destinationIpCounts = buildDdosGraphCountMap(rows, (row) => row.destinationIp);

        renderMetricCards("ddosGraphMetrics", [
          {
            label: "Dataset",
            value: datasetConfig.label,
          },
          {
            label: "Search",
            value: searchSummary,
          },
          {
            label: "Rows Returned",
            value: formatAnalyticsNumber(rows.length),
          },
          {
            label: "Time Buckets",
            value: formatAnalyticsNumber(timelineBuckets.length),
          },
          {
            label: "Chart Interval",
            value: bucketConfig?.label ?? "Auto",
          },
          {
            label: "Top Attack Vector",
            value: formatTopMetricValue(attackVectorCounts),
          },
          {
            label: "Top Source IP",
            value: formatTopMetricValue(sourceIpCounts),
          },
          {
            label: "Top Destination IP",
            value: formatTopMetricValue(destinationIpCounts),
          },
        ]);
      }

      function renderDdosGraphTable(rows) {
        const sortedRows = [...rows].sort((left, right) => {
          const leftMs = left.timestampMs ?? 0;
          const rightMs = right.timestampMs ?? 0;

          if (rightMs !== leftMs) {
            return rightMs - leftMs;
          }

          return left.attackId.localeCompare(right.attackId);
        });
        const displayRows = sortedRows.slice(0, DDOS_GRAPH_TABLE_ROW_LIMIT);
        const hasAttackIdValues = rows.some((row) => Boolean(toAnalyticsText(row.attackId)));
        const hasAttackVectorValues = rows.some((row) => Boolean(toAnalyticsText(row.attackVector)));
        const hasSourceIpValues = rows.some((row) => Boolean(toAnalyticsText(row.sourceIp)));
        const hasDestinationIpValues = rows.some((row) => Boolean(toAnalyticsText(row.destinationIp)));
        const hasSourcePortValues = rows.some((row) => Boolean(toAnalyticsText(row.sourcePort)));
        const hasDestinationPortValues = rows.some((row) => Boolean(toAnalyticsText(row.destinationPort)));
        const hasContextValues = rows.some((row) => Boolean(toAnalyticsText(row.context)));

        const columns = [
          {
            label: "Datetime",
            value: (row) => row.datetimeIso,
          },
        ];

        if (hasAttackIdValues) {
          columns.push({
            label: "Attack ID",
            value: (row) => row.attackId,
          });
        }

        if (hasAttackVectorValues) {
          columns.push({
            label: "Attack Vector",
            value: (row) => row.attackVector,
          });
        }

        if (hasSourceIpValues) {
          columns.push({
            label: "Source IP",
            value: (row) => row.sourceIp,
          });
        }

        if (hasDestinationIpValues) {
          columns.push({
            label: "Destination IP",
            value: (row) => row.destinationIp,
          });
        }

        if (hasSourcePortValues) {
          columns.push({
            label: "Source Port",
            value: (row) => row.sourcePort,
          });
        }

        if (hasDestinationPortValues) {
          columns.push({
            label: "Destination Port",
            value: (row) => row.destinationPort,
          });
        }

        if (hasContextValues) {
          columns.push({
            label: "Context",
            value: (row) => row.context,
          });
        }

        renderDataTable("ddosGraphTable", displayRows, columns);

        const target = document.getElementById("ddosGraphTable");

        if (target && rows.length > DDOS_GRAPH_TABLE_ROW_LIMIT) {
          target.innerHTML +=
            '<p class="analytics-results-note">Showing the newest ' +
            escapeHtml(formatAnalyticsNumber(DDOS_GRAPH_TABLE_ROW_LIMIT)) +
            " rows out of " +
            escapeHtml(formatAnalyticsNumber(rows.length)) +
            " returned rows.</p>";
        }
      }

      function renderDdosGraphResults(filters, rows, timelineData) {
        const datasetLabel = getDdosGraphDatasetConfig(filters.dataset).label;
        renderDdosGraphLineChart(timelineData, datasetLabel);
        renderDdosGraphMetrics(filters, rows, timelineData);
        renderDdosGraphTable(rows);
      }

      async function runDdosGraphQuery() {
        if (ddosGraphLoading) {
          return;
        }

        ddosGraphLoading = true;

        try {
          const filters = readDdosGraphFilters();
          const datasetConfig = getDdosGraphDatasetConfig(filters.dataset);
          const accountTag = await resolveGraphqlAccountId();
          const candidateFields = await loadDdosGraphDatetimeFieldCandidates(filters.dataset);
          const unknownFieldWarnings = [];
          let lastPayload = null;
          let rows = [];
          let usedDatetimeField = "";
          let lastRequestPayload = null;

          setHintMessage(ddosGraphStatus, "Running DDoS GraphQL query...");

          for (const datetimeField of candidateFields) {
            const requestPayload = buildDdosGraphRequest(filters, accountTag, datetimeField);
            lastRequestPayload = requestPayload;
            const response = await callApi("/api/graphql", {
              method: "POST",
              body: requestPayload,
              showOutput: false,
            });

            if (!response || !response.ok) {
              throw new Error(getNetworkFlowErrorMessage(response));
            }

            const graphqlErrors = Array.isArray(response.payload?.errors)
              ? response.payload.errors
              : [];

            if (graphqlErrors.length) {
              const graphQlMessage = graphqlErrors
                .map((item) => toAnalyticsText(item?.message))
                .filter(Boolean)
                .join("; ");
              const unknownFieldError = isUnknownFieldGraphQlError(graphQlMessage, datetimeField);

              if (unknownFieldError && candidateFields.length > 1) {
                unknownFieldWarnings.push(
                  "Field " + datetimeField + " is not available on this dataset's dimensions.",
                );
                continue;
              }

              throw new Error("Cloudflare GraphQL returned errors: " + (graphQlMessage || "Unknown"));
            }

            lastPayload = response.payload;
            rows = extractDdosGraphRows(filters.dataset, response.payload, datetimeField);
            usedDatetimeField = datetimeField;
            ddosGraphDatetimeFieldByDataset[filters.dataset] = datetimeField;
            break;
          }

          if (!usedDatetimeField) {
            const fallbackMessage = unknownFieldWarnings.length
              ? unknownFieldWarnings.join(" ")
              : "Unable to resolve a supported datetime field for this DDoS dataset.";
            throw new Error(fallbackMessage);
          }

          const timelineData = buildDdosGraphTimelineBuckets(rows, filters.timeRange);
          renderDdosGraphResults(filters, rows, timelineData);

          setOutput(true, "200 OK", "POST /api/graphql", {
            queryName: datasetConfig.nodeName,
            datetimeField: usedDatetimeField,
            attemptedDatetimeFields: candidateFields,
            warnings: unknownFieldWarnings,
            rowsReturned: rows.length,
            timeBuckets: timelineData.buckets.length,
            bucketInterval: timelineData.bucketConfig?.label ?? "Auto",
            filters: buildDdosGraphFilterSnapshot(
              filters,
              accountTag,
              usedDatetimeField,
              lastRequestPayload?.variables ?? {},
            ),
            data: lastPayload?.data ?? null,
          });

          if (!rows.length) {
            ddosGraphLatestSummaryMessage =
              "No " + datasetConfig.label.toLowerCase() + " rows were returned for the selected filters.";
            setHintMessage(ddosGraphStatus, ddosGraphLatestSummaryMessage, true);
            return;
          }

          ddosGraphLatestSummaryMessage =
            "Loaded " +
            formatAnalyticsNumber(rows.length) +
            " " +
            datasetConfig.label.toLowerCase() +
            " rows across " +
            formatAnalyticsNumber(timelineData.buckets.length) +
            " time buckets at " +
            (timelineData.bucketConfig?.label ?? "auto") +
            " resolution.";

          if (filters.searchTokens.length) {
            ddosGraphLatestSummaryMessage +=
              " Search matched " + filters.searchTokens.join(", ") + ".";
          }

          if (unknownFieldWarnings.length) {
            ddosGraphLatestSummaryMessage +=
              " Datetime field fallback applied: " + unknownFieldWarnings.join(" ");
          }

          setHintMessage(ddosGraphStatus, ddosGraphLatestSummaryMessage);
        } catch (error) {
          const message = error instanceof Error ? error.message : String(error);
          setHintMessage(ddosGraphStatus, message, true);
          setClientError(message);
        } finally {
          ddosGraphLoading = false;
        }
      }

      function readOverviewTunnelHealthFilters() {
        const rawValue = Number(
          document.getElementById("overviewTunnelHealthRelativeValue")?.value ?? "",
        );
        const unit = (
          document.getElementById("overviewTunnelHealthRelativeUnit")?.value ?? "minutes"
        ).toLowerCase();
        const unitMs = ANALYTICS_TIME_UNIT_TO_MS[unit];

        if (!Number.isFinite(rawValue) || rawValue < 1) {
          throw new Error("Relative range value must be a number greater than zero.");
        }

        if (!unitMs) {
          throw new Error("Relative range unit must be minutes, hours, or days.");
        }

        const nowMs = Date.now();
        const startMs = nowMs - rawValue * unitMs;

        return {
          relativeValue: rawValue,
          relativeUnit: unit,
          startMs,
          endMs: nowMs,
          startIso: new Date(startMs).toISOString(),
          endIso: new Date(nowMs).toISOString(),
          label: "Last " + rawValue + " " + unit,
        };
      }

      function buildOverviewTunnelHealthFilterSnapshot(filters, accountTag, datetimeField) {
        return {
          accountTag,
          datetimeField,
          timeRange: {
            startIso: filters.startIso,
            endIso: filters.endIso,
            label: filters.label,
            relativeValue: filters.relativeValue,
            relativeUnit: filters.relativeUnit,
          },
        };
      }

      function buildMagicTransitTunnelHealthChecksQuery(datetimeField) {
        return [
          "query GetMagicTransitTunnelHealthChecks($accountTag: string, $datetimeStart: string, $datetimeEnd: string) {",
          "  viewer {",
          "    accounts(filter: { accountTag: $accountTag }) {",
          "      magicTransitTunnelHealthChecksAdaptiveGroups(",
          "        limit: 2000,",
          "        filter: { datetime_geq: $datetimeStart, datetime_lt: $datetimeEnd }",
          "      ) {",
          "        avg {",
          "          tunnelState",
          "        }",
          "        dimensions {",
          "          tunnelName",
          "          edgeColoName",
          "          " + datetimeField,
          "        }",
          "      }",
          "    }",
          "  }",
          "}",
        ].join("\\n");
      }

      function buildMagicTransitTunnelHealthChecksRequest(filters, accountTag, datetimeField) {
        return {
          query: buildMagicTransitTunnelHealthChecksQuery(datetimeField),
          variables: {
            accountTag,
            datetimeStart: filters.startIso,
            datetimeEnd: filters.endIso,
          },
        };
      }

      async function loadTunnelHealthDatetimeFieldCandidates() {
        const fallback = [...TUNNEL_HEALTH_DATETIME_FIELD_CANDIDATES];

        if (overviewTunnelHealthDatetimeField) {
          return [
            overviewTunnelHealthDatetimeField,
            ...fallback.filter((candidate) => candidate !== overviewTunnelHealthDatetimeField),
          ];
        }

        try {
          const response = await callApi("/api/graphql", {
            method: "POST",
            body: {
              query: MAGIC_TRANSIT_TUNNEL_HEALTH_DIMENSIONS_INTROSPECTION_QUERY,
              variables: {},
            },
            showOutput: false,
            timeoutMs: 8_000,
          });

          if (!response || !response.ok) {
            return fallback;
          }

          const graphqlErrors = Array.isArray(response.payload?.errors)
            ? response.payload.errors
            : [];

          if (graphqlErrors.length) {
            return fallback;
          }

          const fields = Array.isArray(response.payload?.data?.__type?.fields)
            ? response.payload.data.__type.fields
                .map((entry) => (typeof entry?.name === "string" ? entry.name.trim() : ""))
                .filter(Boolean)
            : [];
          const datetimeFields = fields.filter((field) =>
            field.toLowerCase().startsWith("datetime"),
          );

          if (!datetimeFields.length) {
            return fallback;
          }

          const ordered = [
            ...fallback.filter((candidate) => datetimeFields.includes(candidate)),
            ...datetimeFields,
            ...fallback,
          ];
          const deduped = [];

          for (const field of ordered) {
            if (!deduped.includes(field)) {
              deduped.push(field);
            }
          }

          return deduped;
        } catch {
          return fallback;
        }
      }

      function isUnknownFieldGraphQlError(message, fieldName) {
        const lower = String(message).toLowerCase();
        return lower.includes("cannot query field") && lower.includes(String(fieldName).toLowerCase());
      }

      function extractMagicTransitTunnelHealthRows(payload, datetimeField) {
        const accounts = Array.isArray(payload?.data?.viewer?.accounts)
          ? payload.data.viewer.accounts
          : [];
        const rows = [];

        for (const account of accounts) {
          const groups = Array.isArray(account?.magicTransitTunnelHealthChecksAdaptiveGroups)
            ? account.magicTransitTunnelHealthChecksAdaptiveGroups
            : [];

          for (const group of groups) {
            const tunnelName = toAnalyticsText(group?.dimensions?.tunnelName) || "Unknown";
            const edgeColoName = toAnalyticsText(group?.dimensions?.edgeColoName) || "";
            const datetimeIso = toAnalyticsText(group?.dimensions?.[datetimeField]);
            const timestampMsRaw = Date.parse(datetimeIso);
            const tunnelStateRaw = Number(group?.avg?.tunnelState);
            const tunnelState = Number.isFinite(tunnelStateRaw)
              ? Math.max(0, Math.min(1, tunnelStateRaw))
              : 0;

            rows.push({
              tunnelName,
              edgeColoName,
              datetimeIso,
              timestampMs: Number.isFinite(timestampMsRaw) ? timestampMsRaw : null,
              tunnelState,
            });
          }
        }

        return rows.sort((left, right) => {
          const leftMs = left.timestampMs ?? 0;
          const rightMs = right.timestampMs ?? 0;

          if (leftMs !== rightMs) {
            return leftMs - rightMs;
          }

          return left.tunnelName.localeCompare(right.tunnelName);
        });
      }

      function buildTunnelHealthTimelineBuckets(rows) {
        const aggregateByTimestamp = new Map();

        for (const row of rows) {
          const tunnelName = toAnalyticsText(row.tunnelName) || "Unknown";
          const datetimeIso = toAnalyticsText(row.datetimeIso);
          const timestampMs = Number.isFinite(row.timestampMs)
            ? row.timestampMs
            : Date.parse(datetimeIso);
          const bucketKey = datetimeIso || (Number.isFinite(timestampMs) ? String(timestampMs) : "");

          if (!bucketKey) {
            continue;
          }

          const existing = aggregateByTimestamp.get(bucketKey) ?? {
            timestampMs: Number.isFinite(timestampMs) ? timestampMs : null,
            datetimeIso: datetimeIso || "",
            perTunnelStateTotals: new Map(),
          };
          const tunnelAggregate = existing.perTunnelStateTotals.get(tunnelName) ?? {
            totalState: 0,
            sampleCount: 0,
          };

          tunnelAggregate.totalState += Number.isFinite(row.tunnelState) ? row.tunnelState : 0;
          tunnelAggregate.sampleCount += 1;
          existing.perTunnelStateTotals.set(tunnelName, tunnelAggregate);

          if (existing.timestampMs === null && Number.isFinite(timestampMs)) {
            existing.timestampMs = timestampMs;
          }

          if (!existing.datetimeIso && datetimeIso) {
            existing.datetimeIso = datetimeIso;
          }

          aggregateByTimestamp.set(bucketKey, existing);
        }

        return [...aggregateByTimestamp.values()]
          .map((bucket) => {
            const perTunnelState = new Map();

            for (const [tunnelName, aggregate] of bucket.perTunnelStateTotals.entries()) {
              const sampleCount = aggregate.sampleCount > 0 ? aggregate.sampleCount : 1;
              perTunnelState.set(tunnelName, aggregate.totalState / sampleCount);
            }

            return {
              timestampMs: bucket.timestampMs,
              datetimeIso: bucket.datetimeIso,
              perTunnelState,
            };
          })
          .sort((left, right) => {
            const leftMs = left.timestampMs ?? 0;
            const rightMs = right.timestampMs ?? 0;

            if (leftMs !== rightMs) {
              return leftMs - rightMs;
            }

            return String(left.datetimeIso).localeCompare(String(right.datetimeIso));
          });
      }

      function buildTunnelHealthTunnelNames(rows) {
        const aggregateByTunnel = new Map();

        for (const row of rows) {
          const tunnelName = toAnalyticsText(row.tunnelName) || "Unknown";
          const existing = aggregateByTunnel.get(tunnelName) ?? {
            totalState: 0,
            sampleCount: 0,
          };

          existing.totalState += Number.isFinite(row.tunnelState) ? row.tunnelState : 0;
          existing.sampleCount += 1;
          aggregateByTunnel.set(tunnelName, existing);
        }

        return [...aggregateByTunnel.entries()]
          .map(([name, aggregate]) => {
            const sampleCount = aggregate.sampleCount > 0 ? aggregate.sampleCount : 1;
            return {
              name,
              avgState: aggregate.totalState / sampleCount,
            };
          })
          .sort((left, right) => {
            if (right.avgState !== left.avgState) {
              return right.avgState - left.avgState;
            }

            return left.name.localeCompare(right.name);
          })
          .map((entry) => entry.name);
      }

      function buildTunnelHealthSeriesValues(timelineBuckets, tunnelName) {
        let priorValue = 0;

        return timelineBuckets.map((bucket) => {
          const raw = bucket.perTunnelState.get(tunnelName);

          if (Number.isFinite(raw)) {
            priorValue = Math.max(0, Math.min(1, raw));
          }

          return priorValue;
        });
      }

      function formatTunnelHealthPercentage(value) {
        const normalized = Number.isFinite(value) ? Math.max(0, Math.min(1, value)) : 0;
        const percentage = normalized * 100;

        if (Number.isInteger(percentage)) {
          return percentage.toFixed(0) + "%";
        }

        return percentage.toFixed(1) + "%";
      }

      function buildTunnelHealthSummaryEntries(rows, timelineBuckets) {
        const aggregateByTunnel = new Map();

        for (const row of rows) {
          const tunnelName = toAnalyticsText(row.tunnelName) || "Unknown";
          const state = Number.isFinite(row.tunnelState) ? Math.max(0, Math.min(1, row.tunnelState)) : 0;
          const existing = aggregateByTunnel.get(tunnelName) ?? {
            tunnelName,
            totalState: 0,
            sampleCount: 0,
            latestHealth: null,
            latestTimestampMs: null,
          };

          existing.totalState += state;
          existing.sampleCount += 1;
          aggregateByTunnel.set(tunnelName, existing);
        }

        for (const bucket of timelineBuckets) {
          const bucketTimestampMs = Number.isFinite(bucket.timestampMs)
            ? bucket.timestampMs
            : Date.parse(bucket.datetimeIso);

          for (const [tunnelName, state] of bucket.perTunnelState.entries()) {
            const normalizedState = Number.isFinite(state) ? Math.max(0, Math.min(1, state)) : 0;
            const existing = aggregateByTunnel.get(tunnelName) ?? {
              tunnelName,
              totalState: 0,
              sampleCount: 0,
              latestHealth: null,
              latestTimestampMs: null,
            };

            if (
              existing.latestTimestampMs === null ||
              (Number.isFinite(bucketTimestampMs) && bucketTimestampMs >= existing.latestTimestampMs)
            ) {
              existing.latestHealth = normalizedState;

              if (Number.isFinite(bucketTimestampMs)) {
                existing.latestTimestampMs = bucketTimestampMs;
              }
            } else if (existing.latestHealth === null) {
              existing.latestHealth = normalizedState;
            }

            aggregateByTunnel.set(tunnelName, existing);
          }
        }

        return [...aggregateByTunnel.values()]
          .map((entry) => {
            const sampleCount = entry.sampleCount > 0 ? entry.sampleCount : 1;
            const averageHealth = entry.totalState / sampleCount;

            return {
              tunnelName: entry.tunnelName,
              averageHealth,
              latestHealth:
                entry.latestHealth === null ? averageHealth : Math.max(0, Math.min(1, entry.latestHealth)),
            };
          })
          .sort((left, right) => {
            if (right.averageHealth !== left.averageHealth) {
              return right.averageHealth - left.averageHealth;
            }

            return left.tunnelName.localeCompare(right.tunnelName);
          });
      }

      function renderOverviewTunnelHealthSummaryTable(summaryEntries) {
        const target = document.getElementById("overviewTunnelHealthTable");

        if (!target) {
          return;
        }

        if (!summaryEntries.length) {
          target.innerHTML =
            '<p class="hint">No tunnel health rows are available for summary in the selected range.</p>';
          return;
        }

        renderDataTable("overviewTunnelHealthTable", summaryEntries, [
          {
            label: "Tunnel",
            value: (entry) => entry.tunnelName,
          },
          {
            label: "Average Health",
            value: (entry) => formatTunnelHealthPercentage(entry.averageHealth),
          },
          {
            label: "Latest Health",
            value: (entry) => formatTunnelHealthPercentage(entry.latestHealth),
          },
        ]);
      }

      function buildGraphqlTypeInspectionQuery(typeName) {
        const typeLiteral = JSON.stringify(typeName);

        return [
          "query InspectType {",
          "  __type(name: " + typeLiteral + ") {",
          "    name",
          "    kind",
          "    fields {",
          "      name",
          "    }",
          "    inputFields {",
          "      name",
          "    }",
          "    enumValues {",
          "      name",
          "    }",
          "  }",
          "}",
        ].join("\\n");
      }

      function readGraphqlSchemaTypeName() {
        return (document.getElementById("graphqlSchemaTypeName")?.value ?? "").trim();
      }

      function buildGraphqlSchemaExplorerPresetDefinition(presetValue) {
        const currentTypeName = readGraphqlSchemaTypeName();

        if (presetValue === "query-root") {
          return {
            typeName: currentTypeName || "Account",
            query: [
              "query GetQueryRootFields {",
              "  __schema {",
              "    queryType {",
              "      fields {",
              "        name",
              "      }",
              "    }",
              "  }",
              "}",
            ].join("\\n"),
            variables: {},
            message: "Loaded Query root fields preset.",
          };
        }

        if (presetValue === "account-fields") {
          return {
            typeName: "Account",
            query: buildGraphqlTypeInspectionQuery("Account"),
            variables: {},
            message: "Loaded Account fields preset.",
          };
        }

        if (presetValue === "health-check-dimensions") {
          return {
            typeName: "AccountMagicTransitTunnelHealthChecksAdaptiveGroupsDimensions",
            query: buildGraphqlTypeInspectionQuery(
              "AccountMagicTransitTunnelHealthChecksAdaptiveGroupsDimensions",
            ),
            variables: {},
            message: "Loaded tunnel health dimensions preset.",
          };
        }

        const typeName = currentTypeName || "Account";

        return {
          typeName,
          query: buildGraphqlTypeInspectionQuery(typeName),
          variables: {},
          message: 'Loaded type inspection preset for "' + typeName + '".',
        };
      }

      function renderGraphqlSchemaExplorerResults(payload) {
        const target = document.getElementById("graphqlSchemaResults");

        if (!target) {
          return;
        }

        if (typeof payload === "string") {
          target.textContent = payload;
          return;
        }

        target.textContent = JSON.stringify(payload, null, 2);
      }

      function applyGraphqlSchemaExplorerPreset() {
        const presetInput = document.getElementById("graphqlSchemaPreset");
        const typeNameInput = document.getElementById("graphqlSchemaTypeName");
        const queryInput = document.getElementById("graphqlSchemaQuery");
        const variablesInput = document.getElementById("graphqlSchemaVariables");

        if (!presetInput || !typeNameInput || !queryInput || !variablesInput) {
          return;
        }

        const preset = buildGraphqlSchemaExplorerPresetDefinition(presetInput.value);
        typeNameInput.value = preset.typeName;
        queryInput.value = preset.query;
        variablesInput.value = JSON.stringify(preset.variables, null, 2);
        renderGraphqlSchemaExplorerResults("Run the preset query to view schema results.");
        setHintMessage(graphqlSchemaStatus, preset.message);
      }

      async function runGraphqlSchemaExplorerQuery() {
        if (graphqlSchemaExplorerLoading) {
          return;
        }

        graphqlSchemaExplorerLoading = true;

        try {
          const query = (document.getElementById("graphqlSchemaQuery")?.value ?? "").trim();

          if (!query) {
            throw new Error("GraphQL query is required.");
          }

          const variables = readJsonInput("graphqlSchemaVariables");

          setHintMessage(graphqlSchemaStatus, "Running GraphQL schema explorer query...");

          const response = await callApi("/api/graphql", {
            method: "POST",
            body: {
              query,
              variables,
            },
            showOutput: false,
          });

          renderGraphqlSchemaExplorerResults(response?.payload ?? { error: "No response payload returned." });

          if (!response || !response.ok) {
            const message = getNetworkFlowErrorMessage(response);
            const status = response
              ? response.status + " " + response.statusText
              : "Network error";

            setOutput(false, status, "POST /api/graphql", response?.payload ?? { error: message });
            setHintMessage(graphqlSchemaStatus, message, true);
            return;
          }

          const graphqlErrors = Array.isArray(response.payload?.errors)
            ? response.payload.errors
            : [];
          const ok = graphqlErrors.length === 0;

          setOutput(ok, response.status + " " + response.statusText, "POST /api/graphql", response.payload);

          if (!ok) {
            const graphQlMessage = graphqlErrors
              .map((item) => toAnalyticsText(item?.message))
              .filter(Boolean)
              .join("; ");

            setHintMessage(
              graphqlSchemaStatus,
              "GraphQL returned errors: " + (graphQlMessage || "Unknown"),
              true,
            );
            return;
          }

          const topLevelKeys =
            response.payload?.data && typeof response.payload.data === "object"
              ? Object.keys(response.payload.data)
              : [];
          const summary = topLevelKeys.length
            ? "Loaded schema response with top-level keys: " + topLevelKeys.join(", ") + "."
            : "Loaded schema response.";

          setHintMessage(graphqlSchemaStatus, summary);
        } catch (error) {
          const message = error instanceof Error ? error.message : String(error);
          setHintMessage(graphqlSchemaStatus, message, true);
          setClientError(message);
        } finally {
          graphqlSchemaExplorerLoading = false;
        }
      }

      function renderOverviewTunnelHealthChart(timelineBuckets, tunnelNames) {
        const target = document.getElementById("overviewTunnelHealthChart");

        if (!target) {
          return;
        }

        if (!timelineBuckets.length || !tunnelNames.length) {
          target.innerHTML =
            '<p class="hint">No tunnel health check points are available for charting in the selected range.</p>';
          return;
        }

        const seriesCollection = tunnelNames.map((tunnelName, index) => ({
          label: tunnelName,
          color: API_TUNNEL_SERIES_COLORS[index % API_TUNNEL_SERIES_COLORS.length],
          strokeWidth: 1.8,
          values: buildTunnelHealthSeriesValues(timelineBuckets, tunnelName),
        }));
        const chartWidth = 1200;
        const chartHeight = 340;
        const margin = {
          top: 14,
          right: 16,
          bottom: 52,
          left: 112,
        };
        const plotWidth = chartWidth - margin.left - margin.right;
        const plotHeight = chartHeight - margin.top - margin.bottom;
        const pointCount = timelineBuckets.length;
        const yTicks = [
          { value: 1, label: "100%" },
          { value: 0.5, label: "50%" },
          { value: 0, label: "0%" },
        ];

        const computeX = (index) => {
          if (pointCount <= 1) {
            return margin.left + plotWidth / 2;
          }

          return margin.left + (index / (pointCount - 1)) * plotWidth;
        };

        const computeY = (value) => {
          const numeric = Number.isFinite(value) ? Math.max(0, Math.min(1, value)) : 0;
          return margin.top + (1 - numeric) * plotHeight;
        };

        const gridAndYLabelHtml = yTicks
          .map((tick) => {
            const y = computeY(tick.value);

            return (
              '<line x1="' +
              margin.left.toFixed(2) +
              '" y1="' +
              y.toFixed(2) +
              '" x2="' +
              (margin.left + plotWidth).toFixed(2) +
              '" y2="' +
              y.toFixed(2) +
              '" stroke="rgba(255, 255, 255, 0.12)" stroke-width="1" />' +
              '<text x="' +
              (margin.left - 10).toFixed(2) +
              '" y="' +
              (y + 4).toFixed(2) +
              '" fill="rgba(255, 215, 179, 0.75)" font-size="11" text-anchor="end">' +
              escapeHtml(tick.label) +
              "</text>"
            );
          })
          .join("");

        const xTickIndexes = buildApiLineChartTickIndexes(pointCount, 7);
        const xTickHtml = xTickIndexes
          .map((index) => {
            const x = computeX(index);
            const bucket = timelineBuckets[index];
            const label = formatTunnelBandwidthTimelineLabel(bucket.timestampMs, bucket.datetimeIso);

            return (
              '<line x1="' +
              x.toFixed(2) +
              '" y1="' +
              (margin.top + plotHeight).toFixed(2) +
              '" x2="' +
              x.toFixed(2) +
              '" y2="' +
              (margin.top + plotHeight + 4).toFixed(2) +
              '" stroke="rgba(255, 255, 255, 0.25)" stroke-width="1" />' +
              '<text x="' +
              x.toFixed(2) +
              '" y="' +
              (margin.top + plotHeight + 18).toFixed(2) +
              '" fill="rgba(255, 215, 179, 0.75)" font-size="11" text-anchor="middle">' +
              escapeHtml(label) +
              "</text>"
            );
          })
          .join("");

        const polylineHtml = seriesCollection
          .map((series) => {
            const points = series.values
              .map((value, index) => computeX(index).toFixed(2) + "," + computeY(value).toFixed(2))
              .join(" ");

            return (
              '<polyline points="' +
              points +
              '" fill="none" stroke="' +
              escapeHtml(series.color) +
              '" stroke-width="' +
              series.strokeWidth.toFixed(2) +
              '" stroke-linejoin="round" stroke-linecap="round" />'
            );
          })
          .join("");

        const legendHtml = seriesCollection
          .map(
            (series) =>
              '<span class="api-line-chart-legend-item"><span class="api-tunnel-swatch" style="background:' +
              escapeHtml(series.color) +
              '"></span>' +
              escapeHtml(series.label) +
              "</span>",
          )
          .join("");

        target.innerHTML =
          '<div class="api-line-chart"><svg viewBox="0 0 ' +
          chartWidth +
          " " +
          chartHeight +
          '" role="img" aria-label="Tunnel health status over time">' +
          '<rect x="' +
          margin.left.toFixed(2) +
          '" y="' +
          margin.top.toFixed(2) +
          '" width="' +
          plotWidth.toFixed(2) +
          '" height="' +
          plotHeight.toFixed(2) +
          '" fill="rgba(0, 0, 0, 0.08)" />' +
          gridAndYLabelHtml +
          '<line x1="' +
          margin.left.toFixed(2) +
          '" y1="' +
          margin.top.toFixed(2) +
          '" x2="' +
          margin.left.toFixed(2) +
          '" y2="' +
          (margin.top + plotHeight).toFixed(2) +
          '" stroke="rgba(255, 255, 255, 0.38)" stroke-width="1" />' +
          '<line x1="' +
          margin.left.toFixed(2) +
          '" y1="' +
          (margin.top + plotHeight).toFixed(2) +
          '" x2="' +
          (margin.left + plotWidth).toFixed(2) +
          '" y2="' +
          (margin.top + plotHeight).toFixed(2) +
          '" stroke="rgba(255, 255, 255, 0.38)" stroke-width="1" />' +
          xTickHtml +
          polylineHtml +
          "</svg><div class='api-line-chart-legend'>" +
          legendHtml +
          "</div></div>";
      }

      async function runOverviewTunnelHealthQuery() {
        if (overviewTunnelHealthLoading) {
          return;
        }

        overviewTunnelHealthLoading = true;

        try {
          const filters = readOverviewTunnelHealthFilters();
          const accountTag = await resolveGraphqlAccountId();
          const candidateFields = await loadTunnelHealthDatetimeFieldCandidates();
          const unknownFieldWarnings = [];
          let lastPayload = null;
          let usedDatetimeField = "";
          let rows = [];

          setHintMessage(overviewTunnelHealthStatus, "Running tunnel health checks GraphQL query...");

          for (const datetimeField of candidateFields) {
            const requestPayload = buildMagicTransitTunnelHealthChecksRequest(
              filters,
              accountTag,
              datetimeField,
            );
            const response = await callApi("/api/graphql", {
              method: "POST",
              body: requestPayload,
              showOutput: false,
            });

            if (!response || !response.ok) {
              throw new Error(getNetworkFlowErrorMessage(response));
            }

            const graphqlErrors = Array.isArray(response.payload?.errors)
              ? response.payload.errors
              : [];

            if (graphqlErrors.length) {
              const graphQlMessage = graphqlErrors
                .map((item) => toAnalyticsText(item?.message))
                .filter(Boolean)
                .join("; ");
              const unknownFieldError = isUnknownFieldGraphQlError(graphQlMessage, datetimeField);

              if (unknownFieldError && candidateFields.length > 1) {
                unknownFieldWarnings.push(
                  "Field " +
                    datetimeField +
                    " is not available on this account's health check dimensions.",
                );
                continue;
              }

              throw new Error("Cloudflare GraphQL returned errors: " + (graphQlMessage || "Unknown"));
            }

            lastPayload = response.payload;
            rows = extractMagicTransitTunnelHealthRows(response.payload, datetimeField);
            usedDatetimeField = datetimeField;
            overviewTunnelHealthDatetimeField = datetimeField;
            break;
          }

          if (!usedDatetimeField) {
            const fallbackMessage = unknownFieldWarnings.length
              ? unknownFieldWarnings.join(" ")
              : "Unable to resolve a supported datetime field for tunnel health checks.";
            throw new Error(fallbackMessage);
          }

          overviewTunnelHealthTimelineBuckets = buildTunnelHealthTimelineBuckets(rows);
          overviewTunnelHealthTunnelNames = buildTunnelHealthTunnelNames(rows);
          const overviewTunnelHealthSummaryEntries = buildTunnelHealthSummaryEntries(
            rows,
            overviewTunnelHealthTimelineBuckets,
          );
          renderOverviewTunnelHealthChart(
            overviewTunnelHealthTimelineBuckets,
            overviewTunnelHealthTunnelNames,
          );
          renderOverviewTunnelHealthSummaryTable(overviewTunnelHealthSummaryEntries);

          const filterSnapshot = buildOverviewTunnelHealthFilterSnapshot(
            filters,
            accountTag,
            usedDatetimeField,
          );

          setOutput(true, "200 OK", "POST /api/graphql", {
            queryName: "GetMagicTransitTunnelHealthChecks",
            datetimeField: usedDatetimeField,
            attemptedDatetimeFields: candidateFields,
            warnings: unknownFieldWarnings,
            tunnelDataPoints: rows.length,
            timeBuckets: overviewTunnelHealthTimelineBuckets.length,
            tunnels: overviewTunnelHealthTunnelNames.length,
            summaryTunnels: overviewTunnelHealthSummaryEntries.length,
            filters: filterSnapshot,
            data: lastPayload?.data ?? null,
          });

          if (!rows.length || !overviewTunnelHealthTimelineBuckets.length) {
            overviewTunnelHealthLatestSummaryMessage =
              "No tunnel health rows were returned for the selected time window.";
            setHintMessage(
              overviewTunnelHealthStatus,
              overviewTunnelHealthLatestSummaryMessage,
              true,
            );
            return;
          }

          overviewTunnelHealthLatestSummaryMessage =
            "Loaded " +
            formatAnalyticsNumber(overviewTunnelHealthTimelineBuckets.length) +
            " timeline points across " +
            formatAnalyticsNumber(overviewTunnelHealthTunnelNames.length) +
            " tunnels from " +
            formatAnalyticsNumber(rows.length) +
            " health samples.";

          if (unknownFieldWarnings.length) {
            overviewTunnelHealthLatestSummaryMessage +=
              " Datetime field fallback applied: " + unknownFieldWarnings.join(" ");
          }

          setHintMessage(overviewTunnelHealthStatus, overviewTunnelHealthLatestSummaryMessage);
        } catch (error) {
          const message = error instanceof Error ? error.message : String(error);
          setHintMessage(overviewTunnelHealthStatus, message, true);
          setClientError(message);
        } finally {
          overviewTunnelHealthLoading = false;
        }
      }

      async function resolveGraphqlAccountId() {
        const existingAccountId = (envAccountId?.textContent ?? "").trim();

        if (
          existingAccountId &&
          !existingAccountId.startsWith("(") &&
          !existingAccountId.toLowerCase().startsWith("loading") &&
          !existingAccountId.toLowerCase().startsWith("failed")
        ) {
          return existingAccountId;
        }

        const configResponse = await callApi("/api/config", {
          showOutput: false,
          timeoutMs: 8_000,
        });

        if (
          !configResponse ||
          !configResponse.ok ||
          !configResponse.payload ||
          typeof configResponse.payload !== "object" ||
          Array.isArray(configResponse.payload)
        ) {
          throw new Error("Unable to resolve the Account ID for the GraphQL query.");
        }

        const accountId =
          typeof configResponse.payload.accountId === "string"
            ? configResponse.payload.accountId.trim()
            : "";

        if (!accountId) {
          throw new Error("Account ID is unavailable. Set ACCOUNT_ID.");
        }

        envAccountId.textContent = accountId;
        return accountId;
      }

      function initializeApiAnalyticsDefaults() {
        const directionInput = document.getElementById("apiDirectionInput");
        const relativeValueInput = document.getElementById("apiRelativeValue");
        const relativeUnitInput = document.getElementById("apiRelativeUnit");

        if (directionInput) {
          directionInput.value = "ingress";
        }

        if (relativeValueInput) {
          relativeValueInput.value = "60";
        }

        if (relativeUnitInput) {
          relativeUnitInput.value = "minutes";
        }
      }

      function initializeGraphqlSchemaExplorerDefaults() {
        const presetInput = document.getElementById("graphqlSchemaPreset");
        const typeNameInput = document.getElementById("graphqlSchemaTypeName");
        const variablesInput = document.getElementById("graphqlSchemaVariables");

        if (presetInput) {
          presetInput.value = "query-root";
        }

        if (typeNameInput) {
          typeNameInput.value = "Account";
        }

        if (variablesInput) {
          variablesInput.value = "{}";
        }

        applyGraphqlSchemaExplorerPreset();
      }

      function initializeOverviewTunnelHealthDefaults() {
        const relativeValueInput = document.getElementById("overviewTunnelHealthRelativeValue");
        const relativeUnitInput = document.getElementById("overviewTunnelHealthRelativeUnit");

        if (relativeValueInput) {
          relativeValueInput.value = "60";
        }

        if (relativeUnitInput) {
          relativeUnitInput.value = "minutes";
        }
      }

      function buildMagicTransitTunnelBandwidthRequest(filters, accountTag) {
        return {
          query: MAGIC_TRANSIT_TUNNEL_BANDWIDTH_QUERY,
          variables: {
            accountTag,
            direction: filters.direction,
            datetimeStart: filters.timeRange.startIso,
            datetimeEnd: filters.timeRange.endIso,
          },
        };
      }

      function extractMagicTransitTunnelBandwidthRows(payload) {
        const accounts = Array.isArray(payload?.data?.viewer?.accounts)
          ? payload.data.viewer.accounts
          : [];
        const rows = [];

        for (const account of accounts) {
          const groups = Array.isArray(account?.magicTransitTunnelTrafficAdaptiveGroups)
            ? account.magicTransitTunnelTrafficAdaptiveGroups
            : [];

          for (const group of groups) {
            const tunnelName = toAnalyticsText(group?.dimensions?.tunnelName) || "Unknown";
            const datetimeIso = toAnalyticsText(group?.dimensions?.datetimeFiveMinutes);
            const timestampMsRaw = Date.parse(datetimeIso);
            const bitRateRaw = Number(group?.avg?.bitRateFiveMinutes);

            rows.push({
              tunnelName,
              datetimeIso,
              timestampMs: Number.isFinite(timestampMsRaw) ? timestampMsRaw : null,
              bitRateBps: Number.isFinite(bitRateRaw) ? bitRateRaw : 0,
            });
          }
        }

        return rows.sort((left, right) => {
          const leftMs = left.timestampMs ?? 0;
          const rightMs = right.timestampMs ?? 0;

          if (rightMs !== leftMs) {
            return rightMs - leftMs;
          }

          if (right.bitRateBps !== left.bitRateBps) {
            return right.bitRateBps - left.bitRateBps;
          }

          return left.tunnelName.localeCompare(right.tunnelName);
        });
      }

      function formatTunnelBandwidthBitsPerSecond(value) {
        const numeric = Number(value);

        if (!Number.isFinite(numeric) || numeric < 0) {
          return "—";
        }

        return formatAnalyticsCompactNumber(numeric) + " bps";
      }

      function formatTunnelBandwidthMegabitsPerSecond(value) {
        const numeric = Number(value);

        if (!Number.isFinite(numeric) || numeric < 0) {
          return "—";
        }

        return (numeric / 1_000_000).toFixed(3);
      }

      function buildTunnelBandwidthEntries(rows) {
        const aggregateByTunnel = new Map();

        for (const row of rows) {
          const tunnelName = row.tunnelName || "Unknown";
          const nextValue = Number.isFinite(row.bitRateBps) && row.bitRateBps > 0 ? row.bitRateBps : 0;
          const existing = aggregateByTunnel.get(tunnelName) ?? {
            totalBitRateBps: 0,
            sampleCount: 0,
          };

          existing.totalBitRateBps += nextValue;
          existing.sampleCount += 1;
          aggregateByTunnel.set(tunnelName, existing);
        }

        return [...aggregateByTunnel.entries()]
          .map(([label, aggregate]) => {
            const sampleCount = aggregate.sampleCount > 0 ? aggregate.sampleCount : 1;

            return {
              label,
              value: aggregate.totalBitRateBps / sampleCount,
            };
          })
          .sort((left, right) => {
            if (right.value !== left.value) {
              return right.value - left.value;
            }

            return left.label.localeCompare(right.label);
          });
      }

      async function loadMagicTransitTunnelInventoryNames() {
        const tunnelNames = new Set();
        const warnings = [];
        const endpoints = [
          { label: "GRE", path: "/api/magic/gre_tunnels" },
          { label: "IPSEC", path: "/api/magic/ipsec_tunnels" },
        ];

        const responses = await Promise.all(
          endpoints.map((entry) =>
            callApi(entry.path, {
              showOutput: false,
              timeoutMs: 8_000,
            }),
          ),
        );

        for (const [index, response] of responses.entries()) {
          const endpoint = endpoints[index];

          if (!response || !response.ok) {
            warnings.push(
              endpoint.label +
                " tunnel inventory could not be loaded: " +
                getNetworkFlowErrorMessage(response),
            );
            continue;
          }

          const rows = extractResultArray(response.payload);

          for (const row of rows) {
            const tunnelName = toAnalyticsText(row?.name);

            if (tunnelName) {
              tunnelNames.add(tunnelName);
            }
          }
        }

        return {
          tunnelNames: [...tunnelNames].sort((left, right) => left.localeCompare(right)),
          warnings,
        };
      }

      function buildTunnelEntryKey(value) {
        return String(value ?? "").trim().toLowerCase();
      }

      function mergeTunnelEntriesWithInventory(tunnelEntries, inventoryTunnelNames) {
        const mergedEntriesByKey = new Map();

        for (const entry of tunnelEntries) {
          const key = buildTunnelEntryKey(entry?.label);

          if (!key) {
            continue;
          }

          mergedEntriesByKey.set(key, {
            label: String(entry.label),
            value: Number.isFinite(entry.value) && entry.value > 0 ? entry.value : 0,
          });
        }

        for (const name of inventoryTunnelNames) {
          const key = buildTunnelEntryKey(name);

          if (!key || mergedEntriesByKey.has(key)) {
            continue;
          }

          mergedEntriesByKey.set(key, {
            label: String(name),
            value: 0,
          });
        }

        return [...mergedEntriesByKey.values()].sort((left, right) => {
          if (right.value !== left.value) {
            return right.value - left.value;
          }

          return left.label.localeCompare(right.label);
        });
      }

      function formatTunnelBandwidthTimelineLabel(timestampMs, datetimeIso) {
        if (Number.isFinite(timestampMs)) {
          return new Date(timestampMs).toLocaleString([], {
            month: "2-digit",
            day: "2-digit",
            hour: "2-digit",
            minute: "2-digit",
          });
        }

        return datetimeIso || "Unknown";
      }

      function buildTunnelBandwidthTimelineBuckets(rows) {
        const aggregateByTimestamp = new Map();

        for (const row of rows) {
          const tunnelName = toAnalyticsText(row.tunnelName) || "Unknown";
          const datetimeIso = toAnalyticsText(row.datetimeIso);
          const timestampMs = Number.isFinite(row.timestampMs)
            ? row.timestampMs
            : Date.parse(datetimeIso);
          const bucketKey = datetimeIso || (Number.isFinite(timestampMs) ? String(timestampMs) : "");

          if (!bucketKey) {
            continue;
          }

          const nextValue = Number.isFinite(row.bitRateBps) && row.bitRateBps > 0 ? row.bitRateBps : 0;
          const existing = aggregateByTimestamp.get(bucketKey) ?? {
            timestampMs: Number.isFinite(timestampMs) ? timestampMs : null,
            datetimeIso: datetimeIso || "",
            aggregateBitRateBps: 0,
            perTunnelBitRateBps: new Map(),
          };

          existing.aggregateBitRateBps += nextValue;
          existing.perTunnelBitRateBps.set(
            tunnelName,
            (existing.perTunnelBitRateBps.get(tunnelName) ?? 0) + nextValue,
          );

          if (existing.timestampMs === null && Number.isFinite(timestampMs)) {
            existing.timestampMs = timestampMs;
          }

          if (!existing.datetimeIso && datetimeIso) {
            existing.datetimeIso = datetimeIso;
          }

          aggregateByTimestamp.set(bucketKey, existing);
        }

        return [...aggregateByTimestamp.values()]
          .sort((left, right) => {
            const leftMs = left.timestampMs ?? 0;
            const rightMs = right.timestampMs ?? 0;

            if (leftMs !== rightMs) {
              return leftMs - rightMs;
            }

            return String(left.datetimeIso).localeCompare(String(right.datetimeIso));
          });
      }

      function selectApiTunnelNames(tunnelEntries, previousSelection = []) {
        const availableNames = tunnelEntries.map((entry) => entry.label);
        const availableNameSet = new Set(availableNames);
        const selected = [];

        for (const tunnelName of previousSelection) {
          if (!availableNameSet.has(tunnelName)) {
            continue;
          }

          if (selected.includes(tunnelName)) {
            continue;
          }

          selected.push(tunnelName);

          if (selected.length >= API_MAX_TUNNEL_SERIES) {
            break;
          }
        }

        if (!selected.length) {
          for (const tunnelName of availableNames) {
            selected.push(tunnelName);

            if (selected.length >= API_MAX_TUNNEL_SERIES) {
              break;
            }
          }
        }

        return selected;
      }

      function buildApiTunnelColorMap(selectedTunnelNames) {
        const colorMap = new Map();

        selectedTunnelNames.forEach((tunnelName, index) => {
          colorMap.set(tunnelName, API_TUNNEL_SERIES_COLORS[index % API_TUNNEL_SERIES_COLORS.length]);
        });

        return colorMap;
      }

      function renderApiTunnelSeriesSelector(tunnelEntries, selectedTunnelNames) {
        const target = document.getElementById("apiTunnelSeriesSelector");

        if (!target) {
          return;
        }

        if (!tunnelEntries.length) {
          target.innerHTML =
            '<p class="hint">Run a query to select tunnel lines (up to 10).</p>';
          return;
        }

        const selectedSet = new Set(selectedTunnelNames);
        const colorMap = buildApiTunnelColorMap(selectedTunnelNames);
        const disableUncheckedInputs = selectedSet.size >= API_MAX_TUNNEL_SERIES;

        const optionHtml = tunnelEntries
          .map((entry) => {
            const tunnelName = entry.label;
            const isSelected = selectedSet.has(tunnelName);
            const disabled = disableUncheckedInputs && !isSelected;
            const swatchColor = colorMap.get(tunnelName) || "rgba(122, 74, 36, 0.5)";

            return (
              '<label class="api-tunnel-option' +
              (disabled ? " disabled" : "") +
              '"><input type="checkbox" data-action="toggle-api-tunnel-series" value="' +
              escapeHtml(tunnelName) +
              '"' +
              (isSelected ? " checked" : "") +
              (disabled ? " disabled" : "") +
              ' /><span class="api-tunnel-swatch" style="background:' +
              escapeHtml(swatchColor) +
              '"></span><span>' +
              escapeHtml(tunnelName) +
              "</span></label>"
            );
          })
          .join("");

        target.innerHTML =
          '<p class="hint">Select up to 10 tunnel lines. Aggregate line is always shown. IPSEC/GRE tunnels with no sampled traffic are shown at zero.</p><div class="api-tunnel-selector-list">' +
          optionHtml +
          "</div>";
      }

      function buildApiLineChartTickIndexes(pointCount, maxTicks) {
        if (pointCount <= 0) {
          return [];
        }

        if (pointCount <= maxTicks) {
          return Array.from({ length: pointCount }, (_, index) => index);
        }

        const indexes = new Set([0, pointCount - 1]);
        const step = (pointCount - 1) / (maxTicks - 1);

        for (let index = 1; index < maxTicks - 1; index += 1) {
          indexes.add(Math.round(index * step));
        }

        return [...indexes].sort((left, right) => left - right);
      }

      function renderApiTunnelLineChart(timelineBuckets, selectedTunnelNames) {
        const target = document.getElementById("apiTunnelBandwidthChart");

        if (!target) {
          return;
        }

        if (!timelineBuckets.length) {
          target.innerHTML =
            '<p class="hint">No five-minute tunnel bandwidth points are available for charting.</p>';
          return;
        }

        const selectedColorMap = buildApiTunnelColorMap(selectedTunnelNames);
        const aggregateSeries = {
          label: "All Tunnels (Aggregate)",
          color: API_AGGREGATE_SERIES_COLOR,
          strokeWidth: 2.8,
          values: timelineBuckets.map((bucket) => bucket.aggregateBitRateBps),
        };
        const tunnelSeries = selectedTunnelNames.map((tunnelName) => ({
          label: tunnelName,
          color: selectedColorMap.get(tunnelName) || API_TUNNEL_SERIES_COLORS[0],
          strokeWidth: 1.8,
          values: timelineBuckets.map((bucket) => bucket.perTunnelBitRateBps.get(tunnelName) ?? 0),
        }));
        const seriesCollection = [aggregateSeries, ...tunnelSeries];

        const maxValue = Math.max(
          1,
          ...seriesCollection.flatMap((series) =>
            series.values.map((value) => (Number.isFinite(value) && value > 0 ? value : 0)),
          ),
        );

        const chartWidth = 1200;
        const chartHeight = 360;
        const margin = {
          top: 14,
          right: 16,
          bottom: 52,
          left: 88,
        };
        const plotWidth = chartWidth - margin.left - margin.right;
        const plotHeight = chartHeight - margin.top - margin.bottom;
        const pointCount = timelineBuckets.length;
        const yTickCount = 5;

        const computeX = (index) => {
          if (pointCount <= 1) {
            return margin.left + plotWidth / 2;
          }

          return margin.left + (index / (pointCount - 1)) * plotWidth;
        };

        const computeY = (value) => {
          const numeric = Number.isFinite(value) && value > 0 ? value : 0;
          return margin.top + (1 - numeric / maxValue) * plotHeight;
        };

        const gridAndYLabelHtml = [];

        for (let index = 0; index < yTickCount; index += 1) {
          const ratio = index / (yTickCount - 1);
          const y = margin.top + ratio * plotHeight;
          const value = maxValue * (1 - ratio);

          gridAndYLabelHtml.push(
            '<line x1="' +
              margin.left.toFixed(2) +
              '" y1="' +
              y.toFixed(2) +
              '" x2="' +
              (margin.left + plotWidth).toFixed(2) +
              '" y2="' +
              y.toFixed(2) +
              '" stroke="rgba(255, 255, 255, 0.12)" stroke-width="1" />',
          );
          gridAndYLabelHtml.push(
            '<text x="' +
              (margin.left - 10).toFixed(2) +
              '" y="' +
              (y + 4).toFixed(2) +
              '" fill="rgba(255, 215, 179, 0.75)" font-size="11" text-anchor="end">' +
              escapeHtml(formatTunnelBandwidthBitsPerSecond(value)) +
              "</text>",
          );
        }

        const xTickIndexes = buildApiLineChartTickIndexes(pointCount, 7);
        const xTickHtml = xTickIndexes
          .map((index) => {
            const x = computeX(index);
            const bucket = timelineBuckets[index];
            const label = formatTunnelBandwidthTimelineLabel(bucket.timestampMs, bucket.datetimeIso);

            return (
              '<line x1="' +
              x.toFixed(2) +
              '" y1="' +
              (margin.top + plotHeight).toFixed(2) +
              '" x2="' +
              x.toFixed(2) +
              '" y2="' +
              (margin.top + plotHeight + 4).toFixed(2) +
              '" stroke="rgba(255, 255, 255, 0.25)" stroke-width="1" />' +
              '<text x="' +
              x.toFixed(2) +
              '" y="' +
              (margin.top + plotHeight + 18).toFixed(2) +
              '" fill="rgba(255, 215, 179, 0.75)" font-size="11" text-anchor="middle">' +
              escapeHtml(label) +
              "</text>"
            );
          })
          .join("");

        const polylineHtml = seriesCollection
          .map((series) => {
            const points = series.values
              .map((value, index) => computeX(index).toFixed(2) + "," + computeY(value).toFixed(2))
              .join(" ");

            return (
              '<polyline points="' +
              points +
              '" fill="none" stroke="' +
              escapeHtml(series.color) +
              '" stroke-width="' +
              series.strokeWidth.toFixed(2) +
              '" stroke-linejoin="round" stroke-linecap="round" />'
            );
          })
          .join("");

        const legendHtml = seriesCollection
          .map(
            (series) =>
              '<span class="api-line-chart-legend-item"><span class="api-tunnel-swatch" style="background:' +
              escapeHtml(series.color) +
              '"></span>' +
              escapeHtml(series.label) +
              "</span>",
          )
          .join("");

        target.innerHTML =
          '<div class="api-line-chart"><svg viewBox="0 0 ' +
          chartWidth +
          " " +
          chartHeight +
          '" role="img" aria-label="Tunnel bandwidth over time">' +
          '<rect x="' +
          margin.left.toFixed(2) +
          '" y="' +
          margin.top.toFixed(2) +
          '" width="' +
          plotWidth.toFixed(2) +
          '" height="' +
          plotHeight.toFixed(2) +
          '" fill="rgba(0, 0, 0, 0.08)" />' +
          gridAndYLabelHtml.join("") +
          '<line x1="' +
          margin.left.toFixed(2) +
          '" y1="' +
          margin.top.toFixed(2) +
          '" x2="' +
          margin.left.toFixed(2) +
          '" y2="' +
          (margin.top + plotHeight).toFixed(2) +
          '" stroke="rgba(255, 255, 255, 0.38)" stroke-width="1" />' +
          '<line x1="' +
          margin.left.toFixed(2) +
          '" y1="' +
          (margin.top + plotHeight).toFixed(2) +
          '" x2="' +
          (margin.left + plotWidth).toFixed(2) +
          '" y2="' +
          (margin.top + plotHeight).toFixed(2) +
          '" stroke="rgba(255, 255, 255, 0.38)" stroke-width="1" />' +
          xTickHtml +
          polylineHtml +
          "</svg><div class='api-line-chart-legend'>" +
          legendHtml +
          "</div></div>";
      }

      function renderApiTunnelBandwidthResults(timelineBuckets, tunnelEntries, selectedTunnelNames) {
        renderApiTunnelSeriesSelector(tunnelEntries, selectedTunnelNames);
        renderApiTunnelLineChart(timelineBuckets, selectedTunnelNames);

        renderDataTable("apiTunnelBandwidthTable", tunnelEntries, [
          {
            label: "Tunnel",
            value: (entry) => entry.label,
          },
          {
            label: "Average Bits/Sec",
            value: (entry) => formatTunnelBandwidthBitsPerSecond(entry.value),
          },
          {
            label: "Average Mbps",
            value: (entry) => formatTunnelBandwidthMegabitsPerSecond(entry.value),
          },
        ]);
      }

      function handleApiTunnelSeriesSelectionToggle(input) {
        const tunnelName = toAnalyticsText(input?.value);

        if (!tunnelName) {
          return;
        }

        const availableNames = new Set(apiTunnelSummaryEntries.map((entry) => entry.label));
        const nextSelection = apiSelectedTunnelNames.filter((name) => availableNames.has(name));
        const existingIndex = nextSelection.indexOf(tunnelName);

        if (input.checked) {
          if (existingIndex === -1) {
            if (nextSelection.length >= API_MAX_TUNNEL_SERIES) {
              input.checked = false;
              setHintMessage(
                apiAnalyticsStatus,
                "Select up to 10 tunnels. Uncheck one before selecting another.",
                true,
              );
              return;
            }

            nextSelection.push(tunnelName);
          }
        } else if (existingIndex !== -1) {
          nextSelection.splice(existingIndex, 1);
        }

        apiSelectedTunnelNames = nextSelection;
        renderApiTunnelBandwidthResults(
          apiTunnelTimelineBuckets,
          apiTunnelSummaryEntries,
          apiSelectedTunnelNames,
        );

        setHintMessage(apiAnalyticsStatus, apiLatestSummaryMessage);
      }

      async function runApiAnalyticsQuery() {
        try {
          const filters = readApiAnalyticsFilters();
          const accountTag = await resolveGraphqlAccountId();
          const requestPayload = buildMagicTransitTunnelBandwidthRequest(filters, accountTag);

          const filterSnapshot = buildApiFilterSnapshot(
            filters,
            accountTag,
            requestPayload.variables,
          );

          setHintMessage(apiAnalyticsStatus, "Running tunnel bandwidth GraphQL query...");

          const response = await callApi("/api/graphql", {
            method: "POST",
            body: requestPayload,
            showOutput: false,
          });

          if (!response || !response.ok) {
            throw new Error(getNetworkFlowErrorMessage(response));
          }

          const graphqlErrors = Array.isArray(response.payload?.errors)
            ? response.payload.errors
            : [];

          if (graphqlErrors.length) {
            const graphQlMessage = graphqlErrors
              .map((item) => toAnalyticsText(item?.message))
              .filter(Boolean)
              .join("; ");
            throw new Error("Cloudflare GraphQL returned errors: " + (graphQlMessage || "Unknown"));
          }

          const allRows = extractMagicTransitTunnelBandwidthRows(response.payload);
          const tunnelInventory = await loadMagicTransitTunnelInventoryNames();
          apiTunnelTimelineBuckets = buildTunnelBandwidthTimelineBuckets(allRows);
          apiTunnelSummaryEntries = mergeTunnelEntriesWithInventory(
            buildTunnelBandwidthEntries(allRows),
            tunnelInventory.tunnelNames,
          );
          apiSelectedTunnelNames = selectApiTunnelNames(
            apiTunnelSummaryEntries,
            apiSelectedTunnelNames,
          );

          renderApiTunnelBandwidthResults(
            apiTunnelTimelineBuckets,
            apiTunnelSummaryEntries,
            apiSelectedTunnelNames,
          );

          setOutput(true, "200 OK", "POST /api/graphql", {
            queryName: "GetMagicTransitTunnelBandwidth",
            tunnelDataPoints: allRows.length,
            fiveMinutePoints: apiTunnelTimelineBuckets.length,
            tunnels: apiTunnelSummaryEntries.length,
            selectedTunnels: apiSelectedTunnelNames,
            inventoryTunnels: tunnelInventory.tunnelNames.length,
            inventoryWarnings: tunnelInventory.warnings,
            filters: filterSnapshot,
            data: response.payload?.data ?? null,
          });

          if (!allRows.length) {
            apiLatestSummaryMessage =
              "No tunnel bandwidth rows were returned for the selected time window.";
            setHintMessage(
              apiAnalyticsStatus,
              apiLatestSummaryMessage,
              true,
            );
            return;
          }

          apiLatestSummaryMessage =
            "Loaded " +
            formatAnalyticsNumber(apiTunnelTimelineBuckets.length) +
            " five-minute points across " +
            formatAnalyticsNumber(apiTunnelSummaryEntries.length) +
            " tunnels from " +
            formatAnalyticsNumber(allRows.length) +
            " samples. Showing " +
            formatAnalyticsNumber(apiSelectedTunnelNames.length) +
            " tunnel lines plus aggregate.";

          if (tunnelInventory.warnings.length) {
            apiLatestSummaryMessage += " Tunnel inventory warnings: " + tunnelInventory.warnings.join(" ");
          }

          setHintMessage(apiAnalyticsStatus, apiLatestSummaryMessage);
        } catch (error) {
          const message = error instanceof Error ? error.message : String(error);
          setHintMessage(apiAnalyticsStatus, message, true);
          setClientError(message);
        }
      }

      function formatUsageRate(value) {
        const numeric = Number(value);

        if (!Number.isFinite(numeric) || numeric < 0) {
          return "—";
        }

        const units = [
          { threshold: 1_000_000_000_000, divisor: 1_000_000_000_000, suffix: "Tbps" },
          { threshold: 1_000_000_000, divisor: 1_000_000_000, suffix: "Gbps" },
          { threshold: 1_000_000, divisor: 1_000_000, suffix: "Mbps" },
          { threshold: 1_000, divisor: 1_000, suffix: "Kbps" },
        ];
        const unit = units.find((candidate) => numeric >= candidate.threshold);

        if (!unit) {
          return Math.round(numeric).toLocaleString() + " bps";
        }

        const scaledValue = numeric / unit.divisor;
        const maximumFractionDigits = scaledValue >= 100 ? 0 : scaledValue >= 10 ? 1 : 2;
        return (
          scaledValue.toLocaleString(undefined, { maximumFractionDigits }) + " " + unit.suffix
        );
      }

      function buildUsageTimeRange() {
        const days = Number(document.getElementById("usageLookbackDays")?.value ?? "30");

        if (![1, 7, 30].includes(days)) {
          throw new Error("Select a supported Usage measurement window.");
        }

        const endMs = Math.floor(Date.now() / USAGE_INTERVAL_MS) * USAGE_INTERVAL_MS;
        const startMs = endMs - days * 24 * 60 * 60 * 1000;
        return {
          days,
          startMs,
          endMs,
          startIso: new Date(startMs).toISOString(),
          endIso: new Date(endMs).toISOString(),
        };
      }

      function buildUsageQueryWindows(timeRange, tunnelCount) {
        const targetRowsPerWindow = Math.floor(USAGE_QUERY_ROW_LIMIT * 0.8);
        const targetBuckets = Math.max(1, Math.floor(targetRowsPerWindow / Math.max(1, tunnelCount)));
        const chunkMs = Math.max(
          USAGE_INTERVAL_MS,
          Math.min(USAGE_MAX_CHUNK_MS, targetBuckets * USAGE_INTERVAL_MS),
        );
        const windows = [];

        for (let startMs = timeRange.startMs; startMs < timeRange.endMs; startMs += chunkMs) {
          windows.push({
            startMs,
            endMs: Math.min(timeRange.endMs, startMs + chunkMs),
          });
        }

        return windows;
      }

      function getGraphqlErrorMessage(payload) {
        const graphqlErrors = Array.isArray(payload?.errors) ? payload.errors : [];
        return graphqlErrors
          .map((item) => toAnalyticsText(item?.message))
          .filter(Boolean)
          .join("; ");
      }

      async function queryUsageWindow(accountTag, direction, window, progress) {
        const response = await callApi("/api/graphql", {
          method: "POST",
          body: {
            query: USAGE_TUNNEL_BANDWIDTH_QUERY,
            variables: {
              accountTag,
              direction,
              datetimeStart: new Date(window.startMs).toISOString(),
              datetimeEnd: new Date(window.endMs).toISOString(),
            },
          },
          showOutput: false,
          timeoutMs: 30_000,
        });

        if (!response || !response.ok) {
          throw new Error(getNetworkFlowErrorMessage(response));
        }

        const graphqlMessage = getGraphqlErrorMessage(response.payload);

        if (graphqlMessage) {
          throw new Error("Cloudflare GraphQL returned errors: " + graphqlMessage);
        }

        const rows = extractMagicTransitTunnelBandwidthRows(response.payload);
        progress.completed += 1;
        setHintMessage(
          usageStatus,
          "Loading 5-minute throughput: " +
            formatAnalyticsNumber(progress.completed) +
            " query windows complete...",
        );

        if (rows.length < USAGE_QUERY_ROW_LIMIT) {
          return rows;
        }

        const durationMs = window.endMs - window.startMs;

        if (durationMs <= USAGE_INTERVAL_MS) {
          throw new Error(
            "A five-minute Usage query reached the GraphQL row limit. Reduce the tunnel count or query window.",
          );
        }

        const midpointMs =
          window.startMs +
          Math.floor(durationMs / (2 * USAGE_INTERVAL_MS)) * USAGE_INTERVAL_MS;

        if (midpointMs <= window.startMs || midpointMs >= window.endMs) {
          throw new Error("Unable to split a GraphQL Usage query that reached the row limit.");
        }

        const leftRows = await queryUsageWindow(
          accountTag,
          direction,
          { startMs: window.startMs, endMs: midpointMs },
          progress,
        );
        const rightRows = await queryUsageWindow(
          accountTag,
          direction,
          { startMs: midpointMs, endMs: window.endMs },
          progress,
        );
        return [...leftRows, ...rightRows];
      }

      async function runUsageTasks(tasks, concurrency = 4) {
        const results = new Array(tasks.length);
        let nextTaskIndex = 0;

        const workers = Array.from(
          { length: Math.min(concurrency, tasks.length) },
          async () => {
            while (nextTaskIndex < tasks.length) {
              const taskIndex = nextTaskIndex;
              nextTaskIndex += 1;
              results[taskIndex] = await tasks[taskIndex]();
            }
          },
        );

        await Promise.all(workers);
        return results.flat();
      }

      function renderUsageSummary(summary, timeRange) {
        const summaryTarget = document.getElementById("usageSummaryCards");
        const topTunnel = summary.tunnels[0] ?? null;

        if (summaryTarget) {
          summaryTarget.innerHTML =
            '<div class="metric-card usage-metric-card primary"><div class="metric-label">Total ingress P95</div><div class="metric-value">' +
            escapeHtml(formatUsageRate(summary.totals.ingressP95Bps)) +
            '</div><p class="hint">Sum of tunnel ingress P95s</p></div>' +
            '<div class="metric-card usage-metric-card primary"><div class="metric-label">Total egress P95</div><div class="metric-value">' +
            escapeHtml(formatUsageRate(summary.totals.egressP95Bps)) +
            '</div><p class="hint">Sum of tunnel egress P95s</p></div>' +
            '<div class="metric-card usage-metric-card"><div class="metric-label">Tunnels measured</div><div class="metric-value">' +
            escapeHtml(formatAnalyticsNumber(summary.tunnels.length)) +
            '</div><p class="hint">' +
            escapeHtml(topTunnel ? "Highest: " + topTunnel.tunnelName : "No tunnels returned") +
            '</p></div>' +
            '<div class="metric-card usage-metric-card"><div class="metric-label">5-minute intervals</div><div class="metric-value">' +
            escapeHtml(formatAnalyticsNumber(summary.sampleCount)) +
            '</div><p class="hint">' +
            escapeHtml(timeRange.days + "-day window per tunnel") +
            "</p></div>";
        }

        const chartTarget = document.getElementById("usageP95Chart");

        if (chartTarget) {
          if (!summary.tunnels.length) {
            chartTarget.innerHTML = '<p class="hint">No tunnel inventory or throughput data was returned.</p>';
          } else {
            const visibleTunnels = summary.tunnels.slice(0, 24);
            const maxValue = Math.max(
              1,
              ...visibleTunnels.flatMap((tunnel) => [tunnel.ingressP95Bps, tunnel.egressP95Bps]),
            );
            const rowsHtml = visibleTunnels
              .map((tunnel) => {
                const ingressWidth = Math.max(0.3, (tunnel.ingressP95Bps / maxValue) * 100);
                const egressWidth = Math.max(0.3, (tunnel.egressP95Bps / maxValue) * 100);
                return (
                  '<div class="usage-bar-row"><div class="usage-bar-label" title="' +
                  escapeHtml(tunnel.tunnelName) +
                  '">' +
                  escapeHtml(tunnel.tunnelName) +
                  '</div><div class="usage-bar-track"><div class="usage-bar-segment ingress" style="width:' +
                  ingressWidth.toFixed(2) +
                  '%"></div><div class="usage-bar-segment egress" style="width:' +
                  egressWidth.toFixed(2) +
                  '%"></div></div><div class="usage-bar-value">' +
                  escapeHtml(formatUsageRate(tunnel.ingressP95Bps)) +
                  " / " +
                  escapeHtml(formatUsageRate(tunnel.egressP95Bps)) +
                  "</div></div>"
                );
              })
              .join("");
            const overflowNote =
              summary.tunnels.length > visibleTunnels.length
                ? '<p class="analytics-results-note">Showing the 24 highest combined P95 tunnels. The table includes all tunnels.</p>'
                : "";
            chartTarget.innerHTML =
              '<div class="usage-legend"><span><i class="usage-bar-segment ingress"></i>Ingress P95</span><span><i class="usage-bar-segment egress"></i>Egress P95</span></div><div class="usage-bars">' +
              rowsHtml +
              "</div>" +
              overflowNote;
          }
        }

        renderDataTable("usageP95Table", summary.tunnels, [
          { label: "Tunnel", value: (tunnel) => tunnel.tunnelName },
          { label: "Ingress P95", value: (tunnel) => formatUsageRate(tunnel.ingressP95Bps) },
          { label: "Egress P95", value: (tunnel) => formatUsageRate(tunnel.egressP95Bps) },
          {
            label: "Ingress + Egress P95",
            value: (tunnel) => formatUsageRate(tunnel.combinedP95Bps),
          },
          { label: "Ingress Peak", value: (tunnel) => formatUsageRate(tunnel.ingressPeakBps) },
          { label: "Egress Peak", value: (tunnel) => formatUsageRate(tunnel.egressPeakBps) },
        ]);
      }

      async function runUsageQuery() {
        if (usageLoading) {
          return;
        }

        usageLoading = true;
        usageLoaded = false;
        const runButton = document.getElementById("btnRunUsage");

        if (runButton) {
          runButton.disabled = true;
          runButton.textContent = "Calculating...";
        }

        try {
          const timeRange = buildUsageTimeRange();
          const accountTag = await resolveGraphqlAccountId();
          setHintMessage(usageStatus, "Loading GRE and IPsec tunnel inventory...");
          const inventory = await loadMagicTransitTunnelInventoryNames();
          const windows = buildUsageQueryWindows(timeRange, inventory.tunnelNames.length);
          const progress = { completed: 0 };
          const tasks = [];

          for (const direction of ["ingress", "egress"]) {
            for (const window of windows) {
              tasks.push(async () => ({
                direction,
                rows: await queryUsageWindow(accountTag, direction, window, progress),
              }));
            }
          }

          setHintMessage(
            usageStatus,
            "Loading " +
              formatAnalyticsNumber(tasks.length) +
              " GraphQL query windows for 5-minute throughput...",
          );

          const taskResults = await runUsageTasks(tasks);
          const rowsByDirection = { ingress: [], egress: [] };

          for (const result of taskResults) {
            rowsByDirection[result.direction].push(...result.rows);
          }

          const summary = calculateTunnelUsageSummary({
            rowsByDirection,
            tunnelNames: inventory.tunnelNames,
            startMs: timeRange.startMs,
            endMs: timeRange.endMs,
          });

          renderUsageSummary(summary, timeRange);
          usageLoaded = true;
          const totalRows = rowsByDirection.ingress.length + rowsByDirection.egress.length;
          const warningText = inventory.warnings.length
            ? " Inventory warnings: " + inventory.warnings.join(" ")
            : "";

          setHintMessage(
            usageStatus,
            "Calculated nearest-rank P95 from " +
              formatAnalyticsNumber(totalRows) +
              " GraphQL rows across " +
              formatAnalyticsNumber(summary.sampleCount) +
              " five-minute intervals. Missing intervals count as zero." +
              warningText,
            inventory.warnings.length > 0,
          );
          setOutput(true, "200 OK", "POST /api/graphql", {
            queryName: "GetMagicTransitP95Usage",
            accountTag,
            range: {
              start: timeRange.startIso,
              end: timeRange.endIso,
              days: timeRange.days,
            },
            graphQlRows: {
              ingress: rowsByDirection.ingress.length,
              egress: rowsByDirection.egress.length,
            },
            queryWindows: progress.completed,
            sampleCount: summary.sampleCount,
            tunnels: summary.tunnels.length,
            totals: summary.totals,
            inventoryWarnings: inventory.warnings,
          });
        } catch (error) {
          const message = error instanceof Error ? error.message : String(error);
          setHintMessage(usageStatus, message, true);
          setClientError(message);
        } finally {
          usageLoading = false;

          if (runButton) {
            runButton.disabled = false;
            runButton.textContent = "Calculate P95 usage";
          }
        }
      }

      function networkFlowDurationToUi(value) {
        const rawValue = value === null || value === undefined ? "" : String(value).trim();

        if (!rawValue) {
          return "1m";
        }

        if (rawValue.endsWith("0s") && rawValue.includes("m")) {
          return rawValue.slice(0, -2);
        }

        return rawValue;
      }

      function networkFlowDurationToApi(value) {
        const rawValue = value === null || value === undefined ? "" : String(value).trim();

        if (!rawValue) {
          return "1m0s";
        }

        if (rawValue.endsWith("m") && !rawValue.includes("s")) {
          return rawValue + "0s";
        }

        return rawValue;
      }

      function networkFlowBooleanLabel(value) {
        return value ? "True" : "False";
      }

      function networkFlowSensitivityLabel(value) {
        if (value === "high") {
          return "High";
        }

        if (value === "low") {
          return "Low";
        }

        return "Medium";
      }

      function networkFlowStaticThresholdLabel(rule) {
        if (
          rule.packet_threshold !== null &&
          rule.packet_threshold !== undefined &&
          (rule.bandwidth_threshold === null || rule.bandwidth_threshold === undefined)
        ) {
          return "Packets Per Second";
        }

        return "Bandwidth";
      }

      function networkFlowStaticThresholdMode(rule) {
        if (
          rule.packet_threshold !== null &&
          rule.packet_threshold !== undefined &&
          (rule.bandwidth_threshold === null || rule.bandwidth_threshold === undefined)
        ) {
          return "packets";
        }

        return "bandwidth";
      }

      function networkFlowDynamicTypeLabel(rule) {
        if (rule.zscore_target === "packets") {
          return "Packets Per Second";
        }

        return "Bandwidth";
      }

      function networkFlowPrefixesLabel(prefixes) {
        if (!Array.isArray(prefixes) || !prefixes.length) {
          return "N/A";
        }

        return prefixes.join(", ");
      }

      function renderNetworkFlowEditableCell(rule, section, fieldKey, displayValue) {
        return (
          '<div class="editable-cell">' +
          '<span class="editable-cell-value">' +
          escapeHtml(toDisplayValue(displayValue)) +
          "</span>" +
          '<button class="icon-button" type="button" data-action="edit-network-flow-field" data-rule-id="' +
          escapeHtml(rule.id) +
          '" data-section="' +
          escapeHtml(section) +
          '" data-field="' +
          escapeHtml(fieldKey) +
          '" aria-label="Edit value">✎</button>' +
          "</div>"
        );
      }

      function renderNetworkFlowDeleteButton(rule) {
        if (!rule || rule._isDraft || !rule.id) {
          return "—";
        }

        return (
          '<button class="icon-button" type="button" data-action="delete-network-flow-rule" data-rule-id="' +
          escapeHtml(rule.id) +
          '" title="Delete rule">🗑</button>'
        );
      }

      function createNetworkFlowDraftRow(section) {
        networkFlowDraftCounter += 1;

        const baseDraft = {
          _isDraft: true,
          _section: section,
          _draftId: "draft-" + section + "-" + String(networkFlowDraftCounter),
          name: "",
          prefixes: "",
          duration: "1m",
          automatic_advertisement: "false",
        };

        if (section === "static") {
          return {
            ...baseDraft,
            threshold_mode: "bandwidth",
            bandwidth_threshold: "",
            packet_threshold: "",
          };
        }

        if (section === "dynamic") {
          return {
            ...baseDraft,
            dynamic_type: "bits",
            zscore_sensitivity: "medium",
          };
        }

        return {
          ...baseDraft,
          prefix_match: "exact",
        };
      }

      function addNetworkFlowDraftRow(section) {
        if (!networkFlowDraftRows[section]) {
          return;
        }

        const draft = createNetworkFlowDraftRow(section);
        networkFlowDraftRows[section].push(draft);
        networkFlowDraftMap.set(draft._draftId, draft);
        renderNetworkFlowTables(networkFlowLoadedRules);
      }

      function removeNetworkFlowDraftRow(draftId, options = {}) {
        const draft = networkFlowDraftMap.get(draftId);

        if (!draft) {
          return false;
        }

        const sectionRows = networkFlowDraftRows[draft._section];

        if (Array.isArray(sectionRows)) {
          const index = sectionRows.findIndex((entry) => entry._draftId === draftId);

          if (index !== -1) {
            sectionRows.splice(index, 1);
          }
        }

        networkFlowDraftMap.delete(draftId);

        if (options.render !== false) {
          renderNetworkFlowTables(networkFlowLoadedRules);
        }

        return true;
      }

      function updateNetworkFlowDraftValue(control) {
        const draftId = control.getAttribute("data-draft-id");
        const fieldKey = control.getAttribute("data-field");
        const draft = networkFlowDraftMap.get(draftId);

        if (!draft || !fieldKey) {
          return;
        }

        draft[fieldKey] = control.value;

        if (fieldKey === "threshold_mode" || fieldKey === "duration") {
          renderNetworkFlowTables(networkFlowLoadedRules);
        }
      }

      function syncNetworkFlowDraftFromDom(draftId) {
        const draft = networkFlowDraftMap.get(draftId);

        if (!draft) {
          return;
        }

        const controls = document.querySelectorAll("[data-network-flow-draft='true']");

        for (const control of controls) {
          if (control.getAttribute("data-draft-id") !== draftId) {
            continue;
          }

          const fieldKey = control.getAttribute("data-field");

          if (!fieldKey) {
            continue;
          }

          draft[fieldKey] = control.value;
        }
      }

      function renderNetworkFlowDraftControl(draft, fieldKey, config = {}) {
        const draftId = escapeHtml(draft._draftId);
        const field = escapeHtml(fieldKey);
        const value = config.value === null || config.value === undefined ? "" : String(config.value);
        const disabledAttr = config.disabled ? " disabled" : "";
        const placeholderAttr = config.placeholder
          ? ' placeholder="' + escapeHtml(String(config.placeholder)) + '"'
          : "";

        if (config.type === "select") {
          const options = Array.isArray(config.options) ? config.options : [];
          const optionsHtml = options
            .map((option) => {
              const selected = String(option.value) === value ? " selected" : "";
              return (
                '<option value="' +
                escapeHtml(String(option.value)) +
                '"' +
                selected +
                ">" +
                escapeHtml(String(option.label)) +
                "</option>"
              );
            })
            .join("");

          return (
            '<select class="rule-input" data-network-flow-draft="true" data-draft-id="' +
            draftId +
            '" data-field="' +
            field +
            '"' +
            disabledAttr +
            ">" +
            optionsHtml +
            "</select>"
          );
        }

        if (config.type === "textarea") {
          return (
            '<textarea class="rule-input" data-network-flow-draft="true" data-draft-id="' +
            draftId +
            '" data-field="' +
            field +
            '"' +
            disabledAttr +
            placeholderAttr +
            ">" +
            escapeHtml(value) +
            "</textarea>"
          );
        }

        const inputType = config.type || "text";

        return (
          '<input class="rule-input" type="' +
          escapeHtml(inputType) +
          '" data-network-flow-draft="true" data-draft-id="' +
          draftId +
          '" data-field="' +
          field +
          '" value="' +
          escapeHtml(value) +
          '"' +
          disabledAttr +
          placeholderAttr +
          " />"
        );
      }

      function renderNetworkFlowDraftActionCell(draft) {
        return (
          '<div class="inline-editor table-action-cell">' +
          '<button class="mini-button" type="button" data-action="save-network-flow-draft" data-draft-id="' +
          escapeHtml(draft._draftId) +
          '">Save</button>' +
          '<button class="mini-button" type="button" data-action="remove-network-flow-draft" data-draft-id="' +
          escapeHtml(draft._draftId) +
          '">Remove</button>' +
          "</div>"
        );
      }

      function renderNetworkFlowTables(rules) {
        const staticRules = [];
        const dynamicRules = [];
        const sflowRules = [];

        networkFlowRuleMap.clear();

        for (const rule of rules) {
          if (!rule || !rule.id) {
            continue;
          }

          networkFlowRuleMap.set(rule.id, rule);

          if (rule.type === "threshold") {
            staticRules.push(rule);
            continue;
          }

          if (rule.type === "zscore") {
            dynamicRules.push(rule);
            continue;
          }

          if (rule.type === "advanced_ddos") {
            sflowRules.push(rule);
          }
        }

        const staticRows = [...staticRules, ...networkFlowDraftRows.static];
        const dynamicRows = [...dynamicRules, ...networkFlowDraftRows.dynamic];
        const sflowRows = [...sflowRules, ...networkFlowDraftRows.sflow];

        renderDataTable("staticRulesTable", staticRows, [
          {
            label: "Name",
            render: (rule) => {
              if (rule._isDraft) {
                return renderNetworkFlowDraftControl(rule, "name", {
                  type: "text",
                  value: rule.name,
                  placeholder: "Rule name",
                });
              }

              return renderNetworkFlowEditableCell(rule, "static", "name", rule.name);
            },
          },
          {
            label: "Threshold Type",
            render: (rule) => {
              if (rule._isDraft) {
                return renderNetworkFlowDraftControl(rule, "threshold_mode", {
                  type: "select",
                  value: rule.threshold_mode,
                  options: NETWORK_FLOW_THRESHOLD_MODE_OPTIONS,
                });
              }

              return renderNetworkFlowEditableCell(
                rule,
                "static",
                "threshold_mode",
                networkFlowStaticThresholdLabel(rule),
              );
            },
          },
          {
            label: "Prefixes",
            render: (rule) => {
              if (rule._isDraft) {
                return renderNetworkFlowDraftControl(rule, "prefixes", {
                  type: "textarea",
                  value: rule.prefixes,
                  placeholder: "Comma-separated prefixes",
                });
              }

              return renderNetworkFlowEditableCell(
                rule,
                "static",
                "prefixes",
                networkFlowPrefixesLabel(rule.prefixes),
              );
            },
          },
          {
            label: "Timeframe",
            render: (rule) => {
              if (rule._isDraft) {
                return renderNetworkFlowDraftControl(rule, "duration", {
                  type: "select",
                  value: rule.duration,
                  options: NETWORK_FLOW_TIMEFRAMES.map((entry) => ({ value: entry, label: entry })),
                });
              }

              return renderNetworkFlowEditableCell(
                rule,
                "static",
                "duration",
                networkFlowDurationToUi(rule.duration),
              );
            },
          },
          {
            label: "Auto Advertisement",
            render: (rule) => {
              if (rule._isDraft) {
                return renderNetworkFlowDraftControl(rule, "automatic_advertisement", {
                  type: "select",
                  value: rule.automatic_advertisement,
                  options: NETWORK_FLOW_BOOLEAN_OPTIONS,
                });
              }

              return renderNetworkFlowEditableCell(
                rule,
                "static",
                "automatic_advertisement",
                networkFlowBooleanLabel(rule.automatic_advertisement),
              );
            },
          },
          {
            label: "Bandwidth Threshold (bps)",
            render: (rule) => {
              if (rule._isDraft) {
                const isBandwidth = rule.threshold_mode !== "packets";
                return renderNetworkFlowDraftControl(rule, "bandwidth_threshold", {
                  type: "number",
                  value: rule.bandwidth_threshold,
                  placeholder: isBandwidth ? "bps" : "N/A",
                  disabled: !isBandwidth,
                });
              }

              const useBandwidth = networkFlowStaticThresholdMode(rule) === "bandwidth";
              const value = useBandwidth ? rule.bandwidth_threshold : "N/A";
              return renderNetworkFlowEditableCell(rule, "static", "bandwidth_threshold", value);
            },
          },
          {
            label: "Packets Per Second Threshold (pps)",
            render: (rule) => {
              if (rule._isDraft) {
                const isPackets = rule.threshold_mode === "packets";
                return renderNetworkFlowDraftControl(rule, "packet_threshold", {
                  type: "number",
                  value: rule.packet_threshold,
                  placeholder: isPackets ? "pps" : "N/A",
                  disabled: !isPackets,
                });
              }

              const usePackets = networkFlowStaticThresholdMode(rule) === "packets";
              const value = usePackets ? rule.packet_threshold : "N/A";
              return renderNetworkFlowEditableCell(rule, "static", "packet_threshold", value);
            },
          },
          {
            label: "Save",
            render: (rule) => (rule._isDraft ? renderNetworkFlowDraftActionCell(rule) : "—"),
          },
          {
            label: "Delete",
            render: (rule) => renderNetworkFlowDeleteButton(rule),
          },
        ]);

        renderDataTable("dynamicRulesTable", dynamicRows, [
          {
            label: "Name",
            render: (rule) => {
              if (rule._isDraft) {
                return renderNetworkFlowDraftControl(rule, "name", {
                  type: "text",
                  value: rule.name,
                  placeholder: "Rule name",
                });
              }

              return renderNetworkFlowEditableCell(rule, "dynamic", "name", rule.name);
            },
          },
          {
            label: "Dynamic Type",
            render: (rule) => {
              if (rule._isDraft) {
                return renderNetworkFlowDraftControl(rule, "dynamic_type", {
                  type: "select",
                  value: rule.dynamic_type,
                  options: NETWORK_FLOW_DYNAMIC_TYPE_OPTIONS,
                });
              }

              return renderNetworkFlowEditableCell(
                rule,
                "dynamic",
                "dynamic_type",
                networkFlowDynamicTypeLabel(rule),
              );
            },
          },
          {
            label: "Dynamic Sensitivity",
            render: (rule) => {
              if (rule._isDraft) {
                return renderNetworkFlowDraftControl(rule, "zscore_sensitivity", {
                  type: "select",
                  value: rule.zscore_sensitivity,
                  options: NETWORK_FLOW_SENSITIVITY_OPTIONS,
                });
              }

              return renderNetworkFlowEditableCell(
                rule,
                "dynamic",
                "zscore_sensitivity",
                networkFlowSensitivityLabel(rule.zscore_sensitivity),
              );
            },
          },
          {
            label: "Prefixes",
            render: (rule) => {
              if (rule._isDraft) {
                return renderNetworkFlowDraftControl(rule, "prefixes", {
                  type: "textarea",
                  value: rule.prefixes,
                  placeholder: "Comma-separated prefixes",
                });
              }

              return renderNetworkFlowEditableCell(
                rule,
                "dynamic",
                "prefixes",
                networkFlowPrefixesLabel(rule.prefixes),
              );
            },
          },
          {
            label: "Timeframe",
            render: (rule) => {
              if (rule._isDraft) {
                return renderNetworkFlowDraftControl(rule, "duration", {
                  type: "select",
                  value: rule.duration,
                  options: NETWORK_FLOW_TIMEFRAMES.map((entry) => ({ value: entry, label: entry })),
                });
              }

              return renderNetworkFlowEditableCell(
                rule,
                "dynamic",
                "duration",
                networkFlowDurationToUi(rule.duration),
              );
            },
          },
          {
            label: "Auto Advertisement",
            render: (rule) => {
              if (rule._isDraft) {
                return renderNetworkFlowDraftControl(rule, "automatic_advertisement", {
                  type: "select",
                  value: rule.automatic_advertisement,
                  options: NETWORK_FLOW_BOOLEAN_OPTIONS,
                });
              }

              return renderNetworkFlowEditableCell(
                rule,
                "dynamic",
                "automatic_advertisement",
                networkFlowBooleanLabel(rule.automatic_advertisement),
              );
            },
          },
          {
            label: "Save",
            render: (rule) => (rule._isDraft ? renderNetworkFlowDraftActionCell(rule) : "—"),
          },
          {
            label: "Delete",
            render: (rule) => renderNetworkFlowDeleteButton(rule),
          },
        ]);

        renderDataTable("sflowRulesTable", sflowRows, [
          {
            label: "Name",
            render: (rule) => {
              if (rule._isDraft) {
                return renderNetworkFlowDraftControl(rule, "name", {
                  type: "text",
                  value: rule.name,
                  placeholder: "Rule name",
                });
              }

              return renderNetworkFlowEditableCell(rule, "sflow", "name", rule.name);
            },
          },
          {
            label: "Prefix Matching",
            render: (rule) => {
              if (rule._isDraft) {
                return renderNetworkFlowDraftControl(rule, "prefix_match", {
                  type: "select",
                  value: rule.prefix_match,
                  options: NETWORK_FLOW_PREFIX_MATCH_OPTIONS,
                });
              }

              return renderNetworkFlowEditableCell(
                rule,
                "sflow",
                "prefix_match",
                rule.prefix_match || "exact",
              );
            },
          },
          {
            label: "Prefixes",
            render: (rule) => {
              if (rule._isDraft) {
                return renderNetworkFlowDraftControl(rule, "prefixes", {
                  type: "textarea",
                  value: rule.prefixes,
                  placeholder: "Comma-separated prefixes",
                });
              }

              return renderNetworkFlowEditableCell(
                rule,
                "sflow",
                "prefixes",
                networkFlowPrefixesLabel(rule.prefixes),
              );
            },
          },
          {
            label: "Timeframe",
            render: (rule) => {
              if (rule._isDraft) {
                return renderNetworkFlowDraftControl(rule, "duration", {
                  type: "select",
                  value: rule.duration,
                  options: NETWORK_FLOW_TIMEFRAMES.map((entry) => ({ value: entry, label: entry })),
                });
              }

              return renderNetworkFlowEditableCell(
                rule,
                "sflow",
                "duration",
                networkFlowDurationToUi(rule.duration),
              );
            },
          },
          {
            label: "Auto Advertisement",
            render: (rule) => {
              if (rule._isDraft) {
                return renderNetworkFlowDraftControl(rule, "automatic_advertisement", {
                  type: "select",
                  value: rule.automatic_advertisement,
                  options: NETWORK_FLOW_BOOLEAN_OPTIONS,
                });
              }

              return renderNetworkFlowEditableCell(
                rule,
                "sflow",
                "automatic_advertisement",
                networkFlowBooleanLabel(rule.automatic_advertisement),
              );
            },
          },
          {
            label: "Save",
            render: (rule) => (rule._isDraft ? renderNetworkFlowDraftActionCell(rule) : "—"),
          },
          {
            label: "Delete",
            render: (rule) => renderNetworkFlowDeleteButton(rule),
          },
        ]);

        return {
          total: rules.length,
          static_rules: staticRules.length,
          dynamic_rules: dynamicRules.length,
          sflow_advertisement_rules: sflowRules.length,
        };
      }

      function getNetworkFlowEditorConfig(rule, fieldKey) {
        if (fieldKey === "name") {
          return {
            type: "text",
            value: rule.name || "",
          };
        }

        if (fieldKey === "prefixes") {
          return {
            type: "textarea",
            value: Array.isArray(rule.prefixes) ? rule.prefixes.join(", ") : "",
          };
        }

        if (fieldKey === "duration") {
          return {
            type: "select",
            value: networkFlowDurationToUi(rule.duration),
            options: NETWORK_FLOW_TIMEFRAMES.map((entry) => ({ value: entry, label: entry })),
          };
        }

        if (fieldKey === "automatic_advertisement") {
          return {
            type: "select",
            value: rule.automatic_advertisement ? "true" : "false",
            options: NETWORK_FLOW_BOOLEAN_OPTIONS,
          };
        }

        if (fieldKey === "threshold_mode") {
          return {
            type: "select",
            value: networkFlowStaticThresholdMode(rule),
            options: NETWORK_FLOW_THRESHOLD_MODE_OPTIONS,
          };
        }

        if (fieldKey === "bandwidth_threshold") {
          return {
            type: "number",
            value:
              rule.bandwidth_threshold === null || rule.bandwidth_threshold === undefined
                ? ""
                : String(rule.bandwidth_threshold),
          };
        }

        if (fieldKey === "packet_threshold") {
          return {
            type: "number",
            value:
              rule.packet_threshold === null || rule.packet_threshold === undefined
                ? ""
                : String(rule.packet_threshold),
          };
        }

        if (fieldKey === "dynamic_type") {
          return {
            type: "select",
            value: rule.zscore_target === "packets" ? "packets" : "bits",
            options: NETWORK_FLOW_DYNAMIC_TYPE_OPTIONS,
          };
        }

        if (fieldKey === "zscore_sensitivity") {
          return {
            type: "select",
            value: ["low", "medium", "high"].includes(rule.zscore_sensitivity)
              ? rule.zscore_sensitivity
              : "medium",
            options: NETWORK_FLOW_SENSITIVITY_OPTIONS,
          };
        }

        if (fieldKey === "prefix_match") {
          return {
            type: "select",
            value: ["exact", "subnet", "supernet"].includes(rule.prefix_match)
              ? rule.prefix_match
              : "exact",
            options: NETWORK_FLOW_PREFIX_MATCH_OPTIONS,
          };
        }

        return null;
      }

      function createNetworkFlowEditorControl(editorConfig) {
        let control;

        if (editorConfig.type === "select") {
          control = document.createElement("select");

          for (const option of editorConfig.options) {
            const optionElement = document.createElement("option");
            optionElement.value = option.value;
            optionElement.textContent = option.label;
            control.appendChild(optionElement);
          }

          control.value = editorConfig.value;
          return control;
        }

        if (editorConfig.type === "textarea") {
          control = document.createElement("textarea");
          control.value = editorConfig.value;
          return control;
        }

        control = document.createElement("input");
        control.type = editorConfig.type;
        control.value = editorConfig.value;
        return control;
      }

      function parseNetworkFlowPrefixes(rawValue) {
        const rawText = rawValue === null || rawValue === undefined ? "" : String(rawValue);
        const normalized = rawText.replaceAll(String.fromCharCode(10), ",");
        const pieces = normalized.split(",");
        const prefixes = [];

        for (const piece of pieces) {
          const value = piece.trim();

          if (value) {
            prefixes.push(value);
          }
        }

        if (!prefixes.length) {
          throw new Error("At least one prefix is required.");
        }

        return prefixes;
      }

      function parseNetworkFlowNumber(rawValue, label) {
        const valueText = rawValue === null || rawValue === undefined ? "" : String(rawValue).trim();

        if (!valueText) {
          throw new Error(label + " is required.");
        }

        const numericValue = Number(valueText);

        if (!Number.isFinite(numericValue) || numericValue < 0) {
          throw new Error(label + " must be a non-negative number.");
        }

        return Math.round(numericValue);
      }

      function buildNetworkFlowPatch(rule, fieldKey, rawValue) {
        const textValue = rawValue === null || rawValue === undefined ? "" : String(rawValue).trim();

        if (fieldKey === "name") {
          if (!textValue) {
            throw new Error("Name is required.");
          }

          return { name: textValue };
        }

        if (fieldKey === "prefixes") {
          return { prefixes: parseNetworkFlowPrefixes(rawValue) };
        }

        if (fieldKey === "duration") {
          if (!NETWORK_FLOW_TIMEFRAMES.includes(textValue)) {
            throw new Error("Timeframe must be one of: " + NETWORK_FLOW_TIMEFRAMES.join(", "));
          }

          return { duration: networkFlowDurationToApi(textValue) };
        }

        if (fieldKey === "automatic_advertisement") {
          if (textValue !== "true" && textValue !== "false") {
            throw new Error("Auto Advertisement must be True or False.");
          }

          return { automatic_advertisement: textValue === "true" };
        }

        if (fieldKey === "threshold_mode") {
          if (textValue !== "bandwidth" && textValue !== "packets") {
            throw new Error("Threshold Type must be Bandwidth or Packets Per Second.");
          }

          if (textValue === "bandwidth") {
            return {
              bandwidth_threshold: rule.bandwidth_threshold ?? rule.packet_threshold ?? 0,
              packet_threshold: null,
            };
          }

          return {
            packet_threshold: rule.packet_threshold ?? rule.bandwidth_threshold ?? 0,
            bandwidth_threshold: null,
          };
        }

        if (fieldKey === "bandwidth_threshold") {
          return {
            bandwidth_threshold: parseNetworkFlowNumber(rawValue, "Bandwidth Threshold (bps)"),
            packet_threshold: null,
          };
        }

        if (fieldKey === "packet_threshold") {
          return {
            packet_threshold: parseNetworkFlowNumber(rawValue, "Packets Per Second Threshold (pps)"),
            bandwidth_threshold: null,
          };
        }

        if (fieldKey === "dynamic_type") {
          if (textValue !== "bits" && textValue !== "packets") {
            throw new Error("Dynamic Type must be Bandwidth or Packets Per Second.");
          }

          return { zscore_target: textValue };
        }

        if (fieldKey === "zscore_sensitivity") {
          if (!["low", "medium", "high"].includes(textValue)) {
            throw new Error("Dynamic Sensitivity must be Low, Medium, or High.");
          }

          return { zscore_sensitivity: textValue };
        }

        if (fieldKey === "prefix_match") {
          if (!["exact", "subnet", "supernet"].includes(textValue)) {
            throw new Error("Prefix Matching must be exact, subnet, or supernet.");
          }

          return { prefix_match: textValue };
        }

        throw new Error("Unsupported editable field: " + fieldKey);
      }

      function buildNetworkFlowCreateRule(draft) {
        if (!draft || !draft._section) {
          throw new Error("Invalid draft row.");
        }

        const name = String(draft.name ?? "").trim();

        if (!name) {
          throw new Error("Name is required.");
        }

        const prefixes = parseNetworkFlowPrefixes(draft.prefixes);
        const durationValue = String(draft.duration ?? "").trim();

        if (!NETWORK_FLOW_TIMEFRAMES.includes(durationValue)) {
          throw new Error("Timeframe must be one of: " + NETWORK_FLOW_TIMEFRAMES.join(", "));
        }

        const baseRule = {
          name,
          prefixes,
          automatic_advertisement: String(draft.automatic_advertisement) === "true",
          duration: networkFlowDurationToApi(durationValue),
        };

        if (draft._section === "static") {
          const thresholdMode = String(draft.threshold_mode ?? "").trim();

          if (thresholdMode !== "bandwidth" && thresholdMode !== "packets") {
            throw new Error("Threshold Type must be Bandwidth or Packets Per Second.");
          }

          if (thresholdMode === "bandwidth") {
            return {
              ...baseRule,
              type: "threshold",
              bandwidth_threshold: parseNetworkFlowNumber(
                draft.bandwidth_threshold,
                "Bandwidth Threshold (bps)",
              ),
            };
          }

          return {
            ...baseRule,
            type: "threshold",
            packet_threshold: parseNetworkFlowNumber(
              draft.packet_threshold,
              "Packets Per Second Threshold (pps)",
            ),
          };
        }

        if (draft._section === "dynamic") {
          const dynamicType = String(draft.dynamic_type ?? "").trim();

          if (dynamicType !== "bits" && dynamicType !== "packets") {
            throw new Error("Dynamic Type must be Bandwidth or Packets Per Second.");
          }

          const sensitivity = String(draft.zscore_sensitivity ?? "").trim();

          if (!["low", "medium", "high"].includes(sensitivity)) {
            throw new Error("Dynamic Sensitivity must be Low, Medium, or High.");
          }

          return {
            ...baseRule,
            type: "zscore",
            zscore_target: dynamicType,
            zscore_sensitivity: sensitivity,
          };
        }

        if (draft._section === "sflow") {
          const prefixMatch = String(draft.prefix_match ?? "").trim();

          if (!["exact", "subnet", "supernet"].includes(prefixMatch)) {
            throw new Error("Prefix Matching must be exact, subnet, or supernet.");
          }

          return {
            ...baseRule,
            type: "advanced_ddos",
            prefix_match: prefixMatch,
          };
        }

        throw new Error("Unsupported draft row section.");
      }

      function getNetworkFlowErrorMessage(response) {
        if (!response) {
          return "Request failed.";
        }

        if (typeof response.payload === "string") {
          return response.payload;
        }

        if (response.payload && typeof response.payload === "object") {
          if (typeof response.payload.error === "string") {
            return response.payload.error;
          }

          if (
            Array.isArray(response.payload.errors) &&
            response.payload.errors.length &&
            response.payload.errors[0] &&
            typeof response.payload.errors[0] === "object" &&
            typeof response.payload.errors[0].message === "string"
          ) {
            const firstError = response.payload.errors[0];
            return firstError.code ? String(firstError.code) + ": " + firstError.message : firstError.message;
          }

          if (
            Array.isArray(response.payload.errors) &&
            response.payload.errors.length &&
            typeof response.payload.errors[0] === "string"
          ) {
            return response.payload.errors[0];
          }
        }

        return "Request failed with status " + response.status + " " + response.statusText + ".";
      }

      async function saveNetworkFlowDraft(button) {
        const draftId = button.getAttribute("data-draft-id");
        const draft = networkFlowDraftMap.get(draftId);

        if (!draft) {
          setClientError("Unable to find the selected draft row.");
          return;
        }

        button.disabled = true;

        try {
          syncNetworkFlowDraftFromDom(draftId);
          const rulePayload = buildNetworkFlowCreateRule(draft);
          const endpoint = "/api/mnm/rules";
          const response = await callApi(endpoint, {
            method: "POST",
            body: {
              rules: [rulePayload],
            },
            showOutput: false,
          });

          if (!response || !response.ok) {
            throw new Error(getNetworkFlowErrorMessage(response));
          }

          removeNetworkFlowDraftRow(draftId, { render: false });
          await loadNetworkFlowRules({ updateOutput: false });
          setOutput(true, "Created", "POST " + endpoint, response.payload);
        } catch (error) {
          setClientError(error.message);
          button.disabled = false;
        }
      }

      async function handleNetworkFlowRuleDelete(button) {
        const ruleId = (button.getAttribute("data-rule-id") ?? "").trim();

        if (!ruleId) {
          throw new Error("Missing Network Flow rule identifier.");
        }

        const confirmed = window.confirm(
          "Delete this Network Flow rule? This action cannot be undone.",
        );

        if (!confirmed) {
          return;
        }

        const endpoint = "/api/mnm/rules/" + encodeURIComponent(ruleId);
        setHintMessage(networkFlowStatus, "Deleting Network Flow rule...");

        const response = await callApi(endpoint, {
          method: "DELETE",
          showOutput: false,
        });

        if (!response || !response.ok) {
          throw new Error(getNetworkFlowErrorMessage(response));
        }

        await loadNetworkFlowRules({ updateOutput: false });
        setOutput(true, "Deleted", "DELETE " + endpoint, response.payload);
      }

      async function beginNetworkFlowEdit(button) {
        const cell = button.closest(".editable-cell");

        if (!cell || cell.dataset.editing === "true") {
          return;
        }

        const ruleId = button.getAttribute("data-rule-id");
        const fieldKey = button.getAttribute("data-field");
        const rule = networkFlowRuleMap.get(ruleId);

        if (!rule) {
          setClientError("Unable to find the selected rule.");
          return;
        }

        const editorConfig = getNetworkFlowEditorConfig(rule, fieldKey);

        if (!editorConfig) {
          setClientError("This field cannot be edited.");
          return;
        }

        cell.dataset.editing = "true";

        const displayElement = cell.querySelector(".editable-cell-value");
        displayElement.style.display = "none";
        button.style.display = "none";

        const editorWrapper = document.createElement("div");
        editorWrapper.className = "inline-editor";

        const editorControl = createNetworkFlowEditorControl(editorConfig);
        editorWrapper.appendChild(editorControl);

        const saveButton = document.createElement("button");
        saveButton.type = "button";
        saveButton.className = "mini-button";
        saveButton.textContent = "Save";

        const cancelButton = document.createElement("button");
        cancelButton.type = "button";
        cancelButton.className = "mini-button";
        cancelButton.textContent = "Cancel";

        editorWrapper.appendChild(saveButton);
        editorWrapper.appendChild(cancelButton);
        cell.appendChild(editorWrapper);

        const closeEditor = () => {
          if (!cell.isConnected) {
            return;
          }

          editorWrapper.remove();
          displayElement.style.display = "";
          button.style.display = "";
          delete cell.dataset.editing;
        };

        cancelButton.addEventListener("click", closeEditor);

        saveButton.addEventListener("click", async () => {
          saveButton.disabled = true;
          cancelButton.disabled = true;
          editorControl.disabled = true;

          try {
            const patch = buildNetworkFlowPatch(rule, fieldKey, editorControl.value);
            const endpoint = "/api/mnm/rules/" + encodeURIComponent(rule.id);
            const response = await callApi(endpoint, {
              method: "PATCH",
              body: patch,
              showOutput: false,
            });

            if (!response || !response.ok) {
              throw new Error(getNetworkFlowErrorMessage(response));
            }

            closeEditor();
            await loadNetworkFlowRules({ updateOutput: false });
            setOutput(true, "Updated", "PATCH " + endpoint, response.payload);
          } catch (error) {
            setClientError(error.message);
            saveButton.disabled = false;
            cancelButton.disabled = false;
            editorControl.disabled = false;
          }
        });
      }

      async function loadNetworkFlowRules(options = {}) {
        const updateOutput = options.updateOutput !== false;

        networkFlowStatus.textContent = "Loading Network Flow rules...";
        networkFlowStatus.classList.remove("err");

        const response = await callApi("/api/mnm/rules", { showOutput: false });

        if (!response || !response.ok) {
          networkFlowLoadedRules = [];
          renderNetworkFlowTables([]);
          networkFlowStatus.textContent = "Failed to load Network Flow rules.";
          networkFlowStatus.classList.add("err");

          if (updateOutput) {
            setOutput(
              false,
              response ? response.status + " " + response.statusText : "Network error",
              "GET /api/mnm/rules",
              response ? response.payload : { error: "No response" },
            );
          }

          return;
        }

        const rules = extractResultArray(response.payload);
        networkFlowLoadedRules = rules;
        const summary = renderNetworkFlowTables(networkFlowLoadedRules);

        networkFlowStatus.textContent =
          "Loaded " +
          summary.total +
          " rules (Static: " +
          summary.static_rules +
          ", Dynamic: " +
          summary.dynamic_rules +
          ", sFlow: " +
          summary.sflow_advertisement_rules +
          ").";

        if (updateOutput) {
          setOutput(true, "Loaded", "GET /api/mnm/rules", summary);
        }
      }

      function renderFlowtrackdSelect(field, value, options) {
        const optionHtml = options
          .map((option) => {
            const optionValue = typeof option === "string" ? option : option.value;
            const optionLabel = typeof option === "string" ? option : option.label;
            return (
              '<option value="' +
              escapeHtml(optionValue) +
              '"' +
              (optionValue === value ? " selected" : "") +
              ">" +
              escapeHtml(optionLabel) +
              "</option>"
            );
          })
          .join("");
        return (
          '<select data-flowtrackd-field="' +
          escapeHtml(field) +
          '">' +
          optionHtml +
          "</select>"
        );
      }

      function renderFlowtrackdInput(field, value, options = {}) {
        const type = options.type || "text";
        const placeholder = options.placeholder
          ? ' placeholder="' + escapeHtml(options.placeholder) + '"'
          : "";
        const disabled = options.disabled ? " disabled" : "";
        return (
          '<input type="' +
          escapeHtml(type) +
          '" data-flowtrackd-field="' +
          escapeHtml(field) +
          '" value="' +
          escapeHtml(value ?? "") +
          '"' +
          placeholder +
          disabled +
          " />"
        );
      }

      function renderFlowtrackdActions(resourceKey, item) {
        return (
          '<div class="flowtrackd-actions"><button class="mini-button" type="button" data-action="flowtrackd-save" data-resource="' +
          escapeHtml(resourceKey) +
          '" data-item-id="' +
          escapeHtml(item.id) +
          '">Save</button><button class="mini-button flowtrackd-danger" type="button" data-action="flowtrackd-delete" data-resource="' +
          escapeHtml(resourceKey) +
          '" data-item-id="' +
          escapeHtml(item.id) +
          '">Delete</button></div>'
        );
      }

      function renderFlowtrackdCollection(resourceKey, rows) {
        const config = FLOWTRACKD_RESOURCES[resourceKey];

        if (!config) {
          return;
        }

        const modifiedColumn = {
          label: "Modified",
          value: (item) => formatRecentAlertDisplayTime(item.modified_on),
        };
        const actionColumn = {
          label: "Actions",
          render: (item) => renderFlowtrackdActions(resourceKey, item),
        };

        if (config.kind === "prefix") {
          renderDataTable(config.targetId, rows, [
            {
              label: "Prefix",
              render: (item) => renderFlowtrackdInput("prefix", item.prefix),
            },
            {
              label: "Comment",
              render: (item) => renderFlowtrackdInput("comment", item.comment),
            },
            {
              label: "Protection",
              render: (item) =>
                renderFlowtrackdSelect("excluded", String(Boolean(item.excluded)), [
                  { value: "false", label: "Protected" },
                  { value: "true", label: "Excluded" },
                ]),
            },
            modifiedColumn,
            actionColumn,
          ]);
          return;
        }

        if (config.kind === "allowlist") {
          renderDataTable(config.targetId, rows, [
            {
              label: "Prefix",
              render: (item) => renderFlowtrackdInput("prefix", item.prefix),
            },
            {
              label: "Comment",
              render: (item) => renderFlowtrackdInput("comment", item.comment),
            },
            {
              label: "State",
              render: (item) =>
                renderFlowtrackdSelect("enabled", String(Boolean(item.enabled)), [
                  { value: "true", label: "Enabled" },
                  { value: "false", label: "Disabled" },
                ]),
            },
            modifiedColumn,
            actionColumn,
          ]);
          return;
        }

        if (config.kind === "filter") {
          renderDataTable(config.targetId, rows, [
            {
              label: "Expression",
              render: (item) =>
                '<textarea data-flowtrackd-field="expression">' +
                escapeHtml(item.expression ?? "") +
                "</textarea>",
            },
            {
              label: "Mode",
              render: (item) => renderFlowtrackdSelect("mode", item.mode, FLOWTRACKD_MODE_OPTIONS),
            },
            modifiedColumn,
            actionColumn,
          ]);
          return;
        }

        const columns = [
          {
            label: "Scope",
            render: (item) => renderFlowtrackdSelect("scope", item.scope, FLOWTRACKD_SCOPE_OPTIONS),
          },
          {
            label: "Scope name",
            render: (item) =>
              renderFlowtrackdInput("name", item.name, { disabled: item.scope === "global" }),
          },
          {
            label: "Mode",
            render: (item) => renderFlowtrackdSelect("mode", item.mode, FLOWTRACKD_MODE_OPTIONS),
          },
          {
            label: "Rate sensitivity",
            render: (item) =>
              renderFlowtrackdSelect(
                "rate_sensitivity",
                item.rate_sensitivity,
                FLOWTRACKD_SENSITIVITY_OPTIONS,
              ),
          },
          {
            label: "Burst sensitivity",
            render: (item) =>
              renderFlowtrackdSelect(
                "burst_sensitivity",
                item.burst_sensitivity,
                FLOWTRACKD_SENSITIVITY_OPTIONS,
              ),
          },
        ];

        if (config.kind === "synRule") {
          columns.push({
            label: "Mitigation",
            render: (item) =>
              renderFlowtrackdSelect("mitigation_type", item.mitigation_type || "challenge", [
                "challenge",
                "retransmit",
              ]),
          });
        }

        columns.push(modifiedColumn, actionColumn);
        renderDataTable(config.targetId, rows, columns);
      }

      function readFlowtrackdPayload(resourceKey, root) {
        if (!root) {
          throw new Error("Unable to find the FlowtrackD form or table row.");
        }

        const values = {};

        for (const control of root.querySelectorAll("[data-flowtrackd-field]")) {
          values[control.getAttribute("data-flowtrackd-field")] = control.value.trim();
        }

        if (resourceKey === "prefixBulk") {
          const prefixes = String(values.prefixes ?? "")
            .split(/[,\\n]/)
            .map((entry) => entry.trim())
            .filter(Boolean);

          if (!prefixes.length) {
            throw new Error("Enter at least one prefix for the bulk request.");
          }

          if (prefixes.length > 300) {
            throw new Error("Cloudflare accepts at most 300 prefixes per bulk request.");
          }

          return [...new Set(prefixes)].map((prefix) => ({
            prefix,
            comment: values.comment ?? "",
            excluded: values.excluded === "true",
          }));
        }

        const config = FLOWTRACKD_RESOURCES[resourceKey];

        if (!config) {
          throw new Error("Unsupported FlowtrackD resource.");
        }

        if (config.kind === "prefix") {
          return {
            prefix: values.prefix,
            comment: values.comment ?? "",
            excluded: values.excluded === "true",
          };
        }

        if (config.kind === "allowlist") {
          return {
            prefix: values.prefix,
            comment: values.comment ?? "",
            enabled: values.enabled === "true",
          };
        }

        if (config.kind === "filter") {
          return {
            expression: values.expression,
            mode: values.mode,
          };
        }

        const payload = {
          scope: values.scope,
          name: values.scope === "global" ? "global" : values.name,
          mode: values.mode,
          rate_sensitivity: values.rate_sensitivity,
          burst_sensitivity: values.burst_sensitivity,
        };

        if (config.kind === "synRule") {
          payload.mitigation_type = values.mitigation_type || "challenge";
        }

        return payload;
      }

      function setFlowtrackdProtectionStatus(enabled) {
        const statusTarget = document.getElementById("flowtrackdProtectionStatus");
        const statusInput = document.getElementById("flowtrackdStatusInput");

        if (statusTarget) {
          statusTarget.textContent = "Global status: " + (enabled ? "Enabled" : "Disabled");
          statusTarget.classList.toggle("enabled", enabled);
          statusTarget.classList.toggle("disabled", !enabled);
        }

        if (statusInput) {
          statusInput.value = enabled ? "true" : "false";
        }
      }

      async function loadFlowtrackdDashboard(options = {}) {
        if (flowtrackdLoading) {
          return;
        }

        flowtrackdLoading = true;
        const updateOutput = options.updateOutput !== false;
        const refreshButton = document.getElementById("btnRefreshFlowtrackd");

        if (refreshButton) {
          refreshButton.disabled = true;
        }

        setHintMessage(flowtrackdStatus, "Loading Advanced TCP Protection configuration...");

        try {
          const resourceEntries = Object.entries(FLOWTRACKD_RESOURCES);
          const requests = [
            callApi("/api/ddos-protection/status", { showOutput: false }),
            ...resourceEntries.map(([, config]) =>
              callApi(config.path + "?per_page=1000", { showOutput: false }),
            ),
          ];
          const responses = await Promise.all(requests);
          const statusResponse = responses[0];
          const errors = [];
          const summary = {};

          if (statusResponse?.ok) {
            const protectionEnabled = parseAdvancedTcpProtectionStatus(statusResponse.payload);

            if (protectionEnabled === null) {
              errors.push("Status: Cloudflare returned an unrecognized protection status.");
            } else {
              setFlowtrackdProtectionStatus(protectionEnabled);
            }
          } else {
            errors.push("Status: " + getNetworkFlowErrorMessage(statusResponse));
          }

          resourceEntries.forEach(([resourceKey, config], index) => {
            const response = responses[index + 1];

            if (!response?.ok) {
              errors.push(config.label + ": " + getNetworkFlowErrorMessage(response));
              const target = document.getElementById(config.targetId);

              if (target) {
                target.innerHTML = '<p class="hint err">Unable to load ' + escapeHtml(config.label) + ".</p>";
              }

              return;
            }

            const rows = extractResultArray(response.payload);
            summary[resourceKey] = rows.length;
            renderFlowtrackdCollection(resourceKey, rows);
          });

          flowtrackdLoaded = true;
          const loadedCount = Object.values(summary).reduce((total, count) => total + count, 0);
          setHintMessage(
            flowtrackdStatus,
            "Loaded " +
              formatAnalyticsNumber(loadedCount) +
              " Advanced TCP Protection objects." +
              (errors.length ? " Some endpoints were unavailable: " + errors.join(" ") : ""),
            errors.length > 0,
          );

          if (updateOutput) {
            setOutput(errors.length === 0, errors.length ? "Partial load" : "Loaded", "GET /api/ddos-protection/*", {
              summary,
              errors,
            });
          }
        } catch (error) {
          const message = error instanceof Error ? error.message : String(error);
          setHintMessage(flowtrackdStatus, message, true);
          setClientError(message);
        } finally {
          flowtrackdLoading = false;

          if (refreshButton) {
            refreshButton.disabled = false;
          }
        }
      }

      async function applyFlowtrackdStatus(button) {
        const enabled = document.getElementById("flowtrackdStatusInput")?.value === "true";

        if (!window.confirm((enabled ? "Enable" : "Disable") + " Advanced TCP Protection for this account?")) {
          return;
        }

        button.disabled = true;

        try {
          const response = await callApi("/api/ddos-protection/status", {
            method: "PATCH",
            body: { enabled },
            showOutput: false,
          });

          if (!response?.ok) {
            throw new Error(getNetworkFlowErrorMessage(response));
          }

          setFlowtrackdProtectionStatus(enabled);
          setHintMessage(flowtrackdStatus, "Advanced TCP Protection status updated.");
          setOutput(true, "Updated", "PATCH /api/ddos-protection/status", response.payload);
        } catch (error) {
          const message = error instanceof Error ? error.message : String(error);
          setHintMessage(flowtrackdStatus, message, true);
          setClientError(message);
        } finally {
          button.disabled = false;
        }
      }

      function setFlowtrackdCreateFormOpen(resourceKey, open) {
        const form = document.querySelector(
          '[data-flowtrackd-create-form="' + resourceKey + '"]',
        );
        const toggleButton = document.querySelector(
          '[data-action="flowtrackd-toggle-create"][data-resource="' + resourceKey + '"]',
        );

        if (!form || !toggleButton) {
          return;
        }

        form.classList.toggle("hidden", !open);
        toggleButton.setAttribute("aria-expanded", String(open));
        toggleButton.textContent = open
          ? "Cancel"
          : toggleButton.getAttribute("data-create-label") || "Create";

        if (open) {
          form.querySelector("input:not([disabled]), textarea:not([disabled]), select:not([disabled])")?.focus();
        }
      }

      function toggleFlowtrackdCreateForm(button) {
        const resourceKey = button.getAttribute("data-resource");
        const form = document.querySelector(
          '[data-flowtrackd-create-form="' + resourceKey + '"]',
        );

        if (resourceKey && form) {
          setFlowtrackdCreateFormOpen(resourceKey, form.classList.contains("hidden"));
        }
      }

      async function createFlowtrackdResource(button) {
        const resourceKey = button.getAttribute("data-resource");
        const config = FLOWTRACKD_RESOURCES[resourceKey];
        const root = button.closest("[data-flowtrackd-create-form]");
        const endpoint = resourceKey === "prefixBulk" ? "/api/ddos-protection/prefixes/bulk" : config?.path;

        if (!endpoint) {
          throw new Error("Unsupported FlowtrackD create action.");
        }

        const payload = readFlowtrackdPayload(resourceKey, root);
        button.disabled = true;

        try {
          const response = await callApi(endpoint, {
            method: "POST",
            body: payload,
            showOutput: false,
          });

          if (!response?.ok) {
            throw new Error(getNetworkFlowErrorMessage(response));
          }

          for (const control of root.querySelectorAll("input, textarea, select")) {
            if (control.tagName === "SELECT") {
              const selectedOption = control.querySelector("option[selected]");
              control.value = selectedOption?.value ?? control.options[0]?.value ?? "";
            } else {
              control.value = control.defaultValue;
            }
          }

          const scopeControl = root.querySelector('[data-flowtrackd-field="scope"]');

          if (scopeControl) {
            syncFlowtrackdScopeName(scopeControl);
          }

          setFlowtrackdCreateFormOpen(resourceKey, false);
          await loadFlowtrackdDashboard({ updateOutput: false });
          setHintMessage(flowtrackdStatus, "Created " + (config?.label ?? "protected prefixes") + ".");
          setOutput(true, "Created", "POST " + endpoint, response.payload);
        } finally {
          button.disabled = false;
        }
      }

      async function saveFlowtrackdResource(button) {
        const resourceKey = button.getAttribute("data-resource");
        const itemId = button.getAttribute("data-item-id");
        const config = FLOWTRACKD_RESOURCES[resourceKey];
        const row = button.closest("tr");

        if (!config || !itemId) {
          throw new Error("Missing FlowtrackD resource configuration or item identifier.");
        }

        const payload = readFlowtrackdPayload(resourceKey, row);
        const endpoint = config.path + "/" + encodeURIComponent(itemId);
        button.disabled = true;

        try {
          const response = await callApi(endpoint, {
            method: "PATCH",
            body: payload,
            showOutput: false,
          });

          if (!response?.ok) {
            throw new Error(getNetworkFlowErrorMessage(response));
          }

          await loadFlowtrackdDashboard({ updateOutput: false });
          setHintMessage(flowtrackdStatus, "Updated " + config.label + ".");
          setOutput(true, "Updated", "PATCH " + endpoint, response.payload);
        } finally {
          button.disabled = false;
        }
      }

      async function deleteFlowtrackdResource(button) {
        const resourceKey = button.getAttribute("data-resource");
        const itemId = button.getAttribute("data-item-id");
        const config = FLOWTRACKD_RESOURCES[resourceKey];

        if (!config || !itemId) {
          throw new Error("Missing FlowtrackD resource configuration or item identifier.");
        }

        if (!window.confirm("Delete this " + config.label.replace(/s$/, "") + "?")) {
          return;
        }

        const endpoint = config.path + "/" + encodeURIComponent(itemId);
        const response = await callApi(endpoint, {
          method: "DELETE",
          showOutput: false,
        });

        if (!response?.ok) {
          throw new Error(getNetworkFlowErrorMessage(response));
        }

        await loadFlowtrackdDashboard({ updateOutput: false });
        setHintMessage(flowtrackdStatus, "Deleted " + config.label.replace(/s$/, "") + ".");
        setOutput(true, "Deleted", "DELETE " + endpoint, response.payload);
      }

      async function deleteAllFlowtrackdResources(button) {
        const resourceKey = button.getAttribute("data-resource");
        const config = FLOWTRACKD_RESOURCES[resourceKey];

        if (!config) {
          throw new Error("Unsupported FlowtrackD bulk delete action.");
        }

        if (!window.confirm("Delete all " + config.label + " from this account? This cannot be undone.")) {
          return;
        }

        const response = await callApi(config.path, {
          method: "DELETE",
          showOutput: false,
        });

        if (!response?.ok) {
          throw new Error(getNetworkFlowErrorMessage(response));
        }

        await loadFlowtrackdDashboard({ updateOutput: false });
        setHintMessage(flowtrackdStatus, "Deleted all " + config.label + ".");
        setOutput(true, "Deleted all", "DELETE " + config.path, response.payload);
      }

      function syncFlowtrackdScopeName(scopeControl) {
        if (scopeControl.getAttribute("data-flowtrackd-field") !== "scope") {
          return;
        }

        const root = scopeControl.closest("tr, [data-flowtrackd-create-form]");
        const nameInput = root?.querySelector('[data-flowtrackd-field="name"]');

        if (!nameInput) {
          return;
        }

        if (scopeControl.value === "global") {
          nameInput.value = "global";
          nameInput.disabled = true;
        } else {
          if (nameInput.value === "global") {
            nameInput.value = "";
          }

          nameInput.disabled = false;
          nameInput.placeholder = scopeControl.value === "region" ? "WEUR" : "lax";
        }
      }

      function cleanAddressValue(value) {
        return String(value).trim().replaceAll("[", "").replaceAll("]", "");
      }

      function normalizeEndpointToken(value) {
        if (value === null || value === undefined) {
          return "";
        }

        const cleaned = cleanAddressValue(value);

        if (!cleaned) {
          return "";
        }

        const withoutZone = cleaned.includes("%")
          ? cleaned.split("%")[0]
          : cleaned;
        const withoutCidr = withoutZone.includes("/")
          ? withoutZone.split("/")[0]
          : withoutZone;

        return withoutCidr.trim().toLowerCase();
      }

      function parseIpv4Bytes(value) {
        const normalized = normalizeEndpointToken(value);

        if (!normalized || !normalized.includes(".")) {
          return null;
        }

        const parts = normalized.split(".");

        if (parts.length !== 4) {
          return null;
        }

        const bytes = new Uint8Array(4);

        for (let index = 0; index < 4; index += 1) {
          const part = parts[index];

          if (!/^\\d+$/.test(part)) {
            return null;
          }

          const valueNum = Number(part);

          if (valueNum < 0 || valueNum > 255) {
            return null;
          }

          bytes[index] = valueNum;
        }

        return bytes;
      }

      function parseIpv6Bytes(value) {
        let normalized = normalizeEndpointToken(value);

        if (!normalized || !normalized.includes(":")) {
          return null;
        }

        if (normalized.includes(".")) {
          const lastColon = normalized.lastIndexOf(":");

          if (lastColon === -1) {
            return null;
          }

          const ipv4Part = normalized.slice(lastColon + 1);
          const ipv4Bytes = parseIpv4Bytes(ipv4Part);

          if (!ipv4Bytes) {
            return null;
          }

          const high = ((ipv4Bytes[0] << 8) | ipv4Bytes[1]).toString(16);
          const low = ((ipv4Bytes[2] << 8) | ipv4Bytes[3]).toString(16);
          normalized = normalized.slice(0, lastColon) + ":" + high + ":" + low;
        }

        const doubleColonParts = normalized.split("::");

        if (doubleColonParts.length > 2) {
          return null;
        }

        const left = doubleColonParts[0]
          ? doubleColonParts[0].split(":").filter(Boolean)
          : [];
        const right =
          doubleColonParts.length === 2 && doubleColonParts[1]
            ? doubleColonParts[1].split(":").filter(Boolean)
            : [];

        const hexPattern = /^[0-9a-f]{1,4}$/i;

        if (
          left.some((part) => !hexPattern.test(part)) ||
          right.some((part) => !hexPattern.test(part))
        ) {
          return null;
        }

        if (doubleColonParts.length === 1 && left.length !== 8) {
          return null;
        }

        if (doubleColonParts.length === 2 && left.length + right.length > 7) {
          return null;
        }

        const fillCount =
          doubleColonParts.length === 2 ? 8 - (left.length + right.length) : 0;
        const hextets = [...left, ...new Array(fillCount).fill("0"), ...right];

        if (hextets.length !== 8) {
          return null;
        }

        const bytes = new Uint8Array(16);

        for (let index = 0; index < hextets.length; index += 1) {
          const valueNum = Number.parseInt(hextets[index], 16);
          bytes[index * 2] = (valueNum >> 8) & 0xff;
          bytes[index * 2 + 1] = valueNum & 0xff;
        }

        return bytes;
      }

      function parseIpAddress(value) {
        const ipv4Bytes = parseIpv4Bytes(value);

        if (ipv4Bytes) {
          return { version: 4, bytes: ipv4Bytes };
        }

        const ipv6Bytes = parseIpv6Bytes(value);

        if (ipv6Bytes) {
          return { version: 6, bytes: ipv6Bytes };
        }

        return null;
      }

      function parseCidr(value) {
        if (value === null || value === undefined) {
          return null;
        }

        const cleaned = cleanAddressValue(value);

        if (!cleaned || !cleaned.includes("/")) {
          return null;
        }

        const [rawAddress, rawPrefix] = cleaned.split("/");

        if (!rawAddress || rawPrefix === undefined) {
          return null;
        }

        const parsedAddress = parseIpAddress(rawAddress);

        if (!parsedAddress) {
          return null;
        }

        const prefix = Number(rawPrefix.trim());
        const maxPrefix = parsedAddress.version === 4 ? 32 : 128;

        if (!Number.isInteger(prefix) || prefix < 0 || prefix > maxPrefix) {
          return null;
        }

        return {
          version: parsedAddress.version,
          bytes: parsedAddress.bytes,
          prefix,
        };
      }

      function ipInCidr(ipAddress, cidrBlock) {
        if (!ipAddress || !cidrBlock || ipAddress.version !== cidrBlock.version) {
          return false;
        }

        const fullBytes = Math.floor(cidrBlock.prefix / 8);
        const remainingBits = cidrBlock.prefix % 8;

        for (let index = 0; index < fullBytes; index += 1) {
          if (ipAddress.bytes[index] !== cidrBlock.bytes[index]) {
            return false;
          }
        }

        if (remainingBits === 0) {
          return true;
        }

        const mask = (0xff << (8 - remainingBits)) & 0xff;

        return (
          (ipAddress.bytes[fullBytes] & mask) ===
          (cidrBlock.bytes[fullBytes] & mask)
        );
      }

      function isLikelyIpAddress(token) {
        const ipv4Pattern = /^(?:\\d{1,3}\\.){3}\\d{1,3}$/;
        const ipv6Pattern = /^[0-9a-f:]+$/i;

        if (ipv4Pattern.test(token)) {
          return true;
        }

        return token.includes(":") && ipv6Pattern.test(token);
      }

      function collectAddressTokens(value, tokens = new Set()) {
        if (value === null || value === undefined) {
          return tokens;
        }

        if (Array.isArray(value)) {
          for (const item of value) {
            collectAddressTokens(item, tokens);
          }

          return tokens;
        }

        if (typeof value === "object") {
          for (const item of Object.values(value)) {
            collectAddressTokens(item, tokens);
          }

          return tokens;
        }

        const raw = String(value);
        const segments = raw.split(/[\\s,]+/);

        for (const segment of segments) {
          const token = normalizeEndpointToken(segment);

          if (token && isLikelyIpAddress(token)) {
            tokens.add(token);
          }
        }

        return tokens;
      }

      function collectCidrBlocks(value, cidrBlocks = []) {
        if (value === null || value === undefined) {
          return cidrBlocks;
        }

        if (Array.isArray(value)) {
          for (const item of value) {
            collectCidrBlocks(item, cidrBlocks);
          }

          return cidrBlocks;
        }

        if (typeof value === "object") {
          for (const item of Object.values(value)) {
            collectCidrBlocks(item, cidrBlocks);
          }

          return cidrBlocks;
        }

        const raw = String(value);
        const segments = raw.split(/[\\s,]+/);

        for (const segment of segments) {
          const cidrBlock = parseCidr(segment);

          if (cidrBlock) {
            cidrBlocks.push(cidrBlock);
          }
        }

        return cidrBlocks;
      }

      function buildTunnelLookup(greTunnels, ipsecTunnels, cnis) {
        const exactLookup = new Map();
        const cidrLookup = [];

        function registerRecord(record, fallbackName) {
          const tunnelName =
            record?.name ||
            record?.tunnel_name ||
            record?.description ||
            record?.id ||
            fallbackName;

          const tokens = collectAddressTokens([
            record?.customer_gre_endpoint,
            record?.cloudflare_gre_endpoint,
            record?.customer_endpoint,
            record?.cloudflare_endpoint,
            record?.nexthop,
            record?.next_hop,
            record,
          ]);

          for (const token of tokens) {
            if (!exactLookup.has(token)) {
              exactLookup.set(token, tunnelName);
            }
          }

          const cidrBlocks = [];
          collectCidrBlocks(record?.interface_address, cidrBlocks);
          collectCidrBlocks(record?.interface_address6, cidrBlocks);

          for (const cidrBlock of cidrBlocks) {
            cidrLookup.push({
              name: tunnelName,
              cidr: cidrBlock,
            });
          }
        }

        greTunnels.forEach((record) => registerRecord(record, "GRE Tunnel"));
        ipsecTunnels.forEach((record) => registerRecord(record, "IPSEC Tunnel"));
        cnis.forEach((record) => registerRecord(record, "CNI"));

        return {
          exactLookup,
          cidrLookup,
        };
      }

      function resolveRouteTunnelName(route, tunnelLookup) {
        const nextHopValue = route?.nexthop ?? route?.next_hop;
        const tokens = collectAddressTokens(nextHopValue);

        for (const token of tokens) {
          const parsedIp = parseIpAddress(token);

          if (!parsedIp) {
            continue;
          }

          for (const entry of tunnelLookup.cidrLookup) {
            if (ipInCidr(parsedIp, entry.cidr)) {
              return entry.name;
            }
          }
        }

        for (const token of tokens) {
          if (tunnelLookup.exactLookup.has(token)) {
            return tunnelLookup.exactLookup.get(token);
          }
        }

        return "Unmapped";
      }

      function formatBooleanDisplay(value) {
        if (typeof value === "boolean") {
          return value ? "True" : "False";
        }

        return toDisplayValue(value);
      }

      function readBgpAdvertisedValue(record) {
        if (record && typeof record.advertised === "boolean") {
          return record.advertised;
        }

        if (record && record.on_demand && typeof record.on_demand.advertised === "boolean") {
          return record.on_demand.advertised;
        }

        return false;
      }

      function renderBgpAdvertisedStatus(advertised) {
        const isAdvertised = Boolean(advertised);
        const className = isAdvertised ? "bgp-status advertised" : "bgp-status withdrawn";
        const label = isAdvertised ? "Advertised" : "Withdrawn";
        return '<span class="' + className + '">' + label + "</span>";
      }

      function renderBgpPrefixEditButton(item, field, currentValue, title) {
        const prefixId = typeof item?.prefixId === "string" ? item.prefixId.trim() : "";
        const bgpPrefixId = typeof item?.bgpPrefixId === "string" ? item.bgpPrefixId.trim() : "";

        if (!prefixId || !bgpPrefixId) {
          return "";
        }

        return (
          '<button type="button" class="icon-button" data-action="edit-bgp-prefix-field" title="' +
          escapeHtml(title) +
          '" data-prefix-id="' +
          escapeHtml(prefixId) +
          '" data-bgp-prefix-id="' +
          escapeHtml(bgpPrefixId) +
          '" data-field="' +
          escapeHtml(field) +
          '" data-current-value="' +
          escapeHtml(String(currentValue ?? "")) +
          '">✎</button>'
        );
      }

      function renderBgpPrefixDeleteButton(item) {
        const prefixId = typeof item?.prefixId === "string" ? item.prefixId.trim() : "";
        const bgpPrefixId = typeof item?.bgpPrefixId === "string" ? item.bgpPrefixId.trim() : "";

        if (!prefixId || !bgpPrefixId) {
          return "";
        }

        const isAdvertised = Boolean(item?.advertised);
        const disabledReason = "Withdraw this prefix before deleting.";
        const prefixCidr = item?.prefix ?? "";
        const buttonHtml =
          '<button type="button" class="icon-button" data-action="delete-bgp-prefix" title="' +
          escapeHtml(isAdvertised ? disabledReason : "Delete BGP prefix") +
          '" data-prefix-id="' +
          escapeHtml(prefixId) +
          '" data-bgp-prefix-id="' +
          escapeHtml(bgpPrefixId) +
          '" data-prefix-cidr="' +
          escapeHtml(String(prefixCidr)) +
          '" data-advertised="' +
          (isAdvertised ? "true" : "false") +
          '"' +
          (isAdvertised ? " disabled" : "") +
          '">🗑</button>';

        if (!isAdvertised) {
          return buttonHtml;
        }

        return (
          '<span class="disabled-icon-hint" title="' +
          escapeHtml(disabledReason) +
          '">' +
          buttonHtml +
          "</span>"
        );
      }

      function renderBgpEditableCell(item, field, displayHtml, currentValue, title) {
        const editButton = renderBgpPrefixEditButton(item, field, currentValue, title);

        if (!editButton) {
          return displayHtml;
        }

        return (
          '<div class="editable-cell"><span class="editable-cell-value">' +
          displayHtml +
          "</span>" +
          editButton +
          "</div>"
        );
      }

      function parseBooleanPromptValue(rawValue, label) {
        const normalized = String(rawValue).trim().toLowerCase();

        if (
          normalized === "true" ||
          normalized === "1" ||
          normalized === "yes" ||
          normalized === "y" ||
          normalized === "on" ||
          normalized === "advertised"
        ) {
          return true;
        }

        if (
          normalized === "false" ||
          normalized === "0" ||
          normalized === "no" ||
          normalized === "n" ||
          normalized === "off" ||
          normalized === "withdrawn"
        ) {
          return false;
        }

        throw new Error(label + " must be true or false.");
      }

      function countBgpPrefixRows(prefixGroups) {
        let count = 0;

        for (const group of prefixGroups) {
          count += Array.isArray(group?.bgpPrefixes) ? group.bgpPrefixes.length : 0;
        }

        return count;
      }

      function renderOverviewBgpPrefixes(prefixGroups) {
        const rows = [];

        for (const group of prefixGroups) {
          const prefix = group?.prefix ?? {};
          const bgpPrefixes = Array.isArray(group?.bgpPrefixes) ? group.bgpPrefixes : [];

          for (const item of bgpPrefixes) {
            rows.push({
              prefix: item?.cidr ?? prefix?.cidr,
              asn: item?.asn ?? prefix?.asn,
              advertised: readBgpAdvertisedValue(item),
            });
          }
        }

        renderDataTable("overviewBgpPrefixes", rows, [
          {
            label: "Prefix",
            value: (item) => item.prefix,
          },
          {
            label: "ASN",
            value: (item) => item.asn,
          },
          {
            label: "Advertised",
            render: (item) => renderBgpAdvertisedStatus(item.advertised),
          },
        ]);
      }

      function renderMagicTransitBgpPrefixes(prefixGroups) {
        const rows = [];

        for (const group of prefixGroups) {
          const prefix = group?.prefix ?? {};
          const bgpPrefixes = Array.isArray(group?.bgpPrefixes) ? group.bgpPrefixes : [];

          for (const item of bgpPrefixes) {
            rows.push({
              prefixId: prefix?.id,
              bgpPrefixId: item?.id,
              prefix: item?.cidr ?? prefix.cidr,
              asn: item?.asn ?? prefix.asn,
              advertised: readBgpAdvertisedValue(item),
              asnPrepends: item?.asn_prepend_count,
              overlayBgpAdvertise: item?.auto_advertise_withdraw,
            });
          }
        }

        renderDataTable("magicBgpPrefixesTable", rows, [
          {
            label: "Prefix",
            value: (item) => item.prefix,
          },
          {
            label: "ASN",
            value: (item) => item.asn,
          },
          {
            label: "Advertised",
            render: (item) =>
              renderBgpEditableCell(
                item,
                "advertised",
                renderBgpAdvertisedStatus(item.advertised),
                item.advertised ? "true" : "false",
                "Edit advertised status",
              ),
          },
          {
            label: "ASN Prepends",
            render: (item) =>
              renderBgpEditableCell(
                item,
                "asn_prepend_count",
                escapeHtml(toDisplayValue(item.asnPrepends)),
                item.asnPrepends,
                "Edit ASN prepends",
              ),
          },
          {
            label: "Overlay BGP Advertisement to Internet",
            render: (item) =>
              renderBgpEditableCell(
                item,
                "auto_advertise_withdraw",
                escapeHtml(formatBooleanDisplay(item.overlayBgpAdvertise)),
                item.overlayBgpAdvertise ? "true" : "false",
                "Edit overlay BGP advertisement",
              ),
          },
          {
            label: "Delete",
            render: (item) => renderBgpPrefixDeleteButton(item) || "—",
          },
        ]);
      }

      function hideBgpCreateRow() {
        const createRow = document.getElementById("magicBgpCreateRow");

        if (!createRow) {
          return;
        }

        createRow.innerHTML = "";
        createRow.classList.add("hidden");
      }

      function syncBgpCreateCidrFromRootPrefix() {
        const rootPrefixInput = document.getElementById("bgpCreateRootPrefixId");
        const cidrInput = document.getElementById("bgpCreateCidrInput");

        if (!rootPrefixInput || !cidrInput) {
          return;
        }

        const selectedOption = rootPrefixInput.selectedOptions?.[0];

        if (!selectedOption) {
          return;
        }

        const defaultCidr = (selectedOption.getAttribute("data-default-cidr") ?? "").trim();

        if (defaultCidr) {
          cidrInput.value = defaultCidr;
        }
      }

      function renderBgpCreateRow(prefixes) {
        const createRow = document.getElementById("magicBgpCreateRow");

        if (!createRow) {
          return;
        }

        const selectablePrefixes = Array.isArray(prefixes)
          ? prefixes.filter((prefix) => typeof prefix?.id === "string" && prefix.id.trim())
          : [];

        if (!selectablePrefixes.length) {
          createRow.innerHTML = '<p class="hint">No account prefixes available for BGP creation.</p>';
          createRow.classList.remove("hidden");
          return;
        }

        const optionsHtml = selectablePrefixes
          .map((prefix, index) => {
            const prefixId = String(prefix.id).trim();
            const prefixCidr = toDisplayValue(prefix?.cidr);
            const prefixAsn = toDisplayValue(prefix?.asn);
            const label =
              prefixCidr +
              " (ASN: " +
              prefixAsn +
              ", ID: " +
              toDisplayValue(prefixId) +
              ")";
            const selected = index === 0 ? " selected" : "";

            return (
              '<option value="' +
              escapeHtml(prefixId) +
              '" data-default-cidr="' +
              escapeHtml(String(prefix?.cidr ?? "")) +
              '"' +
              selected +
              ">" +
              escapeHtml(label) +
              "</option>"
            );
          })
          .join("");

        createRow.innerHTML =
          '<div class="bgp-create-grid">' +
          '<div class="filter-block"><label class="label" for="bgpCreateRootPrefixId">Root IP Prefix</label><select id="bgpCreateRootPrefixId" data-action="bgp-create-root-prefix">' +
          optionsHtml +
          '</select></div>' +
          '<div class="filter-block"><label class="label" for="bgpCreateCidrInput">BGP Prefix CIDR</label><input id="bgpCreateCidrInput" type="text" placeholder="203.0.113.0/24" /></div>' +
          '<div class="filter-block"><label class="label" for="bgpCreateAdvertisedInput">Advertised</label><select id="bgpCreateAdvertisedInput"><option value="false" selected>False</option><option value="true">True</option></select></div>' +
          '<div class="filter-block"><label class="label" for="bgpCreateAsnPrependsInput">ASN Prepends</label><input id="bgpCreateAsnPrependsInput" type="number" min="0" step="1" value="0" /></div>' +
          '<div class="filter-block"><label class="label" for="bgpCreateAutoAdvertiseInput">Auto Advertise / Withdraw</label><select id="bgpCreateAutoAdvertiseInput"><option value="false" selected>False</option><option value="true">True</option></select></div>' +
          '<div class="bgp-create-actions"><button type="button" class="mini-button" data-action="cancel-create-bgp-prefix">Cancel</button><button type="button" class="mini-button" data-action="save-create-bgp-prefix">Create Prefix</button></div>' +
          "</div>";

        createRow.classList.remove("hidden");
        syncBgpCreateCidrFromRootPrefix();
      }

      async function handleCreateBgpPrefix() {
        setHintMessage(magicBgpStatus, "Loading account IP prefixes...");

        const prefixesPath = "/api/addressing/prefixes";
        const prefixesResponse = await callApi(prefixesPath, { showOutput: false });

        if (!prefixesResponse || !prefixesResponse.ok) {
          throw new Error(getNetworkFlowErrorMessage(prefixesResponse));
        }

        const accountPrefixes = extractResultArray(prefixesResponse.payload);
        renderBgpCreateRow(accountPrefixes);
        setHintMessage(magicBgpStatus, "Select create values and click Create Prefix.");
      }

      async function submitBgpPrefixCreateRow() {
        const rootPrefixId = readRequiredInput("bgpCreateRootPrefixId", "Root IP Prefix");
        const cidr = readRequiredInput("bgpCreateCidrInput", "BGP Prefix CIDR");

        const asnPrependsRaw =
          document.getElementById("bgpCreateAsnPrependsInput")?.value?.trim() ?? "0";
        const asnPrepends = Number(asnPrependsRaw);

        if (!Number.isInteger(asnPrepends) || asnPrepends < 0) {
          throw new Error("ASN Prepends must be a whole number that is 0 or greater.");
        }

        const advertisedRaw =
          document.getElementById("bgpCreateAdvertisedInput")?.value?.trim() ?? "false";
        const advertised = parseBooleanPromptValue(advertisedRaw, "Advertised status");
        const autoAdvertiseRaw =
          document.getElementById("bgpCreateAutoAdvertiseInput")?.value?.trim() ?? "false";
        const autoAdvertise = parseBooleanPromptValue(
          autoAdvertiseRaw,
          "Auto Advertise / Withdraw",
        );

        const path =
          "/api/addressing/prefixes/" + encodeURIComponent(rootPrefixId) + "/bgp/prefixes";
        setHintMessage(magicBgpStatus, "Creating BGP prefix...");

        const createResponse = await callApi(path, {
          method: "POST",
          body: {
            cidr,
          },
          showOutput: false,
        });

        if (!createResponse || !createResponse.ok) {
          throw new Error(getNetworkFlowErrorMessage(createResponse));
        }

        const createdBgpPrefixIdRaw =
          typeof createResponse.payload?.result?.id === "string"
            ? createResponse.payload.result.id
            : "";
        const createdBgpPrefixId = createdBgpPrefixIdRaw.trim();
        const followUpBody = {};

        if (advertised) {
          followUpBody.on_demand = {
            advertised,
          };
        }

        if (asnPrepends > 0) {
          followUpBody.asn_prepend_count = asnPrepends;
        }

        if (autoAdvertise) {
          followUpBody.auto_advertise_withdraw = autoAdvertise;
        }

        if (Object.keys(followUpBody).length) {
          if (!createdBgpPrefixId) {
            throw new Error(
              "BGP prefix was created, but no prefix ID was returned to apply create options.",
            );
          }

          const followUpPath =
            "/api/addressing/prefixes/" +
            encodeURIComponent(rootPrefixId) +
            "/bgp/prefixes/" +
            encodeURIComponent(createdBgpPrefixId);
          setHintMessage(magicBgpStatus, "Applying selected BGP options...");

          const followUpResponse = await callApi(followUpPath, {
            method: "PATCH",
            body: followUpBody,
            showOutput: false,
          });

          if (!followUpResponse || !followUpResponse.ok) {
            throw new Error(
              "BGP prefix was created, but applying selected options failed: " +
                getNetworkFlowErrorMessage(followUpResponse),
            );
          }
        }

        await Promise.all([
          loadMagicTransitOverview({ showOutput: false }),
          loadOverviewBgpPrefixes(),
        ]);

        hideBgpCreateRow();
        setOutput(true, "Created", "POST " + path, createResponse.payload);
        setHintMessage(magicBgpStatus, "BGP prefix created.");
      }

      async function handleBgpPrefixDelete(button) {
        const prefixId = (button.getAttribute("data-prefix-id") ?? "").trim();
        const bgpPrefixId = (button.getAttribute("data-bgp-prefix-id") ?? "").trim();
        const prefixCidr = (button.getAttribute("data-prefix-cidr") ?? "").trim();
        const advertisedRaw = (button.getAttribute("data-advertised") ?? "").trim();
        const isAdvertised = advertisedRaw.toLowerCase() === "true";

        if (!prefixId || !bgpPrefixId) {
          throw new Error("Missing BGP prefix identifiers for delete operation.");
        }

        if (isAdvertised) {
          throw new Error("BGP prefix must be withdrawn before deleting.");
        }

        const confirmed = window.confirm(
          "Delete BGP prefix " + (prefixCidr || bgpPrefixId) + "? This action cannot be undone.",
        );

        if (!confirmed) {
          return;
        }

        const path =
          "/api/addressing/prefixes/" +
          encodeURIComponent(prefixId) +
          "/bgp/prefixes/" +
          encodeURIComponent(bgpPrefixId);
        setHintMessage(magicBgpStatus, "Deleting BGP prefix...");

        const deleteResponse = await callApi(path, {
          method: "DELETE",
          showOutput: false,
        });

        if (!deleteResponse || !deleteResponse.ok) {
          throw new Error(getNetworkFlowErrorMessage(deleteResponse));
        }

        await Promise.all([
          loadMagicTransitOverview({ showOutput: false }),
          loadOverviewBgpPrefixes(),
        ]);

        setOutput(true, "Deleted", "DELETE " + path, deleteResponse.payload);
        setHintMessage(magicBgpStatus, "BGP prefix deleted.");
      }

      async function handleBgpPrefixFieldEdit(button) {
        const prefixId = (button.getAttribute("data-prefix-id") ?? "").trim();
        const bgpPrefixId = (button.getAttribute("data-bgp-prefix-id") ?? "").trim();
        const field = (button.getAttribute("data-field") ?? "").trim();
        const currentValue = (button.getAttribute("data-current-value") ?? "").trim();

        if (!prefixId || !bgpPrefixId || !field) {
          throw new Error("Missing BGP prefix identifiers for edit operation.");
        }

        let requestBody;

        if (field === "advertised") {
          const nextValueRaw = window.prompt(
            "Set Advertised status (true/false).",
            currentValue || "false",
          );

          if (nextValueRaw === null) {
            return;
          }

          requestBody = {
            on_demand: {
              advertised: parseBooleanPromptValue(nextValueRaw, "Advertised status"),
            },
          };
        } else if (field === "asn_prepend_count") {
          const nextValueRaw = window.prompt(
            "Set ASN Prepends (integer, 0 or greater).",
            currentValue || "0",
          );

          if (nextValueRaw === null) {
            return;
          }

          const parsed = Number(nextValueRaw);

          if (!Number.isInteger(parsed) || parsed < 0) {
            throw new Error("ASN Prepends must be a whole number that is 0 or greater.");
          }

          requestBody = {
            asn_prepend_count: parsed,
          };
        } else if (field === "auto_advertise_withdraw") {
          const nextValueRaw = window.prompt(
            "Set Overlay BGP Advertisement to Internet (true/false).",
            currentValue || "false",
          );

          if (nextValueRaw === null) {
            return;
          }

          requestBody = {
            auto_advertise_withdraw: parseBooleanPromptValue(
              nextValueRaw,
              "Overlay BGP Advertisement to Internet",
            ),
          };
        } else {
          throw new Error("Unsupported BGP field edit: " + field);
        }

        const path =
          "/api/addressing/prefixes/" +
          encodeURIComponent(prefixId) +
          "/bgp/prefixes/" +
          encodeURIComponent(bgpPrefixId);

        setHintMessage(magicBgpStatus, "Updating BGP prefix...");

        const updateResponse = await callApi(path, {
          method: "PATCH",
          body: requestBody,
        });

        if (!updateResponse || !updateResponse.ok) {
          throw new Error(getNetworkFlowErrorMessage(updateResponse));
        }

        await Promise.all([
          loadMagicTransitOverview({ showOutput: false }),
          loadOverviewBgpPrefixes(),
        ]);

        setHintMessage(magicBgpStatus, "BGP prefix updated.");
      }

      async function loadAddressingPrefixGroups() {
        const errors = [];
        const groups = [];
        const listPrefixesPath = "/api/addressing/prefixes";
        const prefixesResponse = await callApi(listPrefixesPath, { showOutput: false });

        if (!prefixesResponse || !prefixesResponse.ok) {
          errors.push({
            endpoint: listPrefixesPath,
            status: prefixesResponse
              ? prefixesResponse.status + " " + prefixesResponse.statusText
              : "No response",
            payload: prefixesResponse ? prefixesResponse.payload : null,
          });

          return {
            groups,
            errors,
          };
        }

        const prefixes = extractResultArray(prefixesResponse.payload);

        for (const prefix of prefixes) {
          const prefixId = typeof prefix?.id === "string" ? prefix.id.trim() : "";

          if (!prefixId) {
            groups.push({
              prefix,
              bgpPrefixes: [],
            });
            continue;
          }

          const listBgpPath =
            "/api/addressing/prefixes/" + encodeURIComponent(prefixId) + "/bgp/prefixes";
          const bgpResponse = await callApi(listBgpPath, { showOutput: false });

          if (!bgpResponse || !bgpResponse.ok) {
            errors.push({
              endpoint: listBgpPath,
              status: bgpResponse
                ? bgpResponse.status + " " + bgpResponse.statusText
                : "No response",
              payload: bgpResponse ? bgpResponse.payload : null,
            });
            groups.push({
              prefix,
              bgpPrefixes: [],
            });
            continue;
          }

          groups.push({
            prefix,
            bgpPrefixes: extractResultArray(bgpResponse.payload),
          });
        }

        return {
          groups,
          errors,
        };
      }

      async function loadOverviewBgpPrefixes() {
        setHintMessage(bgpOverviewStatus, "Loading BGP prefixes...");

        const result = await loadAddressingPrefixGroups();
        const totalPrefixes = result.groups.length;
        const totalBgpPrefixes = countBgpPrefixRows(result.groups);

        renderOverviewBgpPrefixes(result.groups);

        if (result.errors.length) {
          setHintMessage(
            bgpOverviewStatus,
            "Loaded " +
              formatAnalyticsNumber(totalBgpPrefixes) +
              " BGP prefixes across " +
              formatAnalyticsNumber(totalPrefixes) +
              " account prefixes with errors.",
            true,
          );
          return;
        }

        setHintMessage(
          bgpOverviewStatus,
          "Loaded " +
            formatAnalyticsNumber(totalBgpPrefixes) +
            " BGP prefixes across " +
            formatAnalyticsNumber(totalPrefixes) +
            " account prefixes.",
        );
      }

      async function loadMagicTransitOverview(options = {}) {
        const showOutput = options.showOutput !== false;
        magicTransitStatus.textContent = "Loading magic transit resources...";
        magicTransitStatus.classList.remove("err");
        setHintMessage(magicBgpStatus, "Loading BGP prefixes...");

        const endpoints = [
          { key: "gre", path: "/api/magic/gre_tunnels" },
          { key: "ipsec", path: "/api/magic/ipsec_tunnels" },
          { key: "routes", path: "/api/magic/routes" },
          { key: "cnis", path: "/api/magic/cf_interconnects" },
        ];

        const responses = await Promise.all(
          endpoints.map((entry) => callApi(entry.path, { showOutput: false })),
        );

        const collected = {};
        const errors = [];

        for (let index = 0; index < endpoints.length; index += 1) {
          const endpoint = endpoints[index];
          const response = responses[index];

          if (!response || !response.ok) {
            errors.push({
              endpoint: endpoint.path,
              status: response
                ? response.status + " " + response.statusText
                : "No response",
              payload: response ? response.payload : null,
            });
            collected[endpoint.key] = [];
            continue;
          }

          collected[endpoint.key] = extractResultArray(response.payload);
        }

        const bgpPrefixResult = await loadAddressingPrefixGroups();
        const bgpPrefixCount = countBgpPrefixRows(bgpPrefixResult.groups);

        renderMagicTransitBgpPrefixes(bgpPrefixResult.groups);

        if (bgpPrefixResult.errors.length) {
          setHintMessage(
            magicBgpStatus,
            "Loaded " + formatAnalyticsNumber(bgpPrefixCount) + " BGP prefixes with errors.",
            true,
          );
          errors.push(...bgpPrefixResult.errors);
        } else {
          setHintMessage(
            magicBgpStatus,
            "Loaded " + formatAnalyticsNumber(bgpPrefixCount) + " BGP prefixes.",
          );
        }

        renderDataTable("greTunnelTable", collected.gre ?? [], [
          { label: "Type", value: () => "GRE" },
          { label: "Name", value: (item) => item.name },
          { label: "Description", value: (item) => item.description },
          {
            label: "Cust Tunnel Endpoint",
            value: (item) => item.customer_gre_endpoint,
          },
          {
            label: "CF Tunnel Endpoint",
            value: (item) => item.cloudflare_gre_endpoint,
          },
          { label: "CF VTI IPv4", value: (item) => item.interface_address },
          { label: "CF VTI IPv6", value: (item) => item.interface_address6 },
          { label: "Health Target", value: (item) => item.health_check?.target },
        ]);

        renderDataTable("ipsecTunnelTable", collected.ipsec ?? [], [
          { label: "Type", value: () => "IPSEC" },
          { label: "Name", value: (item) => item.name },
          { label: "Description", value: (item) => item.description },
          {
            label: "Cust Tunnel Endpoint",
            value: (item) => item.customer_endpoint,
          },
          {
            label: "CF Tunnel Endpoint",
            value: (item) => item.cloudflare_endpoint,
          },
          { label: "CF VTI IPv4", value: (item) => item.interface_address },
          { label: "CF VTI IPv6", value: (item) => item.interface_address6 },
          { label: "Health Target", value: (item) => item.health_check?.target },
        ]);

        renderDataTable("cnisTable", collected.cnis ?? [], [
          { label: "Type", value: () => "CNI" },
          { label: "Name", value: (item) => item.name },
          { label: "Description", value: (item) => item.description },
          { label: "Version", value: (item) => item.version },
          { label: "POP", value: (item) => item.pop_name },
          { label: "Interface", value: (item) => item.interface_name },
          {
            label: "Cust Tunnel Endpoint",
            value: (item) => item.gre?.customer_endpoint,
          },
          {
            label: "CF Tunnel Endpoint",
            value: (item) => item.gre?.cloudflare_endpoint,
          },
          {
            label: "CNI IP Address",
            value: (item) => item.interface_address,
          },
          { label: "Health Target", value: (item) => item.health_check?.target },
        ]);

        const tunnelLookup = buildTunnelLookup(
          collected.gre ?? [],
          collected.ipsec ?? [],
          collected.cnis ?? [],
        );

        renderDataTable("routesTable", collected.routes ?? [], [
          { label: "Route", value: (item) => item.prefix },
          { label: "Description", value: (item) => item.description },
          { label: "Priority", value: (item) => item.priority },
          {
            label: "Tunnel",
            value: (item) => resolveRouteTunnelName(item, tunnelLookup),
          },
          { label: "Next Hop", value: (item) => item.nexthop ?? item.next_hop },
        ]);

        const summary = {
          gre_tunnels: (collected.gre ?? []).length,
          ipsec_tunnels: (collected.ipsec ?? []).length,
          routes: (collected.routes ?? []).length,
          cnis: (collected.cnis ?? []).length,
          addressing_prefixes: bgpPrefixResult.groups.length,
          bgp_prefixes: bgpPrefixCount,
        };

        if (errors.length) {
          magicTransitStatus.textContent =
            "Loaded with errors. Check response output for details.";
          magicTransitStatus.classList.add("err");

          if (showOutput) {
            setOutput(false, "Partial load", "GET /api/magic/*", {
              summary,
              errors,
            });
          }

          return;
        }

        magicTransitStatus.textContent = "Loaded successfully.";

        if (showOutput) {
          setOutput(true, "Loaded", "GET /api/magic/*", summary);
        }
      }

      async function loadConfig() {
        try {
          const response = await callApi("/api/config", {
            showOutput: false,
            timeoutMs: 8_000,
          });

          if (
            !response ||
            !response.ok ||
            !response.payload ||
            typeof response.payload !== "object" ||
            Array.isArray(response.payload)
          ) {
            throw new Error(getNetworkFlowErrorMessage(response));
          }

          const config = response.payload;

          const accountName =
            config && typeof config.accountName === "string" ? config.accountName.trim() : "";
          const accountId =
            config && typeof config.accountId === "string" ? config.accountId.trim() : "";

          envAccountName.textContent = accountName || "(name unavailable)";
          envAccountId.textContent = accountId || "(not set)";

          setOutput(true, "Loaded", "GET /api/config", {
            accountName: accountName || "(name unavailable)",
            accountId: accountId || "(not set)",
            hasBearerToken: Boolean(config.hasBearerToken),
            bearerSource: typeof config.bearerSource === "string" ? config.bearerSource : "",
          });

          if (config.accountLookupError) {
            setOutput(false, "Account lookup warning", "GET /api/config", {
              message: config.accountLookupError,
            });
          }
        } catch (error) {
          const message = error instanceof Error ? error.message : String(error);
          envAccountName.textContent = "Failed to load";
          envAccountId.textContent = "Failed to load";
          setClientError("Unable to load config: " + message);
        }
      }

      function formatRecentDdosDisplayTime(value) {
        const text = toDisplayValue(value);

        if (text === "—") {
          return text;
        }

        const parsed = Date.parse(String(value));
        return Number.isFinite(parsed) ? new Date(parsed).toLocaleString() : text;
      }

      function renderRecentDdosEvents(rows) {
        renderDataTable("recentDdosEventsTable", rows, [
          {
            label: "Time",
            value: (entry) => formatRecentDdosDisplayTime(entry.datetimeIso),
          },
          {
            label: "Attack ID",
            value: (entry) => entry.attackId,
          },
          {
            label: "Attack Type",
            value: (entry) => entry.context,
          },
          {
            label: "Attack Vector",
            value: (entry) => entry.attackVector,
          },
          {
            label: "Source IP",
            value: (entry) => entry.sourceIp,
          },
          {
            label: "Destination IP",
            value: (entry) => entry.destinationIp,
          },
        ]);
      }

      async function loadRecentDdosEvents() {
        try {
          setHintMessage(recentDdosStatus, "Loading recent DDoS attack events...");

          const endMs = Date.now();
          const filters = {
            dataset: "attack",
            searchField: "attackId",
            searchTokens: [],
            timeRange: {
              startIso: new Date(endMs - ANALYTICS_TIME_UNIT_TO_MS.days).toISOString(),
              endIso: new Date(endMs).toISOString(),
            },
          };
          const accountTag = await resolveGraphqlAccountId();
          const candidateFields = await loadDdosGraphDatetimeFieldCandidates(filters.dataset);
          let rows = [];
          let usedDatetimeField = "";

          for (const datetimeField of candidateFields) {
            const response = await callApi("/api/graphql", {
              method: "POST",
              body: buildDdosGraphRequest(filters, accountTag, datetimeField),
              showOutput: false,
            });

            if (!response || !response.ok) {
              throw new Error(getNetworkFlowErrorMessage(response));
            }

            const graphqlErrors = Array.isArray(response.payload?.errors)
              ? response.payload.errors
              : [];

            if (graphqlErrors.length) {
              const graphQlMessage = graphqlErrors
                .map((item) => toAnalyticsText(item?.message))
                .filter(Boolean)
                .join("; ");

              if (isUnknownFieldGraphQlError(graphQlMessage, datetimeField)) {
                continue;
              }

              throw new Error("Cloudflare GraphQL returned errors: " + (graphQlMessage || "Unknown"));
            }

            rows = extractDosdAttackAnalyticsRows(response.payload, datetimeField);
            usedDatetimeField = datetimeField;
            ddosGraphDatetimeFieldByDataset.attack = datetimeField;
            break;
          }

          if (!usedDatetimeField) {
            throw new Error("Unable to resolve a supported datetime field for DDoS attack events.");
          }

          const recentRows = [...rows]
            .sort((left, right) => (right.timestampMs ?? 0) - (left.timestampMs ?? 0))
            .slice(0, RECENT_DDOS_ROW_LIMIT);

          renderRecentDdosEvents(recentRows);
          setHintMessage(
            recentDdosStatus,
            recentRows.length
              ? "Loaded the newest DDoS attack events from the last 24 hours."
              : "No DDoS attack events were returned for the last 24 hours.",
          );
        } catch (error) {
          const message = error instanceof Error ? error.message : String(error);
          setHintMessage(recentDdosStatus, message, true);
          renderDataTable("recentDdosEventsTable", [], []);
        }
      }

      function addElementListener(id, eventName, handler) {
        const element = document.getElementById(id);

        if (!element) {
          return null;
        }

        element.addEventListener(eventName, handler);
        return element;
      }

      addElementListener("btnRefreshNetworkFlow", "click", () => {
        loadNetworkFlowRules();
      });

      addElementListener("btnRefreshFlowtrackd", "click", () => {
        flowtrackdLoaded = false;
        loadFlowtrackdDashboard();
      });

      addElementListener("btnApplyFlowtrackdStatus", "click", (event) => {
        applyFlowtrackdStatus(event.currentTarget);
      });

      addElementListener("btnAddStaticRuleRow", "click", () => {
        addNetworkFlowDraftRow("static");
      });

      addElementListener("btnAddDynamicRuleRow", "click", () => {
        addNetworkFlowDraftRow("dynamic");
      });

      addElementListener("btnAddSflowRuleRow", "click", () => {
        addNetworkFlowDraftRow("sflow");
      });

      document.addEventListener("input", (event) => {
        const draftControl = event.target.closest("[data-network-flow-draft='true']");

        if (draftControl) {
          updateNetworkFlowDraftValue(draftControl);
        }
      });

      document.addEventListener("change", (event) => {
        const draftControl = event.target.closest("[data-network-flow-draft='true']");

        if (draftControl) {
          updateNetworkFlowDraftValue(draftControl);
        }

        const flowtrackdScopeControl = event.target.closest(
          '[data-flowtrackd-field="scope"]',
        );

        if (flowtrackdScopeControl) {
          syncFlowtrackdScopeName(flowtrackdScopeControl);
        }

        const bgpCreateRootPrefixInput = event.target.closest(
          "[data-action='bgp-create-root-prefix']",
        );

        if (bgpCreateRootPrefixInput) {
          syncBgpCreateCidrFromRootPrefix();
          return;
        }

        const apiTunnelSeriesToggleInput = event.target.closest(
          "[data-action='toggle-api-tunnel-series']",
        );

        if (apiTunnelSeriesToggleInput) {
          handleApiTunnelSeriesSelectionToggle(apiTunnelSeriesToggleInput);
        }
      });

      document.addEventListener("click", (event) => {
        const flowtrackdToggleCreateButton = event.target.closest(
          "[data-action='flowtrackd-toggle-create']",
        );

        if (flowtrackdToggleCreateButton) {
          toggleFlowtrackdCreateForm(flowtrackdToggleCreateButton);
          return;
        }

        const flowtrackdCreateButton = event.target.closest(
          "[data-action='flowtrackd-create']",
        );

        if (flowtrackdCreateButton) {
          createFlowtrackdResource(flowtrackdCreateButton).catch((error) => {
            const message = error instanceof Error ? error.message : String(error);
            setHintMessage(flowtrackdStatus, message, true);
            setClientError(message);
          });
          return;
        }

        const flowtrackdSaveButton = event.target.closest(
          "[data-action='flowtrackd-save']",
        );

        if (flowtrackdSaveButton) {
          saveFlowtrackdResource(flowtrackdSaveButton).catch((error) => {
            const message = error instanceof Error ? error.message : String(error);
            setHintMessage(flowtrackdStatus, message, true);
            setClientError(message);
          });
          return;
        }

        const flowtrackdDeleteButton = event.target.closest(
          "[data-action='flowtrackd-delete']",
        );

        if (flowtrackdDeleteButton) {
          deleteFlowtrackdResource(flowtrackdDeleteButton).catch((error) => {
            const message = error instanceof Error ? error.message : String(error);
            setHintMessage(flowtrackdStatus, message, true);
            setClientError(message);
          });
          return;
        }

        const flowtrackdDeleteAllButton = event.target.closest(
          "[data-action='flowtrackd-delete-all']",
        );

        if (flowtrackdDeleteAllButton) {
          deleteAllFlowtrackdResources(flowtrackdDeleteAllButton).catch((error) => {
            const message = error instanceof Error ? error.message : String(error);
            setHintMessage(flowtrackdStatus, message, true);
            setClientError(message);
          });
          return;
        }

        const saveCreateBgpPrefixButton = event.target.closest(
          "[data-action='save-create-bgp-prefix']",
        );

        if (saveCreateBgpPrefixButton) {
          submitBgpPrefixCreateRow().catch((error) => {
            const message = error instanceof Error ? error.message : String(error);
            setHintMessage(magicBgpStatus, message, true);
            setClientError(message);
          });
          return;
        }

        const cancelCreateBgpPrefixButton = event.target.closest(
          "[data-action='cancel-create-bgp-prefix']",
        );

        if (cancelCreateBgpPrefixButton) {
          hideBgpCreateRow();
          setHintMessage(magicBgpStatus, "Create BGP prefix cancelled.");
          return;
        }

        const saveDraftButton = event.target.closest("[data-action='save-network-flow-draft']");

        if (saveDraftButton) {
          saveNetworkFlowDraft(saveDraftButton);
          return;
        }

        const removeDraftButton = event.target.closest("[data-action='remove-network-flow-draft']");

        if (removeDraftButton) {
          const draftId = removeDraftButton.getAttribute("data-draft-id");

          if (draftId) {
            removeNetworkFlowDraftRow(draftId);
          }

          return;
        }

        const deleteRuleButton = event.target.closest("[data-action='delete-network-flow-rule']");

        if (deleteRuleButton) {
          handleNetworkFlowRuleDelete(deleteRuleButton).catch((error) => {
            const message = error instanceof Error ? error.message : String(error);
            setHintMessage(networkFlowStatus, message, true);
            setClientError(message);
          });
          return;
        }

        const editButton = event.target.closest("[data-action='edit-network-flow-field']");

        if (editButton) {
          beginNetworkFlowEdit(editButton);
          return;
        }

        const editBgpButton = event.target.closest("[data-action='edit-bgp-prefix-field']");

        if (editBgpButton) {
          handleBgpPrefixFieldEdit(editBgpButton).catch((error) => {
            const message = error instanceof Error ? error.message : String(error);
            setHintMessage(magicBgpStatus, message, true);
            setClientError(message);
          });
          return;
        }

        const deleteBgpButton = event.target.closest("[data-action='delete-bgp-prefix']");

        if (deleteBgpButton) {
          handleBgpPrefixDelete(deleteBgpButton).catch((error) => {
            const message = error instanceof Error ? error.message : String(error);
            setHintMessage(magicBgpStatus, message, true);
            setClientError(message);
          });
        }
      });

      addElementListener("btnCreateBgpPrefix", "click", () => {
        handleCreateBgpPrefix().catch((error) => {
          const message = error instanceof Error ? error.message : String(error);
          setHintMessage(magicBgpStatus, message, true);
          setClientError(message);
        });
      });

      addElementListener("btnLoadMagicTransit", "click", loadMagicTransitOverview);

      addElementListener("ddosGraphTimeMode", "change", () => {
        updateAnalyticsTimeModeVisibility("ddosGraph");
      });

      addElementListener("btnRunOverviewTunnelHealth", "click", runOverviewTunnelHealthQuery);

      addElementListener("btnRunApiAnalytics", "click", runApiAnalyticsQuery);

      addElementListener("btnRunUsage", "click", runUsageQuery);

      addElementListener("usageLookbackDays", "change", () => {
        usageLoaded = false;
        setHintMessage(usageStatus, "Measurement window changed. Calculate P95 usage to refresh.");
      });

      addElementListener("ddosGraphDataset", "change", buildDdosGraphSearchFieldOptions);

      addElementListener("ddosGraphSearchField", "change", updateDdosGraphSearchPlaceholder);

      addElementListener("btnRunDdosGraph", "click", runDdosGraphQuery);

      addElementListener("graphqlSchemaPreset", "change", applyGraphqlSchemaExplorerPreset);

      addElementListener("btnApplyGraphqlSchemaPreset", "click", applyGraphqlSchemaExplorerPreset);

      addElementListener("btnRunGraphqlSchemaQuery", "click", runGraphqlSchemaExplorerQuery);

      initializeApiAnalyticsDefaults();
      initializeDdosGraphDefaults();
      initializeOverviewTunnelHealthDefaults();
      initializeGraphqlSchemaExplorerDefaults();
      updateAnalyticsTimeModeVisibility("ddosGraph");

      for (const scopeControl of document.querySelectorAll('[data-flowtrackd-field="scope"]')) {
        syncFlowtrackdScopeName(scopeControl);
      }

      window.addEventListener("error", (event) => {
        const message =
          event?.error instanceof Error
            ? event.error.message
            : typeof event?.message === "string"
              ? event.message
              : "Unknown UI runtime error.";
        envAccountName.textContent = "Failed to load";
        envAccountId.textContent = "Failed to load";
        setClientError("UI runtime error: " + message);
      });

      window.addEventListener("unhandledrejection", (event) => {
        const reason = event?.reason;
        const message = reason instanceof Error ? reason.message : String(reason ?? "Unknown");
        setClientError("Unhandled async error: " + message);
      });

      loadConfig();
      loadRecentDdosEvents();
      loadOverviewBgpPrefixes().catch((error) => {
        const message = error instanceof Error ? error.message : String(error);
        setHintMessage(bgpOverviewStatus, message, true);
        setClientError(message);
      });
      runOverviewTunnelHealthQuery();
    </script>
  </body>
</html>`;
}

export {
  calculateNearestRankPercentile,
  calculateTunnelUsageSummary,
  normalizeAdvancedTcpProtectionBody,
  parseAdvancedTcpProtectionStatus,
  renderUi,
  resolveAdvancedTcpProtectionRoute,
};
