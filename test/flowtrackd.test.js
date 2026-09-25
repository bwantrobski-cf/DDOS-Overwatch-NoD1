import assert from "node:assert/strict";
import test from "node:test";

import worker, {
  normalizeAdvancedTcpProtectionBody,
  parseAdvancedTcpProtectionStatus,
  renderUi,
  resolveAdvancedTcpProtectionRoute,
} from "../src/index.js";

function route(path) {
  return resolveAdvancedTcpProtectionRoute(path.split("/").filter(Boolean));
}

test("resolveAdvancedTcpProtectionRoute maps every Advanced TCP API collection", () => {
  assert.deepEqual(route("/api/ddos-protection/status"), {
    cloudflarePath: "/magic/advanced_tcp_protection/configs/tcp_protection_status",
    allowedMethods: ["GET", "PATCH"],
    bodyType: "status",
  });
  assert.equal(
    route("/api/ddos-protection/prefixes").cloudflarePath,
    "/magic/advanced_tcp_protection/configs/prefixes",
  );
  assert.equal(
    route("/api/ddos-protection/prefixes/bulk").cloudflarePath,
    "/magic/advanced_tcp_protection/configs/prefixes/bulk",
  );
  assert.equal(
    route("/api/ddos-protection/allowlist/item-1").cloudflarePath,
    "/magic/advanced_tcp_protection/configs/allowlist/item-1",
  );
  assert.equal(
    route("/api/ddos-protection/syn/rules").cloudflarePath,
    "/magic/advanced_tcp_protection/configs/syn_protection/rules",
  );
  assert.equal(
    route("/api/ddos-protection/syn/filters/filter-1").cloudflarePath,
    "/magic/advanced_tcp_protection/configs/syn_protection/filters/filter-1",
  );
  assert.equal(
    route("/api/ddos-protection/tcp-flow/rules/rule-1").cloudflarePath,
    "/magic/advanced_tcp_protection/configs/tcp_flow_protection/rules/rule-1",
  );
  assert.equal(
    route("/api/ddos-protection/tcp-flow/filters").cloudflarePath,
    "/magic/advanced_tcp_protection/configs/tcp_flow_protection/filters",
  );
  assert.equal(route("/api/ddos-protection/unknown"), null);
});

test("normalizeAdvancedTcpProtectionBody validates status, rules, filters, and prefixes", () => {
  assert.deepEqual(normalizeAdvancedTcpProtectionBody("status", { enabled: true }), {
    enabled: true,
  });
  assert.deepEqual(
    normalizeAdvancedTcpProtectionBody("synRule", {
      scope: "datacenter",
      name: "lax",
      mode: "monitoring",
      rate_sensitivity: "medium",
      burst_sensitivity: "high",
      mitigation_type: "challenge",
    }),
    {
      scope: "datacenter",
      name: "lax",
      mode: "monitoring",
      rate_sensitivity: "medium",
      burst_sensitivity: "high",
      mitigation_type: "challenge",
    },
  );
  assert.deepEqual(
    normalizeAdvancedTcpProtectionBody("filter", {
      expression: "ip.dst in { 192.0.2.0/24 } and tcp.dstport in { 443 }",
      mode: "disabled",
    }),
    {
      expression: "ip.dst in { 192.0.2.0/24 } and tcp.dstport in { 443 }",
      mode: "disabled",
    },
  );
  assert.equal(
    normalizeAdvancedTcpProtectionBody("prefixBulk", [
      { prefix: "192.0.2.0/24", comment: "Primary", excluded: false },
      { prefix: "192.0.2.64/26", comment: "Excluded", excluded: true },
    ]).length,
    2,
  );
  assert.throws(
    () =>
      normalizeAdvancedTcpProtectionBody("tcpRule", {
        scope: "global",
        name: "not-global",
        mode: "enabled",
        rate_sensitivity: "medium",
        burst_sensitivity: "medium",
      }),
    /must use `global`/,
  );
  assert.throws(
    () => normalizeAdvancedTcpProtectionBody("status", { enabled: "true" }),
    /must be boolean/,
  );
});

test("parseAdvancedTcpProtectionStatus handles supported Cloudflare response shapes", () => {
  assert.equal(parseAdvancedTcpProtectionStatus({ result: { enabled: true } }), true);
  assert.equal(parseAdvancedTcpProtectionStatus({ result: { enabled: false } }), false);
  assert.equal(parseAdvancedTcpProtectionStatus({ result: true }), true);
  assert.equal(parseAdvancedTcpProtectionStatus({ enabled: "disabled" }), false);
  assert.equal(parseAdvancedTcpProtectionStatus({ result: {} }), null);
});

test("Worker exposes one Account ID for REST and GraphQL configuration", async () => {
  const response = await worker.fetch(
    new Request("https://worker.example/api/config"),
    { ACCOUNT_ID: "account-123" },
  );
  const payload = await response.json();

  assert.equal(payload.accountId, "account-123");
  assert.equal("accountTag" in payload, false);
});

test("Worker proxies validated FlowtrackD requests to the account-scoped Cloudflare endpoint", async () => {
  const originalFetch = globalThis.fetch;
  let upstreamRequest;

  globalThis.fetch = async (url, init) => {
    upstreamRequest = { url: String(url), init };
    return new Response(JSON.stringify({ success: true, result: { id: "rule-1" } }), {
      status: 200,
      headers: { "content-type": "application/json" },
    });
  };

  try {
    const response = await worker.fetch(
      new Request("https://worker.example/api/ddos-protection/tcp-flow/rules", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          scope: "datacenter",
          name: "lax",
          mode: "monitoring",
          rate_sensitivity: "low",
          burst_sensitivity: "medium",
        }),
      }),
      {
        ACCOUNT_ID: "account-123",
        API_BEARER: "test-token",
      },
    );

    assert.equal(response.status, 200);
    assert.equal(
      upstreamRequest.url,
      "https://api.cloudflare.com/client/v4/accounts/account-123/magic/advanced_tcp_protection/configs/tcp_flow_protection/rules",
    );
    assert.equal(upstreamRequest.init.method, "POST");
    assert.equal(upstreamRequest.init.headers.Authorization, "Bearer test-token");
    assert.deepEqual(JSON.parse(upstreamRequest.init.body), {
      scope: "datacenter",
      name: "lax",
      mode: "monitoring",
      rate_sensitivity: "low",
      burst_sensitivity: "medium",
    });
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("renderUi orders Magic Transit, Network Flow, FlowtrackD, then Usage", () => {
  const html = renderUi();
  const magicIndex = html.indexOf('data-tab="network"');
  const networkFlowIndex = html.indexOf('data-tab="rules"');
  const flowtrackdIndex = html.indexOf('data-tab="flowtrackd"');
  const usageIndex = html.indexOf('data-tab="usage"');

  assert.ok(magicIndex < networkFlowIndex);
  assert.ok(networkFlowIndex < flowtrackdIndex);
  assert.ok(flowtrackdIndex < usageIndex);
  assert.match(html, /id="tab-flowtrackd"/);
  assert.doesNotMatch(html, /formatRecentAlertDisplayTime/);
  assert.match(html, /function formatDisplayTime/);
  assert.doesNotMatch(html, /Analytics \(D1\)|analytics-d1|recentWebhook/i);
  assert.match(html, /Recent DDoS Events from Cloudflare GraphQL/);
  assert.match(html, /SYN flood protection rules/);
  assert.match(html, /Out-of-state TCP protection filters/);
  assert.match(html, /\/api\/ddos-protection\/tcp-flow\/rules/);
  assert.match(html, /\{ value: "false", label: "Protected" \}/);
  assert.match(html, /\{ value: "true", label: "Excluded" \}/);

  for (const resource of ["synRules", "synFilters", "tcpRules", "tcpFilters"]) {
    assert.match(
      html,
      new RegExp(
        'class="flowtrackd-create-form hidden" data-flowtrackd-create-form="' + resource + '"',
      ),
    );
    assert.match(
      html,
      new RegExp(
        'data-action="flowtrackd-toggle-create" aria-expanded="false" data-resource="' + resource,
      ),
    );
  }
});
