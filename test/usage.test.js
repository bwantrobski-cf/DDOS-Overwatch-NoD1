import assert from "node:assert/strict";
import test from "node:test";

import {
  calculateNearestRankPercentile,
  calculateTunnelUsageSummary,
  renderUi,
} from "../src/index.js";

const intervalMs = 5 * 60 * 1000;

test("calculateNearestRankPercentile uses the nearest-rank method", () => {
  assert.equal(calculateNearestRankPercentile([], 95), 0);
  assert.equal(calculateNearestRankPercentile([1], 95), 1);
  assert.equal(
    calculateNearestRankPercentile(Array.from({ length: 20 }, (_, index) => index + 1), 95),
    19,
  );
  assert.equal(calculateNearestRankPercentile([10, -1, Number.NaN, 30], 50), 10);
});

test("calculateTunnelUsageSummary includes zero-filled intervals and sums tunnel P95s", () => {
  const sampleCount = 20;
  const ingressRows = [];
  const egressRows = [];

  for (let index = 0; index < sampleCount; index += 1) {
    ingressRows.push({
      tunnelName: "Tunnel A",
      timestampMs: index * intervalMs,
      bitRateBps: index + 1,
    });
    ingressRows.push({
      tunnelName: "Tunnel B",
      timestampMs: index * intervalMs,
      bitRateBps: 10,
    });
    egressRows.push({
      tunnelName: "tunnel a",
      timestampMs: index * intervalMs,
      bitRateBps: 2,
    });
  }

  ingressRows.push({
    tunnelName: "Tunnel C",
    timestampMs: 0,
    bitRateBps: 100,
  });

  const summary = calculateTunnelUsageSummary({
    rowsByDirection: {
      ingress: ingressRows,
      egress: egressRows,
    },
    tunnelNames: ["Tunnel A", "Tunnel B", "Tunnel C"],
    startMs: 0,
    endMs: sampleCount * intervalMs,
  });
  const tunnelA = summary.tunnels.find((tunnel) => tunnel.tunnelName === "Tunnel A");
  const tunnelB = summary.tunnels.find((tunnel) => tunnel.tunnelName === "Tunnel B");
  const tunnelC = summary.tunnels.find((tunnel) => tunnel.tunnelName === "Tunnel C");

  assert.equal(summary.sampleCount, 20);
  assert.equal(summary.tunnels.length, 3);
  assert.equal(tunnelA.ingressP95Bps, 19);
  assert.equal(tunnelA.egressP95Bps, 2);
  assert.equal(tunnelB.ingressP95Bps, 10);
  assert.equal(tunnelB.egressP95Bps, 0);
  assert.equal(tunnelC.ingressP95Bps, 0);
  assert.equal(summary.totals.ingressP95Bps, 29);
  assert.equal(summary.totals.egressP95Bps, 2);
  assert.equal(summary.totals.concurrentIngressP95Bps, 30);
});

test("renderUi includes the refreshed Usage navigation and 30-day default", () => {
  const html = renderUi();

  assert.match(html, /data-tab="usage"/);
  assert.match(html, /id="tab-usage"/);
  assert.match(html, /<option value="30" selected>Last 30 days<\/option>/);
  assert.match(html, /Total ingress P95/);
  assert.match(html, /Total egress P95/);
  assert.match(html, /--accent: #f6821f/);
});
