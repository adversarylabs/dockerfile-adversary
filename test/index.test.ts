import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { Adversary, Severity } from "@adversary/sdk";
import { createApp } from "../src/index.ts";

function fixturePath(name: string): string {
  return new URL(`../fixtures/${name}`, import.meta.url).pathname;
}

test("clean fixture produces a structured empty review", async () => {
  const output = await createApp().run({
    input: { source: { path: fixturePath("clean") } },
    write: false,
  });

  assert.equal(output.target.filesScanned, 0);
  assert.equal(output.findings.length, 0);
  assert.equal(output.observations.length, 0);
  assert.equal(output.assessment, undefined);
  assert.equal(output.opinion?.ship, true);
});

test("three uses of the same unpinned image become grouped observations", async () => {
  const output = await createApp().run({
    input: { source: { path: fixturePath("node-multistage") } },
    includeRawObservations: true,
    write: false,
  });

  const observations = output.rawObservations?.filter((observation) => observation.ruleId === "dockerfile.base-image.unpinned-digest") ?? [];
  assert.equal(observations.length, 3);
  assert.deepEqual(
    observations.map((observation) => observation.groupKey),
    [
      "dockerfile.base-image.unpinned-digest:node:22-bookworm-slim",
      "dockerfile.base-image.unpinned-digest:node:22-bookworm-slim",
      "dockerfile.base-image.unpinned-digest:node:22-bookworm-slim",
    ],
  );

  const grouped = output.findings.find((finding) => finding.ruleId === "dockerfile.base-image.unpinned-digest");
  assert.ok(grouped);
  assert.equal(grouped.groupKey, "dockerfile.base-image.unpinned-digest:node:22-bookworm-slim");
  assert.equal(grouped.synthesisSource, "generic");
  assert.equal(grouped.summary, "Three stages reference node:22-bookworm-slim by tag rather than digest.");
  assert.equal(grouped.evidence.length, 3);
  assert.deepEqual(
    grouped.evidence.map((evidence) => evidence.line),
    [1, 6, 12],
  );
  assert.equal(grouped.evidence[0].data?.image, "node:22-bookworm-slim");
  assert.equal(grouped.recommendation?.includes("Pin production base images by digest"), true);
  assert.deepEqual(grouped.remediation, { complexity: "small" });
});

test("positive signals and opinion use structured review APIs", async () => {
  const output = await createApp().run({
    input: { source: { path: fixturePath("node-multistage") } },
    write: false,
  });

  assert.deepEqual(
    output.positives.map((positive) => positive.key),
    [
      "dockerfile.multi-stage:Dockerfile",
      "dockerfile.runtime.artifacts-only:Dockerfile",
      "dockerfile.slim-base:Dockerfile",
    ],
  );
  assert.equal(output.observations[0].key, "dockerfile.stage-layout:Dockerfile");
  assert.equal(output.assessment, undefined);
  assert.equal(output.opinion?.ship, true);
  assert.match(output.opinion?.summary ?? "", /ship/i);
});

test("duplicate observations are deduplicated before finding synthesis", async () => {
  const app = new Adversary({ name: "dedupe-test" });
  app.rule("dedupe", (ctx) => {
    const observation = {
      ruleId: "dockerfile.base-image.unpinned-digest",
      subject: "node:22",
      groupKey: "dockerfile.base-image.unpinned-digest:node:22",
      title: "Base image is not pinned by digest",
      category: "supply-chain",
      severity: Severity.Low,
      confidence: "high" as const,
      summary: "deps references node:22 by tag rather than digest.",
      location: { file: "Dockerfile", line: 1 },
      evidence: { stage: "deps", image: "node:22", instruction: "FROM node:22 AS deps" },
    };
    ctx.observe(observation);
    ctx.observe(observation);
  });

  const output = await app.run({
    input: { source: { path: fixturePath("clean") } },
    includeRawObservations: true,
    write: false,
  });

  assert.equal(output.rawObservations?.length, 2);
  assert.equal(output.findings.length, 1);
  assert.equal(output.findings[0].evidence.length, 1);
});

test("weak broad COPY evidence is not reported", async () => {
  const output = await createApp().run({
    input: { source: { path: fixturePath("weak-copy") } },
    includeRawObservations: true,
    review: { includeInformational: true },
    write: false,
  });

  assert.equal(output.rawObservations?.some((observation) => observation.ruleId === "dockerfile.copy.broad-context"), false);
  assert.equal(output.findings.some((finding) => finding.ruleId === "dockerfile.copy.broad-context"), false);
});

test("broad COPY with avoidable context is reported as structured evidence", async () => {
  const output = await createApp().run({
    input: { source: { path: fixturePath("broad-copy") } },
    includeRawObservations: true,
    review: { includeInformational: true },
    write: false,
  });

  const observation = output.rawObservations?.find((item) => item.ruleId === "dockerfile.copy.broad-context");
  assert.ok(observation);
  assert.equal(observation.category, "build-context");
  assert.equal(typeof observation.summary, "object");
  assert.equal(typeof observation.recommendation, "string");
  assert.deepEqual(observation.remediation, { complexity: "small" });
  assert.equal(observation.evidence?.dockerignorePresent, false);
  assert.deepEqual(observation.evidence?.notableIncludedFiles, ["tests/sample.txt"]);

  const finding = output.findings.find((item) => item.ruleId === "dockerfile.copy.broad-context");
  assert.ok(finding);
  assert.equal(finding.synthesisSource, "generic");
  assert.equal(finding.evidence[0].data?.effectiveFileCount, 2);
});

test("review result is deterministic", async () => {
  const input = { source: { path: fixturePath("node-multistage") } };
  const first = await createApp().run({ input, write: false });
  const second = await createApp().run({ input, write: false });

  assert.deepEqual(
    { ...second, timing: undefined },
    { ...first, timing: undefined },
  );
});

test("JSON output contains structured evidence and metadata", async () => {
  const output = await createApp().run({
    input: { source: { path: fixturePath("node-multistage") } },
    write: false,
  });
  const parsed = JSON.parse(JSON.stringify(output));
  const finding = parsed.findings[0];

  assert.equal(Array.isArray(finding.evidence), true);
  assert.equal(typeof finding.evidence[0].data, "object");
  assert.equal(finding.evidence[0].data.stage, "deps");
  assert.equal(finding.evidence[0].file, "Dockerfile");
  assert.equal(finding.category, "supply-chain");
  assert.equal(finding.confidence, "medium");
});

test("high-risk fixture produces a no-ship opinion", async () => {
  const output = await createApp().run({
    input: { source: { path: fixturePath("vulnerable") } },
    write: false,
  });

  assert.equal(output.assessment, undefined);
  assert.equal(output.opinion?.ship, false);
  assert.equal(output.findings.some((finding) => finding.ruleId === "dockerfile.secret.arg-env"), true);
});

test("adversary code contains no direct terminal review strings", async () => {
  const source = await readFile(new URL("../src/index.ts", import.meta.url), "utf8");

  assert.doesNotMatch(source, /process\.stderr|console\.log|Overall assessment|Positive signals|Primary opportunities|Overall opinion|Rules executed|Process exit code|Running \./);
});
