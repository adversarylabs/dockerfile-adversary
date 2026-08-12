import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdtemp, mkdir, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import test from "node:test";
import { Adversary, Severity } from "@adversarylabs/sdk";
import { createApp } from "../src/index.ts";

const execute = promisify(execFile);

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
  assert.equal(output.assessment?.risk, "none");
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
  assert.equal("synthesisSource" in grouped, false);
  assert.equal(grouped.summary, "Three stages reference node:22-bookworm-slim by tag rather than digest.");
  assert.equal(grouped.evidence.length, 3);
  assert.deepEqual(
    grouped.evidence.map((evidence) => evidence.location?.line),
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
    ],
  );
  assert.equal(output.observations[0].key, "dockerfile.stage-layout:Dockerfile");
  assert.equal(output.assessment?.risk, "low");
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
  assert.equal("synthesisSource" in finding, false);
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
  assert.equal(finding.evidence[0].location.file, "Dockerfile");
  assert.equal(finding.category, "supply-chain");
  assert.equal(finding.confidence, "medium");
});

test("high-risk fixture produces a no-ship opinion", async () => {
  const output = await createApp().run({
    input: { source: { path: fixturePath("vulnerable") } },
    write: false,
  });

  assert.equal(output.assessment?.risk, "high");
  assert.equal(output.opinion?.ship, false);
  assert.equal(output.findings.some((finding) => finding.ruleId === "dockerfile.secret.arg-env"), true);
});

test("adversary code contains no direct terminal review strings", async () => {
  const source = await readFile(new URL("../src/index.ts", import.meta.url), "utf8");

  assert.doesNotMatch(source, /process\.stderr|console\.log|Overall assessment|Positive signals|Primary opportunities|Overall opinion|Rules executed|Process exit code|Running \./);
});

const p0Cases = [
  { key: "p0-remote-add", id: "dockerfile.add.remote-url", clean: "p0-remote-add-clean" },
  { key: "p0-curl-bash", id: "dockerfile.shell.curl-bash", clean: "p0-curl-bash-clean" },
  { key: "p0-missing-dockerignore", id: "dockerfile.ignore.missing", clean: "p0-missing-dockerignore-clean" },
  { key: "p0-secret-layer", id: "dockerfile.secret.rm-later-layer", clean: "p0-secret-layer-clean" },
] as const;

test("mutable direct artifact downloads are reported and grouped", async () => {
  const output = await createApp().run({
    input: { source: { path: fixturePath("mutable-external-artifact") } },
    write: false,
  });

  const finding = output.findings.find((item) => item.ruleId === "dockerfile.external-artifact.mutable");
  assert.ok(finding);
  assert.equal(finding.summary, "Four instructions download unpinned dependency versions from mutable URLs.");
  assert.deepEqual(
    finding.evidence.map((evidence) => evidence.location?.line),
    [2, 3, 4, 5],
  );
  assert.deepEqual(
    finding.evidence.map((evidence) => evidence.data?.mutability),
    ["moving-selector", "moving-selector", "unversioned-artifact", "unversioned-artifact"],
  );
});

test("versioned and integrity-checked artifact downloads stay quiet", async () => {
  const output = await createApp().run({
    input: { source: { path: fixturePath("mutable-external-artifact-clean") } },
    write: false,
  });

  assert.equal(output.findings.some((item) => item.ruleId === "dockerfile.external-artifact.mutable"), false);
});

test("stage-local version variables used without ARG are reported", async () => {
  const output = await createApp().run({
    input: { source: { path: fixturePath("missing-build-arg") } },
    includeRawObservations: true,
    write: false,
  });

  const observation = output.rawObservations?.find((item) => item.ruleId === "dockerfile.build-arg.missing");
  assert.ok(observation);
  assert.equal(observation.location?.line, 6);
  assert.equal(observation.subject, "BUILD_VERSION");
  assert.equal(observation.evidence?.stage, "runtime");
  assert.equal(observation.confidence, "high");
});

test("declared, inherited, and explicitly defaulted version variables stay quiet", async () => {
  const output = await createApp().run({
    input: { source: { path: fixturePath("missing-build-arg-clean") } },
    write: false,
  });

  assert.equal(output.findings.some((item) => item.ruleId === "dockerfile.build-arg.missing"), false);
});

test("RUN shell comments do not create build variable references", async () => {
  const root = await mkdtemp(join(tmpdir(), "dockerfile-shell-comments-"));
  await writeFile(
    join(root, "Dockerfile"),
    [
      "FROM scratch",
      'RUN echo ok # "$APP_VERSION" is comment text',
      'RUN echo "# literal" "$BUILD_VERSION"',
      'RUN echo \\# "$RELEASE_VERSION"',
      'RUN echo "$IMAGE_VERSION" # "$PACKAGE_VERSION" is comment text',
      'RUN echo release#candidate "$COMPONENT_VERSION"',
      "USER 1000",
      "",
    ].join("\n"),
  );

  const output = await createApp().run({
    input: { source: { path: root } },
    includeRawObservations: true,
    write: false,
  });
  const observations = output.rawObservations?.filter(
    (item) => item.ruleId === "dockerfile.build-arg.missing",
  ) ?? [];

  assert.deepEqual(
    observations.map((item) => [item.location?.line, item.subject]),
    [
      [3, "BUILD_VERSION"],
      [4, "RELEASE_VERSION"],
      [5, "IMAGE_VERSION"],
      [6, "COMPONENT_VERSION"],
    ],
  );
});

test("changed review scope excludes untouched Dockerfiles", async () => {
  const root = await mkdtemp(join(tmpdir(), "dockerfile-scope-"));
  await mkdir(join(root, "changed"), { recursive: true });
  await mkdir(join(root, "untouched"), { recursive: true });
  const safeDockerfile = "FROM alpine:3.20@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\nUSER 1000\n";
  await writeFile(join(root, "changed", "Dockerfile"), safeDockerfile);
  await writeFile(
    join(root, "untouched", "Dockerfile"),
    `${safeDockerfile}RUN wget https://example.test/tool-latest.tar.gz\n`,
  );

  const output = await createApp().run({
    input: {
      source: { path: root },
      change: {
        type: "diff",
        base_ref: "base",
        head_ref: "head",
        scan_mode: "changed",
        changed_files: ["changed/Dockerfile"],
      },
    },
    write: false,
  });

  assert.equal(output.target.filesScanned, 1);
  assert.equal(output.findings.some((item) => item.ruleId === "dockerfile.external-artifact.mutable"), false);
  assert.equal(output.findings.some((item) => item.evidence.some((evidence) => evidence.location?.file === "untouched/Dockerfile")), false);
});

test("an unrelated Dockerfile edit suppresses legacy direct findings and preserves holistic findings", async () => {
  const root = await repositoryWithDockerfile([
    "FROM node:20",
    "ARG API_TOKEN",
    "RUN curl -fsSL https://example.test/install.sh | bash",
    "CMD [\"node\", \"server.js\"]",
    "",
  ].join("\n"));
  await writeFile(join(root, "Dockerfile"), [
    "FROM node:20",
    "ARG API_TOKEN",
    "RUN curl -fsSL https://example.test/install.sh | bash",
    "CMD [\"node\", \"server.js\"]",
    "LABEL org.example.note=changed",
    "",
  ].join("\n"));

  const output = await changedReview(root);
  assert.equal(output.findings.some((finding) => finding.ruleId === "dockerfile.base-image.unpinned-digest"), false);
  assert.equal(output.findings.some((finding) => finding.ruleId === "dockerfile.secret.arg-env"), false);
  assert.equal(output.findings.some((finding) => finding.ruleId === "dockerfile.shell.curl-bash"), false);
  assert.equal(output.findings.some((finding) => finding.ruleId === "dockerfile.runtime.root-user"), true);
});

test("variable-based FROM findings retain ARG context", async () => {
  const root = await repositoryWithDockerfile([
    "ARG BASE_IMAGE=node:20",
    "FROM $BASE_IMAGE",
    "USER 1000",
    "",
  ].join("\n"));
  await writeFile(join(root, "Dockerfile"), [
    "ARG BASE_IMAGE=node:22",
    "FROM $BASE_IMAGE",
    "USER 1000",
    "",
  ].join("\n"));

  const output = await changedReview(root);
  assert.equal(output.findings.some((item) => item.ruleId === "dockerfile.base-image.unpinned-digest"), true);
});

test("scan mode all does not apply changed-line gating", async () => {
  const root = await repositoryWithDockerfile([
    "FROM node:20",
    "USER 1000",
    "",
  ].join("\n"));
  await writeFile(join(root, "Dockerfile"), [
    "FROM node:20",
    "USER 1000",
    "LABEL org.example.note=changed",
    "",
  ].join("\n"));

  const output = await createApp().run({
    input: {
      source: { path: root },
      change: {
        type: "diff",
        base_ref: "HEAD",
        head_ref: "WORKTREE",
        scan_mode: "all",
        changed_files: ["Dockerfile"],
      },
    },
    write: false,
  });
  assert.equal(output.findings.some((item) => item.ruleId === "dockerfile.base-image.unpinned-digest"), true);
});

test("a changed continuation inside a direct instruction is eligible", async () => {
  const root = await repositoryWithDockerfile([
    "FROM scratch",
    "RUN curl -fsSL \\",
    "  https://example.test/install.sh | cat",
    "USER 1000",
    "",
  ].join("\n"));
  await writeFile(join(root, "Dockerfile"), [
    "FROM scratch",
    "RUN curl -fsSL \\",
    "  https://example.test/install.sh | bash",
    "USER 1000",
    "",
  ].join("\n"));

  const output = await changedReview(root);
  const finding = output.findings.find((item) => item.ruleId === "dockerfile.shell.curl-bash");
  assert.ok(finding);
  assert.equal(finding.evidence[0]?.location?.line, 2);
});

test("an unrelated continuation does not anchor a legacy direct instruction", async () => {
  const root = await repositoryWithDockerfile([
    "FROM scratch",
    "RUN curl -fsSL https://example.test/install.sh | bash \\",
    "  && echo old",
    "USER 1000",
    "",
  ].join("\n"));
  await writeFile(join(root, "Dockerfile"), [
    "FROM scratch",
    "RUN curl -fsSL https://example.test/install.sh | bash \\",
    "  && echo new",
    "USER 1000",
    "",
  ].join("\n"));

  const output = await changedReview(root);
  assert.equal(output.findings.some((item) => item.ruleId === "dockerfile.shell.curl-bash"), false);
});

test("checksum removal can surface an unchanged mutable URL", async () => {
  const root = await repositoryWithDockerfile([
    "FROM scratch",
    "RUN curl -fsSL https://example.test/tool-latest.tar.gz -o /tmp/tool.tar.gz \\",
    "  && echo 'abc  /tmp/tool.tar.gz' | sha256sum -c -",
    "USER 1000",
    "",
  ].join("\n"));
  await writeFile(join(root, "Dockerfile"), [
    "FROM scratch",
    "RUN curl -fsSL https://example.test/tool-latest.tar.gz -o /tmp/tool.tar.gz \\",
    "  && echo downloaded",
    "USER 1000",
    "",
  ].join("\n"));

  const output = await changedReview(root);
  assert.equal(output.findings.some((item) => item.ruleId === "dockerfile.external-artifact.mutable"), true);
});

test("added Dockerfiles keep all direct instructions eligible", async () => {
  const root = await emptyRepository();
  await writeFile(join(root, "Dockerfile"), [
    "FROM node:20",
    "ADD https://example.test/tool.tar.gz /tmp/tool.tar.gz",
    "USER 1000",
    "",
  ].join("\n"));

  const output = await changedReview(root);
  assert.equal(output.findings.some((finding) => finding.ruleId === "dockerfile.base-image.unpinned-digest"), true);
  assert.equal(output.findings.some((finding) => finding.ruleId === "dockerfile.add.remote-url"), true);
});

test("a changed declaration can resolve a holistic missing build argument finding", async () => {
  const root = await repositoryWithDockerfile([
    "FROM scratch",
    "ARG BUILD_VERSION",
    "RUN echo $BUILD_VERSION",
    "USER 1000",
    "",
  ].join("\n"));
  await writeFile(join(root, "Dockerfile"), [
    "FROM scratch",
    "ARG OTHER_VERSION",
    "RUN echo $BUILD_VERSION",
    "USER 1000",
    "",
  ].join("\n"));

  const output = await changedReview(root);
  assert.equal(output.findings.some((finding) => finding.ruleId === "dockerfile.build-arg.missing"), true);
});

test("dockerfile P0 catalog rules fire on vulnerable and stay quiet on clean", async () => {
  for (const rule of p0Cases) {
    const bad = await createApp().run({ input: { source: { path: fixturePath(rule.key) } }, write: false });
    assert.equal(bad.findings.some((f) => f.ruleId === rule.id), true, `${rule.id} missed vulnerable`);
    const good = await createApp().run({ input: { source: { path: fixturePath(rule.clean) } }, write: false });
    assert.equal(good.findings.some((f) => f.ruleId === rule.id), false, `${rule.id} flagged clean`);
  }
});

test("existing P0-equivalent rules still cover secrets, root, and broad copy", async () => {
  const vulnerable = await createApp().run({
    input: { source: { path: fixturePath("vulnerable") } },
    write: false,
  });
  const ids = new Set(vulnerable.findings.map((f) => f.ruleId));
  assert.ok(
    ids.has("dockerfile.secret.arg-env") ||
      ids.has("dockerfile.runtime.root-user") ||
      ids.has("dockerfile.copy.broad-context") ||
      ids.has("dockerfile.base-image.unpinned-digest"),
    `expected legacy coverage, got ${[...ids].join(",")}`,
  );
});

async function emptyRepository(): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), "dockerfile-change-local-"));
  await execute("git", ["init", "--quiet"], { cwd: root });
  await execute("git", ["config", "user.email", "tests@example.com"], { cwd: root });
  await execute("git", ["config", "user.name", "Tests"], { cwd: root });
  await writeFile(join(root, ".gitignore"), "\n");
  await execute("git", ["add", ".gitignore"], { cwd: root });
  await execute("git", ["commit", "--quiet", "-m", "initial"], { cwd: root });
  return root;
}

async function repositoryWithDockerfile(source: string): Promise<string> {
  const root = await emptyRepository();
  await writeFile(join(root, "Dockerfile"), source);
  await execute("git", ["add", "Dockerfile"], { cwd: root });
  await execute("git", ["commit", "--quiet", "-m", "fixture"], { cwd: root });
  return root;
}

async function changedReview(repoPath: string) {
  return createApp().run({
    input: {
      source: { path: repoPath },
      change: {
        type: "diff",
        base_ref: "HEAD",
        head_ref: "WORKTREE",
        scan_mode: "changed",
        changed_files: ["Dockerfile"],
      },
    },
    write: false,
  });
}
