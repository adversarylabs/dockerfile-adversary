#!/usr/bin/env node

import { readdir, readFile } from "node:fs/promises";
import { dirname, join, sep } from "node:path";
import { Adversary, Severity, type RuleContext } from "@adversary/sdk";
import { observeDockerRule, registerDockerfileRules } from "./rules.js";

interface DockerfileInstruction {
  keyword: string;
  value: string;
  line: number;
  raw: string;
}

interface DockerfileStage {
  name: string;
  image: string;
  from: DockerfileInstruction;
  instructions: DockerfileInstruction[];
  isFinal: boolean;
}

interface ParsedDockerfile {
  path: string;
  instructions: DockerfileInstruction[];
  stages: DockerfileStage[];
}

interface RepositoryContext {
  files: string[];
  hasLockfile: boolean;
  hasDockerignore: (dockerfilePath: string) => boolean;
  dockerignoreEntries: (dockerfilePath: string) => string[];
  contextFiles: (dockerfilePath: string) => string[];
}

const SECRET_NAME_PATTERN = /(?:^|_)(?:TOKEN|SECRET|PASSWORD|PASSWD|PRIVATE_KEY|API_KEY|ACCESS_KEY|AUTH|CREDENTIAL)(?:_|$)/i;
const MAX_REPOSITORY_FILES = 600;
const MAX_DISCOVERY_FILES = 5000;
const SKIPPED_DIRECTORIES = new Set([".adversary", ".git", ".hg", ".svn", "coverage", "dist", "node_modules", "target", "vendor"]);

export function createApp(): Adversary {
  registerDockerfileRules();
  const app = new Adversary({ name: "dockerfile" });

  app.rule("dockerfile.review", async (ctx) => {
    const dockerfiles = await loadDockerfiles(ctx);
    const repo = await inspectRepository(ctx);
    const severities: string[] = [];

    ctx.summary.files_scanned = dockerfiles.length;
    ctx.summary.repository_files_sampled = repo.files.length;

    for (const dockerfile of dockerfiles) {
      reportBaseImageObservations(ctx, dockerfile, repo, severities);
      reportSecretObservations(ctx, dockerfile, severities);
      reportBroadCopyObservations(ctx, dockerfile, repo, severities);
      reportRuntimeObservations(ctx, dockerfile, severities);
      reportPositiveSignals(ctx, dockerfile);
      reportReviewObservations(ctx, dockerfile);
    }

    reportOpinion(ctx, dockerfiles, severities);
  });

  return app;
}

async function loadDockerfiles(ctx: RuleContext): Promise<ParsedDockerfile[]> {
  const paths = (await walkRepository(ctx.repoPath, MAX_DISCOVERY_FILES)).filter(isDockerfilePath).sort();
  const dockerfiles: ParsedDockerfile[] = [];

  for (const path of paths) {
    const raw = await readFile(join(ctx.repoPath, path), "utf8");
    const instructions = parseDockerfile(raw);
    dockerfiles.push({ path, instructions, stages: parseStages(instructions) });
  }

  return dockerfiles;
}

async function inspectRepository(ctx: RuleContext): Promise<RepositoryContext> {
  const files = await walkRepository(ctx.repoPath);
  const fileSet = new Set(files);
  const dockerignoreCache = new Map<string, string[]>();

  for (const path of files.filter((file) => file.endsWith(".dockerignore"))) {
    try {
      dockerignoreCache.set(path, parseDockerignore(await readFile(join(ctx.repoPath, path), "utf8")));
    } catch {
      dockerignoreCache.set(path, []);
    }
  }

  const lockfiles = ["package-lock.json", "pnpm-lock.yaml", "yarn.lock", "bun.lockb", "poetry.lock", "Pipfile.lock", "go.sum"];

  return {
    files,
    hasLockfile: lockfiles.some((path) => fileSet.has(path)),
    hasDockerignore(dockerfilePath: string): boolean {
      return fileSet.has(dockerignorePathFor(dockerfilePath));
    },
    dockerignoreEntries(dockerfilePath: string): string[] {
      return dockerignoreCache.get(dockerignorePathFor(dockerfilePath)) ?? [];
    },
    contextFiles(dockerfilePath: string): string[] {
      const directory = dirname(dockerfilePath);
      const contextRoot = directory === "." ? "" : `${toPosixPath(directory)}/`;
      const entries = dockerignoreCache.get(dockerignorePathFor(dockerfilePath)) ?? [];
      return files.filter((file) => file.startsWith(contextRoot)).filter((file) => !isIgnoredByDockerignore(file.slice(contextRoot.length), entries));
    },
  };
}

function reportBaseImageObservations(ctx: RuleContext, dockerfile: ParsedDockerfile, repo: RepositoryContext, severities: string[]): void {
  for (const stage of dockerfile.stages) {
    if (isScratch(stage.image) || hasDigest(stage.image)) {
      continue;
    }

    severities.push(Severity.Low);
    observeDockerRule(ctx, {
      ruleId: "dockerfile.base-image.unpinned-digest",
      subject: stage.image,
      severity: Severity.Low,
      confidence: imageTag(stage.image) === undefined || imageTag(stage.image) === "latest" ? "high" : "medium",
      location: { file: dockerfile.path, line: stage.from.line },
      evidence: {
        stage: stage.name,
        instruction: stage.from.raw,
        image: stage.image,
        lockfilePresent: repo.hasLockfile,
      },
    });
  }
}

function reportSecretObservations(ctx: RuleContext, dockerfile: ParsedDockerfile, severities: string[]): void {
  for (const instruction of dockerfile.instructions) {
    if (instruction.keyword !== "ARG" && instruction.keyword !== "ENV") {
      continue;
    }

    for (const name of variableNames(instruction)) {
      if (!SECRET_NAME_PATTERN.test(name)) {
        continue;
      }

      severities.push(Severity.High);
      observeDockerRule(ctx, {
        ruleId: "dockerfile.secret.arg-env",
        subject: name,
        severity: Severity.High,
        confidence: "medium",
        location: { file: dockerfile.path, line: instruction.line },
        evidence: {
          instruction: instruction.raw,
          variable: name,
        },
      });
    }
  }
}

function reportBroadCopyObservations(ctx: RuleContext, dockerfile: ParsedDockerfile, repo: RepositoryContext, severities: string[]): void {
  for (const stage of dockerfile.stages) {
    for (const instruction of stage.instructions) {
      if ((instruction.keyword !== "COPY" && instruction.keyword !== "ADD") || !copiesWholeContext(instruction.value)) {
        continue;
      }

      const effectiveContext = repo.contextFiles(dockerfile.path);
      const notableIncludedFiles = effectiveContext.filter((file) => isLikelyUnneededInImage(file) || isLikelySensitiveContextFile(file)).slice(0, 8);
      const dockerignorePresent = repo.hasDockerignore(dockerfile.path);
      const reachesRuntime = stage.isFinal || finalStageCopiesFromStage(dockerfile, stage.name);
      const confidence = notableIncludedFiles.length > 0 || !dockerignorePresent ? "medium" : "low";

      if (confidence === "low" && effectiveContext.length < 40) {
        continue;
      }

      severities.push(Severity.Info);
      observeDockerRule(ctx, {
        ruleId: "dockerfile.copy.broad-context",
        subject: dockerfile.path,
        severity: Severity.Info,
        confidence,
        location: { file: dockerfile.path, line: instruction.line },
        evidence: {
          stage: stage.name,
          instruction: instruction.raw,
          effectiveFileCount: effectiveContext.length,
          notableIncludedFiles,
          dockerignorePresent,
          reachesRuntime,
          dockerignoreEntries: repo.dockerignoreEntries(dockerfile.path),
        },
      });
    }
  }
}

function reportRuntimeObservations(ctx: RuleContext, dockerfile: ParsedDockerfile, severities: string[]): void {
  const stage = dockerfile.stages.find((candidate) => candidate.isFinal);
  if (stage === undefined) {
    return;
  }

  const lastUser = stage.instructions.filter((instruction) => instruction.keyword === "USER").slice(-1)[0];
  if (lastUser !== undefined && !isRootUser(lastUser.value)) {
    return;
  }

  severities.push(Severity.Medium);
  observeDockerRule(ctx, {
    ruleId: "dockerfile.runtime.root-user",
    subject: dockerfile.path,
    severity: Severity.Medium,
    confidence: "high",
    location: { file: dockerfile.path, line: lastUser?.line ?? stage.from.line },
    evidence: {
      stage: stage.name,
      instruction: lastUser?.raw,
      defaultUser: lastUser === undefined ? "root" : lastUser.value,
    },
  });
}

function reportPositiveSignals(ctx: RuleContext, dockerfile: ParsedDockerfile): void {
  if (dockerfile.stages.length > 1) {
    ctx.review.positive({
      key: `dockerfile.multi-stage:${dockerfile.path}`,
      summary: `The Dockerfile uses a multi-stage build (${stageNames(dockerfile).join(", ")}).`,
      evidence: [{ file: dockerfile.path, line: dockerfile.stages[0].from.line }],
    });
  }

  const copyFrom = dockerfile.stages
    .find((stage) => stage.isFinal)
    ?.instructions.find((instruction) => instruction.keyword === "COPY" && /(?:^|\s)--from=/i.test(instruction.value));
  if (copyFrom !== undefined) {
    ctx.review.positive({
      key: `dockerfile.runtime.artifacts-only:${dockerfile.path}`,
      summary: "The runtime stage copies artifacts from an earlier stage instead of rebuilding the application.",
      evidence: [{ file: dockerfile.path, line: copyFrom.line }],
    });
  }

  const stageImages = dockerfile.stages.map((stage) => stage.image);
  if (stageImages.length > 0 && stageImages.every((image) => /^node:.*-slim(?:@|$)/i.test(image))) {
    ctx.review.positive({
      key: `dockerfile.slim-base:${dockerfile.path}`,
      summary: "The Dockerfile uses slim Node base images across its stages.",
    });
  }
}

function reportReviewObservations(ctx: RuleContext, dockerfile: ParsedDockerfile): void {
  if (dockerfile.stages.length >= 3 && dockerfile.stages.every((stage) => !/^stage-\d+$/.test(stage.name))) {
    ctx.review.observe({
      key: `dockerfile.stage-layout:${dockerfile.path}`,
      summary: `The Dockerfile defines ${stageNames(dockerfile).join(", ")} stages.`,
    });
  }
}

function reportOpinion(ctx: RuleContext, dockerfiles: ParsedDockerfile[], severities: string[]): void {
  const risk = riskFromSeverities(severities);
  if (dockerfiles.length === 0) {
    ctx.review.opinion({ ship: true, summary: "There is no Dockerfile to review in this repository." });
    return;
  }

  if (risk === "none") {
    ctx.review.opinion({ ship: true, summary: "I would ship this Dockerfile as-is. No material issues were identified." });
  } else if (risk === "low") {
    ctx.review.opinion({ ship: true, summary: "I would ship this Dockerfile as-is. The remaining recommendations are low-risk hardening improvements." });
  } else {
    ctx.review.opinion({ ship: false, summary: "I would address the runtime or security findings before shipping this image." });
  }
}

function riskFromSeverities(severities: string[]): "none" | "low" | "medium" | "high" | "critical" {
  if (severities.includes(Severity.Critical)) {
    return "critical";
  }
  if (severities.includes(Severity.High)) {
    return "high";
  }
  if (severities.includes(Severity.Medium)) {
    return "medium";
  }
  if (severities.includes(Severity.Low) || severities.includes(Severity.Info)) {
    return "low";
  }
  return "none";
}

async function walkRepository(repoPath: string, maxFiles = MAX_REPOSITORY_FILES): Promise<string[]> {
  const files: string[] = [];

  async function visit(directory: string): Promise<void> {
    if (files.length >= maxFiles) {
      return;
    }

    let entries;
    try {
      entries = await readdir(join(repoPath, directory), { withFileTypes: true });
    } catch {
      return;
    }

    entries.sort((left, right) => left.name.localeCompare(right.name));
    for (const entry of entries) {
      if (files.length >= maxFiles) {
        return;
      }

      const relativePath = directory === "" ? entry.name : join(directory, entry.name);
      const posixPath = toPosixPath(relativePath);
      if (entry.isDirectory()) {
        if (!SKIPPED_DIRECTORIES.has(entry.name)) {
          await visit(posixPath);
        }
      } else if (entry.isFile()) {
        files.push(posixPath);
      }
    }
  }

  await visit("");
  return files;
}

function parseDockerfile(source: string): DockerfileInstruction[] {
  const instructions: DockerfileInstruction[] = [];
  const lines = source.split(/\r?\n/);
  let current: { line: number; lines: string[] } | undefined;

  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index];
    const trimmed = line.trim();
    if (current === undefined && (trimmed.length === 0 || trimmed.startsWith("#"))) {
      continue;
    }

    if (current === undefined) {
      current = { line: index + 1, lines: [line] };
    } else {
      current.lines.push(line);
    }

    if (continuesInstruction(line)) {
      continue;
    }

    const raw = current.lines.join("\n");
    const match = raw.match(/^\s*([a-z]+)\s+(.*)$/is);
    if (match !== null) {
      instructions.push({
        keyword: match[1].toUpperCase(),
        value: stripContinuations(match[2]).trim(),
        line: current.line,
        raw,
      });
    }
    current = undefined;
  }

  return instructions;
}

function parseStages(instructions: DockerfileInstruction[]): DockerfileStage[] {
  const stages: DockerfileStage[] = [];
  let current: DockerfileStage | undefined;

  for (const instruction of instructions) {
    if (instruction.keyword === "FROM") {
      if (current !== undefined) {
        stages.push(current);
      }

      current = {
        name: parseStageName(instruction.value) ?? `stage-${stages.length}`,
        image: parseFromImage(instruction.value) ?? "unknown",
        from: instruction,
        instructions: [instruction],
        isFinal: false,
      };
    } else if (current !== undefined) {
      current.instructions.push(instruction);
    }
  }

  if (current !== undefined) {
    stages.push(current);
  }

  const final = stages[stages.length - 1];
  if (final !== undefined) {
    final.isFinal = true;
  }

  return stages;
}

function parseDockerignore(source: string): string[] {
  return source
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line.length > 0 && !line.startsWith("#"));
}

function continuesInstruction(line: string): boolean {
  return /(^|[^\\])\\\s*$/.test(line);
}

function stripContinuations(value: string): string {
  return value.replace(/\\\r?\n/g, " ");
}

function parseFromImage(value: string): string | undefined {
  const tokens = shellLikeTokens(value);
  return tokens.find((token) => !token.startsWith("--") && token.toUpperCase() !== "AS");
}

function parseStageName(value: string): string | undefined {
  const tokens = shellLikeTokens(value);
  const asIndex = tokens.findIndex((token) => token.toUpperCase() === "AS");
  return asIndex === -1 ? undefined : tokens[asIndex + 1];
}

function variableNames(instruction: DockerfileInstruction): string[] {
  if (instruction.keyword === "ARG") {
    return [instruction.value.split("=", 1)[0].trim()].filter(Boolean);
  }

  const tokens = shellLikeTokens(instruction.value);
  if (tokens.length === 0) {
    return [];
  }

  return tokens[0].includes("=") ? tokens.map((token) => token.split("=", 1)[0]).filter(Boolean) : [tokens[0]];
}

function copiesWholeContext(value: string): boolean {
  const tokens = shellLikeTokens(value).filter((token) => !token.startsWith("--"));
  return tokens[0] === ".";
}

function shellLikeTokens(value: string): string[] {
  const tokens: string[] = [];
  const pattern = /"([^"\\]*(?:\\.[^"\\]*)*)"|'([^']*)'|(\S+)/g;
  let match: RegExpExecArray | null;

  while ((match = pattern.exec(value)) !== null) {
    tokens.push(match[1] ?? match[2] ?? match[3]);
  }

  return tokens;
}

function finalStageCopiesFromStage(dockerfile: ParsedDockerfile, stageName: string): boolean {
  const finalStage = dockerfile.stages.find((stage) => stage.isFinal);
  return finalStage?.instructions.some((instruction) => instruction.keyword === "COPY" && instruction.value.includes(`--from=${stageName}`)) ?? false;
}

function imageTag(image: string): string | undefined {
  const imageWithoutDigest = image.split("@", 1)[0];
  const parts = imageWithoutDigest.split("/");
  const lastSegment = parts[parts.length - 1] ?? "";
  const colonIndex = lastSegment.lastIndexOf(":");
  return colonIndex === -1 ? undefined : lastSegment.slice(colonIndex + 1);
}

function hasDigest(image: string): boolean {
  return /@sha256:[a-f0-9]{32,}$/i.test(image);
}

function isScratch(image: string): boolean {
  return image.toLowerCase() === "scratch";
}

function isRootUser(value: string): boolean {
  const user = value.trim().split(/\s+/, 1)[0].split(":", 1)[0].toLowerCase();
  return user === "root" || user === "0";
}

function dockerignorePathFor(dockerfilePath: string): string {
  const directory = dirname(dockerfilePath);
  return directory === "." ? ".dockerignore" : join(directory, ".dockerignore");
}

function isIgnoredByDockerignore(path: string, entries: string[]): boolean {
  let ignored = false;
  for (const entry of entries) {
    const negated = entry.startsWith("!");
    const pattern = negated ? entry.slice(1) : entry;
    if (matchesDockerignorePattern(path, pattern)) {
      ignored = !negated;
    }
  }
  return ignored;
}

function matchesDockerignorePattern(path: string, pattern: string): boolean {
  const normalizedPattern = pattern.replace(/^\//, "").replace(/\/$/, "");
  if (normalizedPattern.length === 0) {
    return false;
  }

  if (normalizedPattern.includes("*")) {
    const source = normalizedPattern
      .replace(/[.+^${}()|[\]\\]/g, "\\$&")
      .replace(/\*\*/g, "\0")
      .replace(/\*/g, "[^/]*")
      .replace(/\0/g, ".*");
    return new RegExp(`(^|/)${source}($|/)`).test(path);
  }

  return path === normalizedPattern || path.startsWith(`${normalizedPattern}/`) || path.endsWith(`/${normalizedPattern}`);
}

function isDockerfilePath(path: string): boolean {
  const filename = path.split("/").pop() ?? "";
  return filename === "Dockerfile" || filename.startsWith("Dockerfile.") || filename.endsWith(".dockerfile");
}

function isLikelyUnneededInImage(path: string): boolean {
  return /(^|\/)(?:test|tests|fixtures|docs|examples|coverage|\.github)(\/|$)/i.test(path) || /\.(?:md|snap|map)$/i.test(path);
}

function isLikelySensitiveContextFile(path: string): boolean {
  return /(^|\/)(?:\.env|\.npmrc|\.pypirc|\.netrc|id_rsa|credentials|config\.json)$|\.pem$|\.key$/i.test(path);
}

function stageNames(dockerfile: ParsedDockerfile): string[] {
  return dockerfile.stages.map((stage) => stage.name);
}

function toPosixPath(path: string): string {
  return path.split(sep).join("/");
}

if (process.argv[1] !== undefined && import.meta.url === new URL(process.argv[1], "file:").href) {
  await createApp().run();
}
