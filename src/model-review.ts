import {
  formatOpinion,
  isOpinionConcernPhrase,
  ModelUnavailableError,
  requireOpinionConcern,
  type ModelReviewRequest,
  type RuleContext,
} from "@adversarylabs/sdk";

const MAX_MODEL_FILES = 12;
const MAX_FILE_CHARS = 5_000;
const MAX_DETERMINISTIC = 40;
const MAX_OBS = 6;

export const DOCKERFILE_MODEL_PROMPT = `You are reviewing Dockerfiles for supply-chain, secret, and runtime hardening issues.

Authority: unpinned base images, secrets in ARG/ENV, root runtime user, overly broad COPY, missing multi-stage separation when evidence shows risk.
Prefer silence. Zero to six observations. Cite evidenceIds only.
primaryConcern is a short noun phrase after "I would address", empty when ship is true.
Return JSON matching the schema only.`;

export const DOCKERFILE_MODEL_SCHEMA: Record<string, unknown> = {
  type: "object",
  additionalProperties: false,
  required: ["assessment", "ship", "observations"],
  properties: {
    assessment: {
      type: "object",
      additionalProperties: false,
      required: ["risk", "summary"],
      properties: {
        risk: { type: "string", enum: ["none", "low", "medium", "high", "critical"] },
        summary: { type: "string", minLength: 1, maxLength: 800 },
      },
    },
    ship: { type: "boolean" },
    primaryConcern: { type: "string", minLength: 1, maxLength: 120 },
    observations: {
      type: "array",
      maxItems: MAX_OBS,
      items: {
        type: "object",
        additionalProperties: false,
        required: ["id", "title", "category", "severity", "confidence", "summary", "whyItMatters", "recommendation", "evidenceIds"],
        properties: {
          id: { type: "string", minLength: 1, maxLength: 64 },
          title: { type: "string", minLength: 1, maxLength: 160 },
          category: { type: "string", enum: ["base-image", "secrets", "root-user", "broad-copy", "supply-chain", "completeness"] },
          severity: { type: "string", enum: ["low", "medium", "high", "critical"] },
          confidence: { type: "string", enum: ["medium", "high"] },
          summary: { type: "string", minLength: 1, maxLength: 500 },
          whyItMatters: { type: "string", minLength: 1, maxLength: 500 },
          recommendation: { type: "string", minLength: 1, maxLength: 500 },
          evidenceIds: {
            type: "array",
            minItems: 1,
            maxItems: 8,
            items: { type: "string", minLength: 1, maxLength: 96 },
          },
        },
      },
    },
  },
};

export interface PreparedEvidenceItem {
  id: string;
  kind: "deterministic" | "source";
  path: string;
  line?: number;
  message: string;
  snippet: string;
}

export interface DetectionInput {
  ruleId: string;
  file: string;
  line: number;
  snippet: string;
  message: string;
  severity?: string;
}

export interface SourceInput {
  path: string;
  content: string;
}

export interface ModelFactoryObservation {
  id: string;
  title: string;
  category: string;
  severity: "low" | "medium" | "high" | "critical";
  confidence: "medium" | "high";
  summary: string;
  whyItMatters: string;
  recommendation: string;
  evidenceIds: string[];
}

export interface ModelFactoryReview {
  assessment: { risk: "none" | "low" | "medium" | "high" | "critical"; summary: string };
  ship: boolean;
  primaryConcern?: string;
  observations: ModelFactoryObservation[];
}

export function prepareFactoryModelInput(
  detections: DetectionInput[],
  sources: SourceInput[],
  changeFiles: readonly string[] = [],
): {
  request: ModelReviewRequest;
  evidenceById: Map<string, PreparedEvidenceItem>;
} {
  const evidenceCatalog: PreparedEvidenceItem[] = [];
  const deterministicSignals = detections.slice(0, MAX_DETERMINISTIC).map((d) => {
    const id = `det:${d.ruleId}:${d.file}:${d.line}`;
    evidenceCatalog.push({
      id,
      kind: "deterministic",
      path: d.file,
      line: d.line,
      message: d.message,
      snippet: d.snippet.slice(0, 300),
    });
    return { id, ruleId: d.ruleId, path: d.file, line: d.line, message: d.message, snippet: d.snippet.slice(0, 300) };
  });

  const ordered = [...sources].sort((a, b) => {
    const ch = new Set(changeFiles);
    return (ch.has(a.path) ? 0 : 1) - (ch.has(b.path) ? 0 : 1) || a.path.localeCompare(b.path);
  });
  const preparedSources = [];
  for (const source of ordered.slice(0, MAX_MODEL_FILES)) {
    const truncated = source.content.length > MAX_FILE_CHARS;
    const content = truncated ? `${source.content.slice(0, MAX_FILE_CHARS)}\n/* truncated */\n` : source.content;
    const id = `file:${source.path}`;
    preparedSources.push({ id, path: source.path, content, truncated });
    evidenceCatalog.push({
      id,
      kind: "source",
      path: source.path,
      message: `Prepared source for ${source.path}`,
      snippet: content.split("\n").slice(0, 3).join("\n").slice(0, 300),
    });
  }

  const input = {
    domain: "dockerfile",
    deterministicSignals,
    sources: preparedSources,
    evidenceCatalog,
    change: { changedFiles: [...changeFiles].slice(0, 100) },
  };
  return {
    evidenceById: new Map(evidenceCatalog.map((e) => [e.id, e])),
    request: {
      prompt: DOCKERFILE_MODEL_PROMPT,
      input,
      schema: DOCKERFILE_MODEL_SCHEMA,
      budget: { maximumOutputTokens: 4_096, timeoutMs: 120_000 },
    },
  };
}

export async function runModelDockerfileReview(
  ctx: RuleContext,
  detections: DetectionInput[],
  sources: SourceInput[],
  staticSeverities: string[] = [],
  staticPrimaryConcern?: string,
): Promise<"applied" | "unavailable"> {
  const { request, evidenceById } = prepareFactoryModelInput(
    detections,
    sources,
    ctx.change?.changedFiles ?? [],
  );
  try {
    const result = await ctx.model.review<ModelFactoryReview>(request);
    await applyModelDockerfileReview(ctx, result.output, evidenceById, staticSeverities, staticPrimaryConcern);
    return "applied";
  } catch (error) {
    if (error instanceof ModelUnavailableError) return "unavailable";
    throw error;
  }
}

async function applyModelDockerfileReview(
  ctx: RuleContext,
  output: ModelFactoryReview,
  evidenceById: Map<string, PreparedEvidenceItem>,
  staticSeverities: string[],
  staticPrimaryConcern?: string,
): Promise<void> {
  const rank = (s: string) => ({ none: 0, low: 1, medium: 2, high: 3, critical: 4 } as Record<string, number>)[s] ?? 0;
  const modelSevs = output.observations.map((o) => o.severity);
  const all = ["none", output.assessment.risk, ...staticSeverities, ...modelSevs];
  const risk = all.reduce((best, cur) => (rank(cur) > rank(best) ? cur : best), "none") as
    "none" | "low" | "medium" | "high" | "critical";
  ctx.review.assessment({ risk, summary: output.assessment.summary });

  const blocking =
    staticSeverities.some((s) => rank(s) >= 2) || modelSevs.some((s) => rank(s) >= 2);
  const ship = output.ship && !blocking;
  let concern: string | undefined = staticPrimaryConcern;
  const top = [...output.observations].sort((a, b) => rank(b.severity) - rank(a.severity))[0];
  for (const candidate of [top?.title, output.primaryConcern, staticPrimaryConcern]) {
    if (!candidate) continue;
    if (isOpinionConcernPhrase(candidate)) {
      concern = requireOpinionConcern(candidate);
      break;
    }
    try {
      concern = (await ctx.model.concern({ text: candidate })).concern;
      break;
    } catch { /* next */ }
  }
  ctx.review.opinion(formatOpinion({ ship, ...(concern ? { concern } : {}), change: ctx.change }));

  for (const observation of output.observations.slice(0, MAX_OBS)) {
    const evidence = observation.evidenceIds
      .map((id) => evidenceById.get(id))
      .filter((item): item is PreparedEvidenceItem => item !== undefined)
      .slice(0, 8)
      .map((item) => ({
        location: { file: item.path, ...(item.line === undefined ? {} : { line: item.line }) },
        message: item.message,
        snippet: item.snippet,
      }));
    ctx.review.observe({
      key: `dockerfile.model.${observation.id}`,
      summary: `[${observation.severity}/${observation.confidence}] ${observation.title}: ${observation.summary}`,
      ...(evidence.length === 0 ? {} : { evidence }),
      metadata: {
        source: "model",
        category: observation.category,
        severity: observation.severity,
        confidence: observation.confidence,
        whyItMatters: observation.whyItMatters,
        recommendation: observation.recommendation,
        evidenceIds: observation.evidenceIds,
      },
    });
  }
}
