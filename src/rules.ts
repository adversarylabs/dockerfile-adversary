import { type Confidence, type Evidence, type RuleContext, type Severity as SeverityValue } from "@adversarylabs/sdk";

type RuleTitle = {
  singular: string;
  plural: string;
};

type RuleDefinition = {
  id: string;
  category: string;
  title: RuleTitle;
  summary: {
    singular: string;
    grouped: string;
  };
  whyItMatters: string;
  impact: string;
  recommendation: string;
  remediation: {
    complexity: "small" | "medium" | "large" | "trivial";
  };
  tags: string[];
  groupKey: (observation: DockerObservationInput) => string;
};

export type DockerObservationInput = {
  ruleId: string;
  subject: string;
  severity: SeverityValue;
  confidence: Confidence | number;
  location?: Evidence;
  evidence?: Record<string, unknown>;
  tags?: string[];
  metadata?: Record<string, unknown>;
};

export const dockerfileRules = [
  defineRule({
    id: "dockerfile.base-image.unpinned-digest",
    category: "supply-chain",
    title: {
      singular: "Base image is not pinned by digest",
      plural: "Base images are not pinned by digest",
    },
    summary: {
      singular: "{stage} stage references {subject} by tag rather than digest.",
      grouped: "{count} stages reference {subject} by tag rather than digest.",
    },
    whyItMatters: "Container image tags are mutable and can resolve to different image contents over time.",
    impact: "A future build may consume a different base image even when the Dockerfile itself has not changed.",
    recommendation: "Pin production base images by digest when reproducibility and auditability matter. Use Renovate or Dependabot to keep digests current.",
    remediation: {
      complexity: "small",
    },
    tags: ["supply-chain"],
    groupKey: (observation) => `dockerfile.base-image.unpinned-digest:${observation.subject}`,
  }),
  defineRule({
    id: "dockerfile.secret.arg-env",
    category: "secrets",
    title: {
      singular: "Build input appears to contain credential material",
      plural: "Build inputs appear to contain credential material",
    },
    summary: {
      singular: "{subject} looks like a credential input.",
      grouped: "{count} Dockerfile build inputs look like credential input.",
    },
    whyItMatters: "ARG and ENV values can be exposed through image metadata, build logs, intermediate layers, or later instructions.",
    impact: "A real token passed through this path could be recoverable from build artifacts or logs.",
    recommendation:
      "Use BuildKit secret mounts for temporary tokens and SSH mounts for private Git access. If a value is only a placeholder, rename it so future maintainers do not pass real credentials through ARG or ENV.",
    remediation: {
      complexity: "small",
    },
    tags: ["secrets"],
    groupKey: (observation) => `dockerfile.secret.arg-env:${observation.location?.file ?? observation.subject}`,
  }),
  defineRule({
    id: "dockerfile.copy.broad-context",
    category: "build-context",
    title: {
      singular: "Broad COPY relies on build-context filtering",
      plural: "Broad COPY instructions rely on build-context filtering",
    },
    summary: {
      singular: "{stage} stage copies the full repository context after Docker has applied .dockerignore filtering.",
      grouped: "{count} Dockerfile instructions copy the full repository context after Docker has applied .dockerignore filtering.",
    },
    whyItMatters: "Broad copies can accidentally include local files and make image contents depend on .dockerignore maintenance.",
    impact: "Repository changes may increase build context size or introduce unintended files into intermediate layers.",
    recommendation: "Keep .dockerignore intentionally narrow and copy only required source or build inputs where practical.",
    remediation: {
      complexity: "small",
    },
    tags: ["build-context"],
    groupKey: (observation) => `dockerfile.copy.broad-context:${observation.location?.file ?? observation.subject}`,
  }),
  defineRule({
    id: "dockerfile.runtime.root-user",
    category: "runtime",
    title: {
      singular: "Runtime stage does not clearly drop root privileges",
      plural: "Runtime stages do not clearly drop root privileges",
    },
    summary: {
      singular: "{stage} runtime stage does not clearly drop root privileges.",
      grouped: "{count} runtime stages do not clearly drop root privileges.",
    },
    whyItMatters: "The image default travels with the artifact across environments, even when deployment platforms can override it.",
    impact: "If a deployment forgets to override the runtime user, the application can run as root.",
    recommendation:
      "Create a dedicated runtime user and set USER before CMD or ENTRYPOINT. If the application requires root, document that requirement and enforce compensating controls in the runtime platform.",
    remediation: {
      complexity: "small",
    },
    tags: ["runtime", "production"],
    groupKey: (observation) => `dockerfile.runtime.root-user:${observation.location?.file ?? observation.subject}`,
  }),
] satisfies RuleDefinition[];

const dockerRuleMap = new Map(dockerfileRules.map((rule) => [rule.id, rule]));

export function registerDockerfileRules(): void {
  // Reserved for SDK-level rule registration once the SDK exports that API.
}

export function observeDockerRule(ctx: RuleContext, observation: DockerObservationInput): void {
  const rule = dockerRuleMap.get(observation.ruleId);
  if (rule === undefined) {
    throw new Error(`Unknown Dockerfile rule ${observation.ruleId}.`);
  }

  ctx.observe({
    ruleId: observation.ruleId,
    subject: observation.subject,
    groupKey: rule.groupKey(observation),
    title: rule.title,
    category: rule.category,
    severity: observation.severity,
    confidence: observation.confidence,
    confidenceAggregation: "maximum",
    severityAggregation: "highest",
    summary: rule.summary,
    whyItMatters: rule.whyItMatters,
    impact: rule.impact,
    location: observation.location,
    evidence: observation.evidence,
    recommendation: rule.recommendation,
    remediation: rule.remediation,
    tags: [...rule.tags, ...(observation.tags ?? [])],
    metadata: observation.metadata,
  });
}

function defineRule(rule: RuleDefinition): RuleDefinition {
  return rule;
}
