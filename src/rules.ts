import { type Confidence, type EvidenceInput, type RuleContext, type Severity as SeverityValue } from "@adversarylabs/sdk";

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
  location?: EvidenceInput;
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
  defineRule({
    id: "dockerfile.add.remote-url",
    category: "supply-chain",
    title: {
      singular: "ADD fetches a remote URL",
      plural: "ADD instructions fetch remote URLs",
    },
    summary: {
      singular: "{subject} uses ADD with a remote URL.",
      grouped: "{count} ADD instructions fetch remote URLs.",
    },
    whyItMatters: "Remote ADD content is mutable and hard to audit compared to COPY of vendored artifacts.",
    impact: "A future build may pull different remote content without a Dockerfile change.",
    recommendation: "Prefer COPY of verified local artifacts, or pin remote inputs with digests and checksum verification.",
    remediation: { complexity: "small" },
    tags: ["supply-chain"],
    groupKey: (observation) => `dockerfile.add.remote-url:${observation.location?.file ?? observation.subject}`,
  }),
  defineRule({
    id: "dockerfile.shell.curl-bash",
    category: "supply-chain",
    title: {
      singular: "curl|bash install pattern",
      plural: "curl|bash install patterns",
    },
    summary: {
      singular: "{subject} pipes a remote script into a shell.",
      grouped: "{count} RUN instructions pipe remote scripts into a shell.",
    },
    whyItMatters: "Pipe-to-shell installs execute unpinned remote code during image builds.",
    impact: "A compromised download endpoint can inject code into every build.",
    recommendation: "Download, verify checksum/signature, then execute a pinned artifact.",
    remediation: { complexity: "small" },
    tags: ["supply-chain"],
    groupKey: (observation) => `dockerfile.shell.curl-bash:${observation.location?.file ?? observation.subject}`,
  }),
  defineRule({
    id: "dockerfile.external-artifact.mutable",
    category: "supply-chain",
    title: {
      singular: "External artifact uses a mutable download URL",
      plural: "External artifacts use mutable download URLs",
    },
    summary: {
      singular: "The download uses an unpinned dependency version from a mutable URL.",
      grouped: "{count} instructions download unpinned dependency versions from mutable URLs.",
    },
    whyItMatters: "Moving download URLs can resolve to different artifact contents without a Dockerfile change.",
    impact: "Rebuilds can silently consume a different dependency or execute content that was never reviewed.",
    recommendation: "Use a versioned or commit-addressed artifact URL and verify the downloaded checksum or signature before use.",
    remediation: { complexity: "small" },
    tags: ["supply-chain", "reproducibility"],
    groupKey: (observation) => `dockerfile.external-artifact.mutable:${observation.location?.file ?? observation.subject}`,
  }),
  defineRule({
    id: "dockerfile.build-arg.missing",
    category: "reproducibility",
    title: {
      singular: "Version build variable is not declared in this stage",
      plural: "Version build variables are not declared in their stages",
    },
    summary: {
      singular: "{stage} stage uses {subject} before declaring it as ARG or ENV.",
      grouped: "{count} instructions in {stage} stage use {subject} without a stage-visible declaration.",
    },
    whyItMatters: "Docker build arguments are stage-scoped and are unavailable before their ARG declaration.",
    impact: "Release metadata or build inputs can silently become empty or fall back to an unintended value.",
    recommendation: "Declare the variable with ARG before its first use in each independent stage. A stage based on a named earlier stage inherits its ARG declarations; unrelated stages need their own declaration.",
    remediation: { complexity: "small" },
    tags: ["build-configuration", "reproducibility"],
    groupKey: (observation) => {
      const stage = typeof observation.evidence?.stage === "string" ? observation.evidence.stage : "stage";
      return `dockerfile.build-arg.missing:${observation.location?.file ?? "Dockerfile"}:${stage}:${observation.subject}`;
    },
  }),
  defineRule({
    id: "dockerfile.ignore.missing",
    category: "build-context",
    title: {
      singular: "Missing .dockerignore with broad COPY",
      plural: "Missing .dockerignore with broad COPY",
    },
    summary: {
      singular: "{subject} copies the full context without a .dockerignore.",
      grouped: "{count} Dockerfiles copy the full context without a .dockerignore.",
    },
    whyItMatters: "Without .dockerignore, secrets and local debris can enter the build context.",
    impact: "Larger context, slower builds, and risk of packing local credentials into layers.",
    recommendation: "Add a .dockerignore that excludes VCS metadata, env files, and local secrets.",
    remediation: { complexity: "trivial" },
    tags: ["build-context"],
    groupKey: (observation) => `dockerfile.ignore.missing:${observation.location?.file ?? observation.subject}`,
  }),
  defineRule({
    id: "dockerfile.secret.rm-later-layer",
    category: "secrets",
    title: {
      singular: "Secret removed in a later layer",
      plural: "Secrets removed in later layers",
    },
    summary: {
      singular: "{subject} adds a credential-like file then removes it later.",
      grouped: "{count} credential-like files are removed only in later layers.",
    },
    whyItMatters: "Deleting a secret in a later RUN does not remove it from earlier image layers.",
    impact: "Credentials remain recoverable from image history.",
    recommendation: "Use BuildKit --mount=type=secret so secrets never land in a layer.",
    remediation: { complexity: "small" },
    tags: ["secrets"],
    groupKey: (observation) => `dockerfile.secret.rm-later-layer:${observation.location?.file ?? observation.subject}`,
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
