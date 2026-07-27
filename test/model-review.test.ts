import assert from "node:assert/strict";
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { ModelUnavailableError, type ModelReviewRequest, type ReviewModel } from "@adversarylabs/sdk";
import { createApp } from "../src/index.ts";
import { DOCKERFILE_MODEL_PROMPT, DOCKERFILE_MODEL_SCHEMA } from "../src/model-review.ts";

function unavailableModel(): ReviewModel {
  return { async review() { throw new ModelUnavailableError("no"); } };
}
function capturingModel(output: unknown): ReviewModel & { requests: ModelReviewRequest[] } {
  const requests: ModelReviewRequest[] = [];
  return {
    requests,
    async review<T>(request: ModelReviewRequest) {
      requests.push(request);
      const schema = request.schema as { required?: string[] };
      if (Array.isArray(schema.required) && schema.required.includes("concern")) {
        return { output: { concern: "runtime root user" } as T, provider: "f", model: "c" };
      }
      return { output: output as T, provider: "f", model: "t" };
    },
  };
}

test("static dockerfile review works without model", async () => {
  const root = await mkdtemp(join(tmpdir(), "df-static-"));
  await writeFile(join(root, "Dockerfile"), "FROM node:20\nUSER root\nCMD [\"node\"]\n");
  const result = await createApp().run({ model: unavailableModel(), input: { source: { path: root } } });
  assert.ok(Array.isArray(result.findings));
  assert.equal(result.opinion?.ship, false);
});

test("model path receives dockerfile catalog", async () => {
  const root = await mkdtemp(join(tmpdir(), "df-model-"));
  await writeFile(join(root, "Dockerfile"), "FROM node:20\nUSER root\nCMD [\"node\"]\n");
  const model = capturingModel({
    assessment: { risk: "medium", summary: "Runtime user is root." },
    ship: true,
    observations: [],
  });
  const result = await createApp().run({ model, input: { source: { path: root } } });
  const req = model.requests.find((r) => {
    const schema = r.schema as { required?: string[] };
    return !(Array.isArray(schema.required) && schema.required.includes("concern"));
  })!;
  assert.equal(req.prompt, DOCKERFILE_MODEL_PROMPT);
  assert.deepEqual(req.schema, DOCKERFILE_MODEL_SCHEMA);
  assert.equal((req.input as { domain: string }).domain, "dockerfile");
  assert.equal(result.opinion?.ship, false);
});
