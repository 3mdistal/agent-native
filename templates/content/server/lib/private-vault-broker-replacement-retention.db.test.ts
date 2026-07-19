import { rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { eq } from "drizzle-orm";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";

const TEST_DB_PATH = join(
  tmpdir(),
  `private-vault-replacement-retention-${process.pid}-${Date.now()}.sqlite`,
);
const DAY = 24 * 60 * 60 * 1_000;
const START = new Date("2026-01-01T00:00:00.000Z");

let getDb: (typeof import("../db/index.js"))["getDb"];
let schema: typeof import("../db/schema.js");
let createService: (typeof import("./private-vault-broker-replacement-retention.js"))["createPrivateVaultReplacementRetentionService"];
let maxDelay: number;

function scope(suffix: string) {
  return {
    ownerEmail: `${suffix}@example.test`,
    accountId: `account:${suffix}`,
    orgId: `org:${suffix}`,
    workspaceId: `workspace:${suffix}`,
    vaultId: suffix.padEnd(32, "0").slice(0, 32),
  };
}

async function insertTranscript(input: {
  suffix: string;
  phase: string;
  terminalAt?: Date;
  drainPhase?: string;
  active?: boolean;
}) {
  const scoped = scope(input.suffix);
  const transcriptId = `transcript:${input.suffix}`;
  const drainId = input.drainPhase ? `drain:${input.suffix}` : null;
  await getDb()
    .insert(schema.contentEncryptedVaults)
    .values({
      ...scoped,
      vaultState: "active",
    });
  if (drainId) {
    await getDb()
      .insert(schema.contentEncryptedVaultBrokerReplacementDrains)
      .values({
        drainId,
        vaultId: scoped.vaultId,
        ownerEmail: scoped.ownerEmail,
        orgId: scoped.orgId,
        oldBrokerEndpointId: `old:${input.suffix}`,
        replacementBrokerEndpointId: `new:${input.suffix}`,
        authorizerEndpointId: `authorizer:${input.suffix}`,
        authorizerApprovalId: `approval:${input.suffix}`,
        authorizerApprovalHash: "11".repeat(32),
        drainGeneration: "00000001",
        phase: input.drainPhase,
        activeKey: input.active ? `active-drain:${input.suffix}` : null,
        deadlineAt: new Date(START.getTime() + DAY).toISOString(),
        frozenAt: START.toISOString(),
        witnessGeneration: input.drainPhase === "witnessed" ? 1 : null,
        terminalJobsDigest:
          input.drainPhase === "witnessed" ? "22".repeat(32) : null,
        completedAt: input.terminalAt?.toISOString() ?? null,
      });
    await getDb()
      .insert(schema.contentEncryptedVaultBrokerReplacementDrainJobs)
      .values({
        id: `job-row:${input.suffix}`,
        drainId,
        vaultId: scoped.vaultId,
        ownerEmail: scoped.ownerEmail,
        orgId: scoped.orgId,
        jobId: `job:${input.suffix}`,
        drainGeneration: "00000001",
        frozenAt: START.toISOString(),
      });
  }
  await getDb()
    .insert(schema.contentEncryptedVaultBrokerReplacementTranscripts)
    .values({
      id: `row:${input.suffix}`,
      transcriptId,
      ...scoped,
      phase: input.phase,
      activeKey: input.active ? `active-transcript:${input.suffix}` : null,
      oldBrokerEndpointId: `old:${input.suffix}`,
      newBrokerEndpointId: `new:${input.suffix}`,
      authorizerEndpointId: `authorizer:${input.suffix}`,
      offerHash: "33".repeat(32),
      offerBytesBase64url: "AQ",
      drainId,
      drainGeneration: drainId ? "00000001" : null,
      expiresAt: new Date(START.getTime() + DAY).toISOString(),
      offeredAt: START.toISOString(),
      activatedAt:
        input.phase === "activated" ? input.terminalAt?.toISOString() : null,
      terminatedAt:
        input.phase !== "activated" ? input.terminalAt?.toISOString() : null,
    });
  return { ...scoped, transcriptId, drainId };
}

async function insertRotationEvidence(suffix: string, eligibleAt: Date) {
  const scoped = scope(suffix);
  await getDb()
    .insert(schema.contentEncryptedVaults)
    .values({
      ...scoped,
      vaultState: "active",
    });
  const ceremonyId = `ceremony:${suffix}`;
  await getDb()
    .insert(schema.contentEncryptedVaultRotationEvidenceArtifacts)
    .values([
      {
        id: `ceremony-row:${suffix}`,
        ...scoped,
        ceremonyId,
        artifactKind: "ceremony",
        artifactKey: "ceremony",
        phase: "completed",
        terminalAt: START.toISOString(),
        purgeEligibleAt: eligibleAt.toISOString(),
      },
      {
        id: `artifact-row:${suffix}`,
        ...scoped,
        ceremonyId,
        artifactKind: "completion_attestation",
        artifactKey: "completion_attestation",
        evidenceBytesBase64url: "AQ",
      },
    ]);
}

beforeAll(async () => {
  process.env.DATABASE_URL = `file:${TEST_DB_PATH}`;
  const db = await import("../db/index.js");
  getDb = db.getDb;
  schema = db.schema;
  await (await import("../plugins/db.js")).default(undefined as never);
  const retention =
    await import("./private-vault-broker-replacement-retention.js");
  createService = retention.createPrivateVaultReplacementRetentionService;
  maxDelay = retention.PRIVATE_VAULT_REPLACEMENT_PURGE_MAX_DELAY_MS;
}, 60_000);

beforeEach(async () => {
  await getDb().delete(schema.contentEncryptedVaultRotationEvidenceArtifacts);
  await getDb().delete(schema.contentEncryptedVaultBrokerReplacementDrainJobs);
  await getDb().delete(
    schema.contentEncryptedVaultBrokerReplacementTranscripts,
  );
  await getDb().delete(schema.contentEncryptedVaultBrokerReplacementDrains);
  await getDb().delete(schema.contentEncryptedVaults);
});

afterAll(() => {
  for (const suffix of ["", "-shm", "-wal"]) {
    rmSync(`${TEST_DB_PATH}${suffix}`, { force: true });
  }
});

describe("Private Vault replacement retention", () => {
  it("retains terminal evidence through day 89 and makes it eligible at day 90", async () => {
    const terminal = await insertTranscript({
      suffix: "day90",
      phase: "activated",
      terminalAt: START,
      drainPhase: "committed",
    });
    await insertRotationEvidence(
      "evidence90",
      new Date(START.getTime() + 90 * DAY),
    );
    expect(
      await createService({
        now: () => new Date(START.getTime() + 89 * DAY),
      }).sweep(),
    ).toMatchObject({ transcriptsDeleted: 0, evidenceCeremoniesDeleted: 0 });
    expect(
      await createService({
        now: () => new Date(START.getTime() + 90 * DAY),
      }).sweep(),
    ).toMatchObject({
      transcriptsDeleted: 1,
      drainsDeleted: 1,
      drainJobsDeleted: 1,
      evidenceCeremoniesDeleted: 1,
      evidenceArtifactsDeleted: 2,
    });
    expect(
      await getDb()
        .select()
        .from(schema.contentEncryptedVaultBrokerReplacementTranscripts)
        .where(
          eq(
            schema.contentEncryptedVaultBrokerReplacementTranscripts
              .transcriptId,
            terminal.transcriptId,
          ),
        ),
    ).toHaveLength(0);
  });

  it("never purges active, witnessed, drained, or unactivated rotation state", async () => {
    await insertTranscript({
      suffix: "active",
      phase: "draining",
      terminalAt: START,
      drainPhase: "witnessed",
      active: true,
    });
    await insertTranscript({
      suffix: "drained",
      phase: "drained",
      terminalAt: START,
      drainPhase: "witnessed",
      active: true,
    });
    await insertTranscript({
      suffix: "rotation",
      phase: "rotation_committed",
      terminalAt: START,
      drainPhase: "committed",
      active: true,
    });
    const result = await createService({
      now: () => new Date(START.getTime() + 97 * DAY),
    }).sweep();
    expect(result.transcriptsDeleted).toBe(0);
    expect(
      await getDb()
        .select()
        .from(schema.contentEncryptedVaultBrokerReplacementTranscripts),
    ).toHaveLength(3);
    expect(
      await getDb()
        .select()
        .from(schema.contentEncryptedVaultBrokerReplacementDrains),
    ).toHaveLength(3);
  });

  it("is bounded, scope-isolated, idempotent, and scheduled inside the day-97 SLA", async () => {
    await insertTranscript({
      suffix: "scopea",
      phase: "aborted",
      terminalAt: START,
      drainPhase: "aborted",
    });
    await insertTranscript({
      suffix: "scopeb",
      phase: "aborted",
      terminalAt: START,
      drainPhase: "aborted",
    });
    const service = createService({
      now: () => new Date(START.getTime() + 97 * DAY),
      batchSize: 1,
    });
    expect(maxDelay).toBe(7 * DAY);
    expect((await service.sweep()).transcriptsDeleted).toBe(1);
    expect(
      await getDb()
        .select()
        .from(schema.contentEncryptedVaultBrokerReplacementTranscripts),
    ).toHaveLength(1);
    expect((await service.sweep()).transcriptsDeleted).toBe(1);
    expect((await service.sweep()).transcriptsDeleted).toBe(0);
  });
});
