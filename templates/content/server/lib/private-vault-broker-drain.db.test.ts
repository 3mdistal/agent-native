import { rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { eq } from "drizzle-orm";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import type { PrivateVaultJobMetadata } from "./private-vault-jobs.js";

const TEST_DB_PATH = join(
  tmpdir(),
  `private-vault-broker-drain-${process.pid}-${Date.now()}.sqlite`,
);
const START = "2026-07-19T12:00:00.000Z";
const DEADLINE = "2026-07-19T12:10:00.000Z";
const AFTER_DEADLINE = "2026-07-19T12:11:00.000Z";

let clock = START;
let getDb: (typeof import("../db/index.js"))["getDb"];
let schema: typeof import("../db/schema.js");
let jobStore: (typeof import("./private-vault-jobs.js"))["sqlPrivateVaultJobStore"];
let createDrainService: (typeof import("./private-vault-jobs.js"))["createPrivateVaultBrokerDrainService"];
let DrainConflict: (typeof import("./private-vault-jobs.js"))["PrivateVaultBrokerDrainConflictError"];
let DrainNotFound: (typeof import("./private-vault-jobs.js"))["PrivateVaultBrokerDrainNotFoundError"];
let JobConflict: (typeof import("./private-vault-jobs.js"))["PrivateVaultJobConflictError"];
let createStagingService: (typeof import("./private-vault-ciphertext-staging.js"))["createPrivateVaultCiphertextStagingService"];
let stagingStore: (typeof import("./private-vault-ciphertext-staging.js"))["sqlPrivateVaultCiphertextStagingStore"];

beforeAll(async () => {
  process.env.DATABASE_URL = `file:${TEST_DB_PATH}`;
  const dbModule = await import("../db/index.js");
  getDb = dbModule.getDb;
  schema = dbModule.schema;
  const jobs = await import("./private-vault-jobs.js");
  jobStore = jobs.sqlPrivateVaultJobStore;
  createDrainService = jobs.createPrivateVaultBrokerDrainService;
  DrainConflict = jobs.PrivateVaultBrokerDrainConflictError;
  DrainNotFound = jobs.PrivateVaultBrokerDrainNotFoundError;
  JobConflict = jobs.PrivateVaultJobConflictError;
  const staging = await import("./private-vault-ciphertext-staging.js");
  createStagingService = staging.createPrivateVaultCiphertextStagingService;
  stagingStore = staging.sqlPrivateVaultCiphertextStagingStore;
  await (await import("../plugins/db.js")).default(undefined as never);
}, 60_000);

afterAll(() => {
  for (const suffix of ["", "-shm", "-wal"]) {
    rmSync(`${TEST_DB_PATH}${suffix}`, { force: true });
  }
});

async function seedVault(suffix: string) {
  const ownerEmail = `${suffix}@example.com`;
  const orgId = `org:${suffix}`;
  const vaultId = `vault:${suffix}`;
  const oldBrokerEndpointId = `endpoint:old:${suffix}`;
  const authorizerEndpointId = `endpoint:authorizer:${suffix}`;
  const replacementBrokerEndpointId = `endpoint:replacement:${suffix}`;
  const grantId = `grant:${suffix}`;
  await getDb()
    .insert(schema.contentEncryptedVaults)
    .values({
      vaultId,
      ownerEmail,
      orgId,
      accountId: `account:${suffix}`,
      workspaceId: `workspace:${suffix}`,
      vaultState: "active",
      serverReceivedAt: START,
    });
  await getDb()
    .insert(schema.contentEncryptedVaultEndpoints)
    .values([
      {
        endpointId: oldBrokerEndpointId,
        vaultId,
        ownerEmail,
        orgId,
        endpointState: "online",
        publicIdentityJson: "{}",
        healthState: "healthy",
        serverReceivedAt: START,
      },
      {
        endpointId: authorizerEndpointId,
        vaultId,
        ownerEmail,
        orgId,
        endpointState: "online",
        publicIdentityJson: "{}",
        healthState: "healthy",
        serverReceivedAt: START,
      },
    ]);
  await getDb()
    .insert(schema.contentEncryptedVaultKeyEpochs)
    .values({
      id: `${vaultId}:1`,
      vaultId,
      ownerEmail,
      orgId,
      epoch: 1,
      state: "active",
      serverReceivedAt: START,
    });
  await getDb().insert(schema.contentEncryptedVaultGrants).values({
    grantId,
    vaultId,
    ownerEmail,
    orgId,
    recipientEndpointId: oldBrokerEndpointId,
    algorithmId: "anc:v1",
    ciphertextByteLength: 4,
    issuedAt: START,
    expiresAt: "2026-07-20T12:00:00.000Z",
    serverReceivedAt: START,
  });
  return {
    scope: { ownerEmail, orgId, vaultId },
    oldBrokerEndpointId,
    authorizerEndpointId,
    replacementBrokerEndpointId,
    grantId,
  };
}

function freezeInput(
  seeded: Awaited<ReturnType<typeof seedVault>>,
  suffix: string,
) {
  return {
    drainId: `drain:${suffix}`,
    oldBrokerEndpointId: seeded.oldBrokerEndpointId,
    replacementBrokerEndpointId: seeded.replacementBrokerEndpointId,
    authorizerEndpointId: seeded.authorizerEndpointId,
    authorizerApprovalId: `approval:${suffix}`,
    authorizerApprovalHash: `approvalhash:${suffix}`,
    drainGeneration: `generation:${suffix}`,
    deadlineAt: DEADLINE,
  };
}

function jobMetadata(
  seeded: Awaited<ReturnType<typeof seedVault>>,
  jobId: string,
): PrivateVaultJobMetadata {
  return {
    vaultId: seeded.scope.vaultId,
    jobId,
    grantId: seeded.grantId,
    recipientEndpointId: seeded.oldBrokerEndpointId,
    epoch: 1,
    algorithmId: "anc:v1",
    ciphertextByteLength: 4,
    issuedAt: START,
    expiresAt: "2026-07-20T12:00:00.000Z",
    state: "queued",
    retryCount: 0,
    retryAt: null,
    leaseExpiresAt: null,
    serverReceivedAt: START,
  };
}

async function insertJob(
  seeded: Awaited<ReturnType<typeof seedVault>>,
  jobId: string,
  state: "queued" | "completed" | "failed" | "cancelled",
) {
  const job = jobMetadata(seeded, jobId);
  await getDb().insert(schema.contentEncryptedVaultJobs).values({
    jobId,
    vaultId: seeded.scope.vaultId,
    ownerEmail: seeded.scope.ownerEmail,
    orgId: seeded.scope.orgId,
    grantId: seeded.grantId,
    recipientEndpointId: seeded.oldBrokerEndpointId,
    epoch: 1,
    algorithmId: job.algorithmId,
    ciphertextByteLength: job.ciphertextByteLength,
    issuedAt: job.issuedAt,
    expiresAt: job.expiresAt,
    jobState: state,
    retryCount: 0,
    serverReceivedAt: START,
  });
}

describe("Private Vault hosted broker replacement drain", () => {
  it("freezes enqueue, persist, and claim for the old broker and is exact-retry idempotent", async () => {
    clock = START;
    const seeded = await seedVault("freeze");
    const service = createDrainService({ now: () => clock });
    const input = freezeInput(seeded, "freeze");
    await insertJob(seeded, "job:before-freeze", "queued");

    const first = await service.freeze(seeded.scope, input);
    const retry = await service.freeze(seeded.scope, input);
    expect(retry).toEqual(first);

    await expect(
      jobStore.authorizeEnqueue(
        seeded.scope,
        jobMetadata(seeded, "job:after-freeze"),
        START,
      ),
    ).resolves.toBe(false);
    await expect(
      jobStore.claim(
        { ...seeded.scope, endpointId: seeded.oldBrokerEndpointId },
        START,
        "2026-07-19T12:01:00.000Z",
      ),
    ).resolves.toBeNull();

    const staging = createStagingService({
      store: stagingStore,
      now: () => new Date(clock),
    });
    const stage = await staging.stage(seeded.scope, {
      kind: "job",
      vaultId: seeded.scope.vaultId,
      jobId: "job:after-freeze",
      part: "request",
    });
    await expect(
      jobStore.persist(
        seeded.scope,
        jobMetadata(seeded, "job:after-freeze"),
        stage,
      ),
    ).rejects.toBeInstanceOf(JobConflict);
    clock = AFTER_DEADLINE;
    await expect(service.freeze(seeded.scope, input)).resolves.toEqual(first);
  });

  it("allows only one active replacement for an old broker", async () => {
    clock = START;
    const seeded = await seedVault("unique");
    const service = createDrainService({ now: () => clock });
    await service.freeze(seeded.scope, freezeInput(seeded, "unique:first"));
    await expect(
      service.freeze(seeded.scope, freezeInput(seeded, "unique:second")),
    ).rejects.toBeInstanceOf(DrainConflict);
  });

  it("publishes counts and a stable digest only after every job is terminal", async () => {
    clock = START;
    const seeded = await seedVault("witness");
    const service = createDrainService({ now: () => clock });
    const input = freezeInput(seeded, "witness");
    await insertJob(seeded, "job:witness:completed", "completed");
    await insertJob(seeded, "job:witness:failed", "failed");
    await insertJob(seeded, "job:witness:queued", "queued");
    await service.freeze(seeded.scope, input);

    await expect(
      service.witness(seeded.scope, input.drainId),
    ).rejects.toBeInstanceOf(DrainConflict);
    const before = await service.get(seeded.scope, input.drainId);
    expect(before).toMatchObject({
      totalJobCount: null,
      terminalJobsDigest: null,
      witnessGeneration: null,
    });

    clock = AFTER_DEADLINE;
    const decided = await service.resolveDeadline(seeded.scope, {
      drainId: input.drainId,
      decisionId: "decision:cancel:witness",
      decision: "cancel_nonterminal",
    });
    expect(decided.deadlineDecision).toBe("cancel_nonterminal");
    await expect(
      service.resolveDeadline(seeded.scope, {
        drainId: input.drainId,
        decisionId: "decision:cancel:witness",
        decision: "cancel_nonterminal",
      }),
    ).resolves.toEqual(decided);
    await expect(
      service.resolveDeadline(seeded.scope, {
        drainId: input.drainId,
        decisionId: "decision:conflicting:witness",
        decision: "abort",
      }),
    ).rejects.toBeInstanceOf(DrainConflict);
    const witness = await service.witness(seeded.scope, input.drainId);
    expect(witness).toMatchObject({
      phase: "witnessed",
      witnessGeneration: 1,
      totalJobCount: 1,
      completedJobCount: 0,
      failedJobCount: 0,
      cancelledJobCount: 1,
    });
    expect(witness.terminalJobsDigest).toMatch(/^[a-f0-9]{64}$/);
    await expect(service.witness(seeded.scope, input.drainId)).resolves.toEqual(
      witness,
    );
  });

  it("requires an explicit deadline decision and never expires a still-live job", async () => {
    clock = START;
    const seeded = await seedVault("deadline");
    const service = createDrainService({ now: () => clock });
    const input = freezeInput(seeded, "deadline");
    await insertJob(seeded, "job:deadline:live", "queued");
    await service.freeze(seeded.scope, input);

    await expect(
      service.resolveDeadline(seeded.scope, {
        drainId: input.drainId,
        decisionId: "decision:early",
        decision: "abort",
      }),
    ).rejects.toBeInstanceOf(DrainConflict);
    clock = AFTER_DEADLINE;
    await expect(
      service.resolveDeadline(seeded.scope, {
        drainId: input.drainId,
        decisionId: "decision:expire-live",
        decision: "expire_nonterminal",
      }),
    ).rejects.toBeInstanceOf(DrainConflict);
    expect(
      await getDb()
        .select({ state: schema.contentEncryptedVaultJobs.jobState })
        .from(schema.contentEncryptedVaultJobs)
        .where(eq(schema.contentEncryptedVaultJobs.jobId, "job:deadline:live")),
    ).toEqual([{ state: "queued" }]);

    const aborted = await service.resolveDeadline(seeded.scope, {
      drainId: input.drainId,
      decisionId: "decision:abort-deadline",
      decision: "abort",
    });
    expect(aborted.phase).toBe("aborted");
    await expect(
      service.resolveDeadline(seeded.scope, {
        drainId: input.drainId,
        decisionId: "decision:abort-deadline",
        decision: "abort",
      }),
    ).resolves.toEqual(aborted);
  });

  it("fails closed across account scope and on conflicting finalization", async () => {
    clock = START;
    const seeded = await seedVault("hostile");
    const otherVault = await seedVault("hostile-other-vault");
    const service = createDrainService({ now: () => clock });
    const input = freezeInput(seeded, "hostile");
    await insertJob(seeded, "job:hostile:done", "completed");
    await service.freeze(seeded.scope, input);
    const witness = await service.witness(seeded.scope, input.drainId);
    const wrongScope = {
      ...seeded.scope,
      ownerEmail: "attacker@example.com",
    };
    await expect(service.get(wrongScope, input.drainId)).rejects.toBeInstanceOf(
      DrainNotFound,
    );
    await expect(
      service.get(otherVault.scope, input.drainId),
    ).rejects.toBeInstanceOf(DrainNotFound);
    await expect(
      service.finalize(wrongScope, {
        drainId: input.drainId,
        completionId: "completion:hostile",
        witnessGeneration: witness.witnessGeneration!,
        terminalJobsDigest: witness.terminalJobsDigest!,
      }),
    ).rejects.toBeInstanceOf(DrainNotFound);
    await expect(
      service.finalize(otherVault.scope, {
        drainId: input.drainId,
        completionId: "completion:other-vault",
        witnessGeneration: witness.witnessGeneration!,
        terminalJobsDigest: witness.terminalJobsDigest!,
      }),
    ).rejects.toBeInstanceOf(DrainNotFound);

    const committed = await service.finalize(seeded.scope, {
      drainId: input.drainId,
      completionId: "completion:hostile",
      witnessGeneration: witness.witnessGeneration!,
      terminalJobsDigest: witness.terminalJobsDigest!,
    });
    await expect(
      service.finalize(seeded.scope, {
        drainId: input.drainId,
        completionId: "completion:different",
        witnessGeneration: witness.witnessGeneration!,
        terminalJobsDigest: witness.terminalJobsDigest!,
      }),
    ).rejects.toBeInstanceOf(DrainConflict);
    await expect(
      service.finalize(seeded.scope, {
        drainId: input.drainId,
        completionId: "completion:hostile",
        witnessGeneration: witness.witnessGeneration!,
        terminalJobsDigest: witness.terminalJobsDigest!,
      }),
    ).resolves.toEqual(committed);
  });
});
