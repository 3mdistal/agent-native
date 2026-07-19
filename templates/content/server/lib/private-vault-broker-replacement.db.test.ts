import { createHash } from "node:crypto";
import { rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { and, eq } from "drizzle-orm";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

const TEST_DB_PATH = join(
  tmpdir(),
  `private-vault-broker-replacement-${process.pid}-${Date.now()}.sqlite`,
);
const START = new Date("2026-07-19T12:00:00.000Z");
const EXPIRES = "2026-07-19T12:30:00.000Z";

let clock = START;
let getDb: (typeof import("../db/index.js"))["getDb"];
let schema: typeof import("../db/schema.js");
let createService: (typeof import("./private-vault-broker-replacement.js"))["createPrivateVaultBrokerReplacementTranscriptService"];
let ReplacementError: (typeof import("./private-vault-broker-replacement.js"))["PrivateVaultBrokerReplacementError"];

beforeAll(async () => {
  process.env.DATABASE_URL = `file:${TEST_DB_PATH}`;
  const dbModule = await import("../db/index.js");
  getDb = dbModule.getDb;
  schema = dbModule.schema;
  const replacement = await import("./private-vault-broker-replacement.js");
  createService =
    replacement.createPrivateVaultBrokerReplacementTranscriptService;
  ReplacementError = replacement.PrivateVaultBrokerReplacementError;
  await (await import("../plugins/db.js")).default(undefined as never);
}, 60_000);

afterAll(() => {
  for (const suffix of ["", "-shm", "-wal"]) {
    rmSync(`${TEST_DB_PATH}${suffix}`, { force: true });
  }
});

function bytes(value: string) {
  return Uint8Array.from(Buffer.from(value));
}

function hash(value: Uint8Array) {
  return createHash("sha256").update(value).digest("hex");
}

async function seed(suffix: string) {
  const scope = {
    ownerEmail: `${suffix}@example.com`,
    accountId: `account:${suffix}`,
    orgId: `org:${suffix}`,
    workspaceId: `workspace:${suffix}`,
    vaultId: `vault:${suffix}`,
  };
  const bindings = {
    oldBrokerEndpointId: `endpoint:old:${suffix}`,
    newBrokerEndpointId: `endpoint:new:${suffix}`,
    authorizerEndpointId: `endpoint:authorizer:${suffix}`,
  };
  await getDb()
    .insert(schema.contentEncryptedVaults)
    .values({
      ...scope,
      vaultState: "active",
      serverReceivedAt: START.toISOString(),
    });
  await getDb()
    .insert(schema.contentEncryptedVaultEndpoints)
    .values(
      [bindings.oldBrokerEndpointId, bindings.authorizerEndpointId].map(
        (endpointId) => ({
          endpointId,
          vaultId: scope.vaultId,
          ownerEmail: scope.ownerEmail,
          orgId: scope.orgId,
          endpointState: "online",
          publicIdentityJson: "{}",
          healthState: "healthy",
          serverReceivedAt: START.toISOString(),
        }),
      ),
    );
  return { scope, bindings };
}

function establishInput(
  seeded: Awaited<ReturnType<typeof seed>>,
  transcriptId: string,
) {
  return {
    transcriptId,
    bindings: seeded.bindings,
    offer: bytes(`offer:${transcriptId}`),
    expiresAt: EXPIRES,
  };
}

describe("Private Vault hosted broker replacement transcript", () => {
  it("is tenant-scoped, exact-retry idempotent, and permits one active replacement lane", async () => {
    const seeded = await seed("scope");
    const service = createService({ now: () => clock });
    const input = establishInput(seeded, "replacement:scope");

    const first = await service.establish(seeded.scope, input);
    await expect(service.establish(seeded.scope, input)).resolves.toEqual(
      first,
    );
    await expect(
      service.establish(seeded.scope, {
        ...input,
        offer: bytes("substituted-offer"),
      }),
    ).rejects.toBeInstanceOf(ReplacementError);
    await expect(
      service.read(
        { ...seeded.scope, ownerEmail: "attacker@example.com" },
        input.transcriptId,
      ),
    ).rejects.toMatchObject({ code: "not_found" });
    await expect(
      service.establish(
        seeded.scope,
        establishInput(seeded, "replacement:parallel"),
      ),
    ).rejects.toMatchObject({ code: "conflict" });
  });

  it("fails closed on phase skips, endpoint substitution, and oversized public frames", async () => {
    const seeded = await seed("hostile");
    const service = createService({ now: () => clock });
    const status = await service.establish(
      seeded.scope,
      establishInput(seeded, "replacement:hostile"),
    );
    const common = {
      bindings: seeded.bindings,
      offerHash: status.offerHash,
    };

    await expect(
      service.advance(seeded.scope, status.transcriptId, {
        ...common,
        to: "authorized",
        sasHash: "00".repeat(32),
        authorization: bytes("authorization"),
        approval: bytes("approval"),
      }),
    ).rejects.toMatchObject({ code: "conflict" });
    await expect(
      service.advance(seeded.scope, status.transcriptId, {
        ...common,
        bindings: {
          ...seeded.bindings,
          newBrokerEndpointId: "endpoint:new:substituted",
        },
        to: "challenge",
        challenge: bytes("challenge"),
      }),
    ).rejects.toMatchObject({ code: "conflict" });
    await expect(
      service.advance(seeded.scope, status.transcriptId, {
        ...common,
        to: "challenge",
        challenge: new Uint8Array(64 * 1024 + 1),
      }),
    ).rejects.toMatchObject({ code: "invalid_request" });
  });

  it("binds drain evidence and refuses activation until the exact rotation commit is recorded", async () => {
    const seeded = await seed("flow");
    const service = createService({ now: () => clock });
    let status = await service.establish(
      seeded.scope,
      establishInput(seeded, "replacement:flow"),
    );
    const common = {
      bindings: seeded.bindings,
      offerHash: status.offerHash,
    };
    const challenge = bytes("challenge:flow");
    status = await service.advance(seeded.scope, status.transcriptId, {
      ...common,
      to: "challenge",
      challenge,
    });
    const firstChallenge = status;
    clock = new Date("2026-07-19T12:01:00.000Z");
    await expect(
      service.advance(seeded.scope, status.transcriptId, {
        ...common,
        to: "challenge",
        challenge,
      }),
    ).resolves.toEqual(firstChallenge);
    const sas = bytes("sas:flow");
    status = await service.advance(seeded.scope, status.transcriptId, {
      ...common,
      to: "candidate_confirmed",
      challengeHash: hash(challenge),
      sas,
    });
    const approval = bytes("approval:flow");
    status = await service.advance(seeded.scope, status.transcriptId, {
      ...common,
      to: "authorized",
      sasHash: hash(sas),
      authorization: bytes("authorization:flow"),
      approval,
    });
    status = await service.advance(seeded.scope, status.transcriptId, {
      ...common,
      to: "draining",
      approvalHash: hash(approval),
      drainId: "drain:flow",
      drainGeneration: "generation:flow",
    });
    const attestation = bytes("signed-drain-attestation:flow");
    status = await service.advance(seeded.scope, status.transcriptId, {
      ...common,
      to: "drained",
      drainId: "drain:flow",
      drainGeneration: "generation:flow",
      totalCount: 3,
      completedCount: 2,
      failedCount: 1,
      cancelledCount: 0,
      drainDigest: "11".repeat(32),
      signedDrainAttestation: attestation,
    });
    await expect(
      service.advance(seeded.scope, status.transcriptId, {
        ...common,
        to: "activated",
        controlEntryId: "control:missing",
        controlEntryHash: "22".repeat(32),
        controlSequence: 7,
        rotationReceiptHash: "33".repeat(32),
      }),
    ).rejects.toMatchObject({ code: "conflict" });
    const receipt = bytes("rotation-receipt:flow");
    status = await service.advance(seeded.scope, status.transcriptId, {
      ...common,
      to: "rotation_committed",
      drainAttestationHash: hash(attestation),
      controlEntryId: "control:flow",
      controlEntryHash: "44".repeat(32),
      controlSequence: 7,
      rotationReceipt: receipt,
    });
    clock = new Date("2026-07-19T13:00:00.000Z");
    await expect(
      service.advance(seeded.scope, status.transcriptId, {
        ...common,
        to: "expired",
      }),
    ).rejects.toMatchObject({ code: "conflict" });
    await expect(
      service.advance(seeded.scope, status.transcriptId, {
        ...common,
        to: "aborted",
      }),
    ).rejects.toMatchObject({ code: "conflict" });
    await expect(
      service.advance(seeded.scope, status.transcriptId, {
        ...common,
        to: "activated",
        controlEntryId: "control:flow",
        controlEntryHash: "55".repeat(32),
        controlSequence: 7,
        rotationReceiptHash: hash(receipt),
      }),
    ).rejects.toMatchObject({ code: "conflict" });
    await expect(
      service.advance(seeded.scope, status.transcriptId, {
        ...common,
        to: "activated",
        controlEntryId: "control:flow",
        controlEntryHash: "44".repeat(32),
        controlSequence: 7,
        rotationReceiptHash: hash(receipt),
      }),
    ).resolves.toMatchObject({ phase: "activated" });
    const [candidateEndpoint] = await getDb()
      .select({ endpointId: schema.contentEncryptedVaultEndpoints.endpointId })
      .from(schema.contentEncryptedVaultEndpoints)
      .where(
        and(
          eq(
            schema.contentEncryptedVaultEndpoints.vaultId,
            seeded.scope.vaultId,
          ),
          eq(
            schema.contentEncryptedVaultEndpoints.endpointId,
            seeded.bindings.newBrokerEndpointId,
          ),
        ),
      )
      .limit(1);
    expect(candidateEndpoint).toBeUndefined();
  });
});
