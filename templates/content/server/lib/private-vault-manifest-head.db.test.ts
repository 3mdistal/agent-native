import { rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";

const TEST_DB_PATH = join(
  tmpdir(),
  `private-vault-manifest-head-${process.pid}-${Date.now()}.sqlite`,
);
const SCOPE = {
  ownerEmail: "owner@example.com",
  accountId: "account:manifest-head",
  orgId: "org:manifest-head",
  workspaceId: "workspace:manifest-head",
  vaultId: "vault:manifest-head",
};
const MANIFEST_OBJECT_ID = "object:manifest-head";

type Db = ReturnType<(typeof import("../db/index.js"))["getDb"]>;
type Tx =
  import("./private-vault-mutation-gate.js").PrivateVaultMutationTransaction;
type ManifestModule = typeof import("./private-vault-manifest-head.js");

let db: Db;
let schema: typeof import("../db/schema.js");
let manifest: ManifestModule;

function head(generation: number, suffix = `${generation}`) {
  return {
    objectId: MANIFEST_OBJECT_ID,
    revisionId: `revision:manifest-${suffix}`,
    generation,
  };
}

async function insertHead(
  transaction: Tx | Db,
  value: ReturnType<typeof head>,
) {
  await transaction
    .insert(schema.contentEncryptedVaultObjects)
    .values({
      objectId: value.objectId,
      vaultId: SCOPE.vaultId,
      ownerEmail: SCOPE.ownerEmail,
      orgId: SCOPE.orgId,
      objectType: "vault-manifest",
      objectState: "active",
      serverReceivedAt: "2026-07-19T12:00:00.000Z",
    })
    .onConflictDoNothing();
  await transaction.insert(schema.contentEncryptedVaultObjectRevisions).values({
    revisionId: value.revisionId,
    vaultId: SCOPE.vaultId,
    objectId: value.objectId,
    ownerEmail: SCOPE.ownerEmail,
    orgId: SCOPE.orgId,
    epoch: 7,
    algorithmId: "anc/v1",
    ciphertextByteLength: 32,
    opaqueRevisionJson: JSON.stringify({
      version: 1,
      vaultId: SCOPE.vaultId,
      objectId: value.objectId,
      revisionId: value.revisionId,
      revision: value.generation,
      parentRevisionIds: [],
      epoch: 7,
      ciphertextByteLength: 32,
      serverReceivedAt: "2026-07-19T12:00:00.000Z",
    }),
    serverReceivedAt: "2026-07-19T12:00:00.000Z",
  });
}

beforeAll(async () => {
  process.env.DATABASE_URL = `file:${TEST_DB_PATH}`;
  const dbModule = await import("../db/index.js");
  db = dbModule.getDb();
  schema = dbModule.schema;
  manifest = await import("./private-vault-manifest-head.js");
  await (await import("../plugins/db.js")).default(undefined as never);
}, 60_000);

beforeEach(async () => {
  await db.delete(schema.contentEncryptedVaultObjectRevisions);
  await db.delete(schema.contentEncryptedVaultObjects);
  await db.delete(schema.contentEncryptedVaults);
  await db.insert(schema.contentEncryptedVaults).values({
    ...SCOPE,
    vaultState: "active",
    serverReceivedAt: "2026-07-19T12:00:00.000Z",
  });
  await insertHead(db, head(1));
});

afterAll(() => {
  for (const suffix of ["", "-shm", "-wal"])
    rmSync(`${TEST_DB_PATH}${suffix}`, { force: true });
});

describe("Private Vault hosted manifest head", () => {
  it("allows one of two concurrent writers from the same prior head", async () => {
    const prior = head(1);
    const candidates = [head(2, "writer-a"), head(2, "writer-b")];
    const results = await Promise.allSettled(
      candidates.map((next) =>
        manifest.withPrivateVaultOrdinaryWrite(
          SCOPE,
          { prior, next },
          async (transaction) => {
            await insertHead(transaction, next);
            return next.revisionId;
          },
        ),
      ),
    );
    expect(
      results.filter((result) => result.status === "fulfilled"),
    ).toHaveLength(1);
    expect(
      results.filter((result) => result.status === "rejected"),
    ).toHaveLength(1);
  });

  it("pins the exact manifest and rejects stale or in-flight ordinary writes", async () => {
    const frozen = await manifest.freezePrivateVaultRotation({
      scope: SCOPE,
      kind: "remove_device",
      ceremonyId: "ceremony:manifest-head",
      baseEpoch: 7,
      targetEpoch: 8,
      manifest: head(1),
    });
    expect(frozen).toMatchObject({ idempotent: false });

    await expect(
      manifest.withPrivateVaultOrdinaryWrite(
        SCOPE,
        { prior: head(1), next: head(2) },
        async (transaction) => insertHead(transaction, head(2)),
      ),
    ).rejects.toBeInstanceOf(manifest.PrivateVaultManifestHeadConflictError);

    await expect(
      manifest.freezePrivateVaultRotation({
        scope: SCOPE,
        kind: "remove_device",
        ceremonyId: "ceremony:manifest-head",
        baseEpoch: 7,
        targetEpoch: 8,
        manifest: head(1),
      }),
    ).resolves.toMatchObject({ idempotent: true });
  });

  it("rejects a freeze against stale coordinates and hides tenant mismatch", async () => {
    await expect(
      manifest.freezePrivateVaultRotation({
        scope: SCOPE,
        kind: "remove_device",
        ceremonyId: "ceremony:manifest-stale",
        baseEpoch: 7,
        targetEpoch: 8,
        manifest: head(2),
      }),
    ).rejects.toBeInstanceOf(manifest.PrivateVaultManifestHeadConflictError);
    await expect(
      manifest.freezePrivateVaultRotation({
        scope: { ...SCOPE, ownerEmail: "other@example.com" },
        kind: "remove_device",
        ceremonyId: "ceremony:manifest-stale",
        baseEpoch: 7,
        targetEpoch: 8,
        manifest: head(1),
      }),
    ).rejects.toBeInstanceOf(manifest.PrivateVaultManifestHeadConflictError);
  });

  it("rolls back a candidate head when the caller fails inside the gate", async () => {
    await expect(
      manifest.withPrivateVaultOrdinaryWrite(
        SCOPE,
        { prior: head(1), next: head(2) },
        async (transaction) => {
          await insertHead(transaction, head(2));
          throw new Error("synthetic metadata failure");
        },
      ),
    ).rejects.toThrow("synthetic metadata failure");
    await expect(
      manifest.freezePrivateVaultRotation({
        scope: SCOPE,
        kind: "remove_device",
        ceremonyId: "ceremony:after-rollback",
        baseEpoch: 7,
        targetEpoch: 8,
        manifest: head(1),
      }),
    ).resolves.toMatchObject({ idempotent: false });
  });
});
