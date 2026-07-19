import { afterAll, beforeAll, describe, expect, it } from "vitest";

const DATABASE_URL = process.env.PRIVATE_VAULT_POSTGRES_TEST_DATABASE_URL;
const postgresIt = DATABASE_URL ? it : it.skip;
const suffix = `${process.pid}-${Date.now()}`;
const scope = {
  ownerEmail: `manifest-head-${suffix}@example.com`,
  accountId: `account:manifest-head:${suffix}`,
  orgId: `org:manifest-head:${suffix}`,
  workspaceId: `workspace:manifest-head:${suffix}`,
  vaultId: `vault:manifest-head:${suffix}`,
};
const objectId = `object:manifest-head:${suffix}`;

type Db = ReturnType<(typeof import("../db/index.js"))["getDb"]>;
type Tx =
  import("./private-vault-mutation-gate.js").PrivateVaultMutationTransaction;

let db: Db;
let schema: typeof import("../db/schema.js");
let manifest: typeof import("./private-vault-manifest-head.js");

function head(generation: number, writer = "base") {
  return {
    objectId,
    revisionId: `revision:manifest-head:${generation}:${writer}:${suffix}`,
    generation,
  };
}

async function insertHead(
  transaction: Db | Tx,
  value: ReturnType<typeof head>,
) {
  await transaction
    .insert(schema.contentEncryptedVaultObjects)
    .values({
      objectId,
      vaultId: scope.vaultId,
      ownerEmail: scope.ownerEmail,
      orgId: scope.orgId,
      objectType: "vault-manifest",
      objectState: "active",
      serverReceivedAt: "2026-07-19T12:00:00.000Z",
    })
    .onConflictDoNothing();
  await transaction.insert(schema.contentEncryptedVaultObjectRevisions).values({
    revisionId: value.revisionId,
    vaultId: scope.vaultId,
    objectId,
    ownerEmail: scope.ownerEmail,
    orgId: scope.orgId,
    epoch: 7,
    algorithmId: "anc/v1",
    ciphertextByteLength: 32,
    opaqueRevisionJson: JSON.stringify({
      version: 1,
      vaultId: scope.vaultId,
      objectId,
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
  if (!DATABASE_URL) return;
  process.env.DATABASE_URL = DATABASE_URL;
  const dbModule = await import("../db/index.js");
  db = dbModule.getDb();
  schema = dbModule.schema;
  manifest = await import("./private-vault-manifest-head.js");
  await (await import("../plugins/db.js")).default(undefined as never);
  await db.insert(schema.contentEncryptedVaults).values({
    ...scope,
    vaultState: "active",
    serverReceivedAt: "2026-07-19T12:00:00.000Z",
  });
  await insertHead(db, head(1));
}, 120_000);

afterAll(async () => {
  if (!DATABASE_URL || !db || !schema) return;
  const { eq } = await import("drizzle-orm");
  await db
    .delete(schema.contentEncryptedVaultObjectRevisions)
    .where(
      eq(schema.contentEncryptedVaultObjectRevisions.vaultId, scope.vaultId),
    );
  await db
    .delete(schema.contentEncryptedVaultObjects)
    .where(eq(schema.contentEncryptedVaultObjects.vaultId, scope.vaultId));
  await db
    .delete(schema.contentEncryptedVaults)
    .where(eq(schema.contentEncryptedVaults.vaultId, scope.vaultId));
});

describe("Private Vault manifest CAS on Postgres", () => {
  postgresIt(
    "serializes two physical writer transactions from one prior head",
    async () => {
      const prior = head(1);
      const candidates = [head(2, "a"), head(2, "b")];
      const settled = await Promise.allSettled(
        candidates.map((next) =>
          manifest.withPrivateVaultOrdinaryWrite(
            scope,
            { prior, next },
            async (transaction) => {
              await insertHead(transaction, next);
              return next.revisionId;
            },
          ),
        ),
      );
      expect(
        settled.filter((result) => result.status === "fulfilled"),
      ).toHaveLength(1);
      expect(
        settled.filter((result) => result.status === "rejected"),
      ).toHaveLength(1);
    },
    120_000,
  );
});
