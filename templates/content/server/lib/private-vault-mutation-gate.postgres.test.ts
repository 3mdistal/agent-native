import { afterAll, beforeAll, describe, expect, it } from "vitest";

const DATABASE_URL = process.env.PRIVATE_VAULT_POSTGRES_TEST_DATABASE_URL;
const postgresIt = DATABASE_URL ? it : it.skip;
const suffix = `${process.pid}-${Date.now()}`;
const scope = {
  ownerEmail: `mutation-gate-${suffix}@example.com`,
  accountId: `account:mutation-gate:${suffix}`,
  orgId: `org:mutation-gate:${suffix}`,
  workspaceId: `workspace:mutation-gate:${suffix}`,
  vaultId: `vault:mutation-gate:${suffix}`,
};

type DbExec = import("@agent-native/core/db").DbExec;
type GateModule = typeof import("./private-vault-mutation-gate.js");

let firstConnection: DbExec | undefined;
let getDb: (typeof import("../db/index.js"))["getDb"];
let schema: typeof import("../db/schema.js");
let gateModule: GateModule;

beforeAll(async () => {
  if (!DATABASE_URL) return;
  process.env.DATABASE_URL = DATABASE_URL;
  const dbModule = await import("../db/index.js");
  getDb = dbModule.getDb;
  schema = dbModule.schema;
  gateModule = await import("./private-vault-mutation-gate.js");
  await (await import("../plugins/db.js")).default(undefined as never);
  const { createDbExec } = await import("@agent-native/core/db");
  firstConnection = await createDbExec({ url: DATABASE_URL });
  await getDb()
    .insert(schema.contentEncryptedVaults)
    .values({
      ...scope,
      vaultState: "active",
      serverReceivedAt: "2026-07-19T12:00:00.000Z",
    });
}, 120_000);

afterAll(async () => {
  if (!DATABASE_URL || !getDb || !schema) return;
  await getDb()
    .delete(schema.contentEncryptedVaults)
    .where(
      (await import("drizzle-orm")).eq(
        schema.contentEncryptedVaults.vaultId,
        scope.vaultId,
      ),
    );
  await firstConnection?.close?.();
});

describe("Private Vault mutation gate Postgres row lock", () => {
  postgresIt(
    "blocks a second pool on the real vault tuple and then observes the committed CAS",
    async () => {
      if (!firstConnection?.transaction) throw new Error("missing transaction");
      let release!: () => void;
      const held = new Promise<void>((resolve) => {
        release = resolve;
      });
      let rowLocked!: () => void;
      const locked = new Promise<void>((resolve) => {
        rowLocked = resolve;
      });

      const first = firstConnection.transaction(async (tx) => {
        const result = await tx.execute({
          sql: `UPDATE content_encrypted_vaults
            SET mutation_phase = ?, mutation_kind = ?, mutation_ceremony_id = ?,
                mutation_base_epoch = ?, mutation_target_epoch = ?, mutation_serial = ?
            WHERE vault_id = ? AND owner_email = ? AND account_id = ?
              AND org_id = ? AND workspace_id = ? AND mutation_serial = ?`,
          args: [
            "draining",
            "remove_device",
            "ceremony:postgres-first",
            11,
            12,
            1,
            scope.vaultId,
            scope.ownerEmail,
            scope.accountId,
            scope.orgId,
            scope.workspaceId,
            0,
          ],
        });
        expect(result.rowsAffected).toBe(1);
        rowLocked();
        await held;
      });
      await locked;

      let secondEntered = false;
      const second = gateModule.withPrivateVaultMutationGate(
        scope,
        async (gate) => {
          secondEntered = true;
          return gate.transition(
            {
              serial: 0,
              phase: "open",
              kind: null,
              ceremonyId: null,
              baseEpoch: null,
              targetEpoch: null,
              manifestObjectId: null,
              manifestRevisionId: null,
              manifestGeneration: null,
            },
            {
              phase: "draining",
              kind: "remove_device",
              ceremonyId: "ceremony:postgres-second",
              baseEpoch: 11,
              targetEpoch: 12,
              manifestObjectId: null,
              manifestRevisionId: null,
              manifestGeneration: null,
            },
          );
        },
      );
      await new Promise((resolve) => setTimeout(resolve, 100));
      expect(secondEntered).toBe(false);

      release();
      await first;
      await expect(second).rejects.toMatchObject({ code: "conflict" });
      expect(secondEntered).toBe(true);
    },
    120_000,
  );
});
