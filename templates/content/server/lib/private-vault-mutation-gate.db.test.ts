import { rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";

const TEST_DB_PATH = join(
  tmpdir(),
  `private-vault-mutation-gate-${process.pid}-${Date.now()}.sqlite`,
);
const SCOPE = {
  ownerEmail: "owner@example.com",
  accountId: "account:mutation-gate",
  orgId: "org:mutation-gate",
  workspaceId: "workspace:mutation-gate",
  vaultId: "vault:mutation-gate",
};

type GateModule = typeof import("./private-vault-mutation-gate.js");
type DbExec = import("@agent-native/core/db").DbExec;
type State =
  import("./private-vault-mutation-gate.js").PrivateVaultMutationState;
type Destination =
  import("./private-vault-mutation-gate.js").PrivateVaultMutationDestination;

let getDb: (typeof import("../db/index.js"))["getDb"];
let schema: typeof import("../db/schema.js");
let gateModule: GateModule;
let sqliteProbe: DbExec;

const open = (serial = 0): State => ({
  serial,
  phase: "open",
  kind: null,
  ceremonyId: null,
  baseEpoch: null,
  targetEpoch: null,
  manifestObjectId: null,
  manifestRevisionId: null,
  manifestGeneration: null,
});

const draining = (ceremonyId = "ceremony:one"): Destination => ({
  phase: "draining",
  kind: "remove_device",
  ceremonyId,
  baseEpoch: 7,
  targetEpoch: 8,
  manifestObjectId: null,
  manifestRevisionId: null,
  manifestGeneration: null,
});

const rotating = (): Destination => ({
  phase: "rotating",
  kind: "remove_device",
  ceremonyId: "ceremony:one",
  baseEpoch: 7,
  targetEpoch: 8,
  manifestObjectId: "object:manifest",
  manifestRevisionId: "revision:manifest",
  manifestGeneration: 19,
});

beforeAll(async () => {
  process.env.DATABASE_URL = `file:${TEST_DB_PATH}`;
  const dbModule = await import("../db/index.js");
  getDb = dbModule.getDb;
  schema = dbModule.schema;
  gateModule = await import("./private-vault-mutation-gate.js");
  await (await import("../plugins/db.js")).default(undefined as never);
  const { createDbExec } = await import("@agent-native/core/db");
  sqliteProbe = await createDbExec({ url: `file:${TEST_DB_PATH}` });
  await sqliteProbe.execute("PRAGMA busy_timeout = 25");
}, 60_000);

beforeEach(async () => {
  await getDb().delete(schema.contentEncryptedVaults);
  await getDb()
    .insert(schema.contentEncryptedVaults)
    .values({
      ...SCOPE,
      vaultState: "active",
      serverReceivedAt: "2026-07-19T12:00:00.000Z",
    });
});

afterAll(async () => {
  await sqliteProbe.close?.();
  for (const suffix of ["", "-shm", "-wal"]) {
    rmSync(`${TEST_DB_PATH}${suffix}`, { force: true });
  }
});

describe("Private Vault mutation gate state contract", () => {
  it("enforces exact phase metadata and consecutive epochs", () => {
    expect(gateModule.isValidPrivateVaultMutationState(open())).toBe(true);
    expect(
      gateModule.isValidPrivateVaultMutationState(
        open(Number.MAX_SAFE_INTEGER),
      ),
    ).toBe(true);
    expect(
      gateModule.isValidPrivateVaultMutationState({
        ...open(),
        phase: "draining",
      }),
    ).toBe(false);
    expect(
      gateModule.isValidPrivateVaultMutationState({
        serial: 1,
        ...draining(),
        targetEpoch: 9,
      }),
    ).toBe(false);
    expect(
      gateModule.isValidPrivateVaultMutationState({
        serial: 2,
        ...rotating(),
      }),
    ).toBe(true);
    expect(
      gateModule.isValidPrivateVaultMutationState({
        serial: 2,
        ...rotating(),
        manifestGeneration: null,
      }),
    ).toBe(false);
  });

  it("increments the serial for exact allowed transitions and exact retries only", async () => {
    const first = await gateModule.withPrivateVaultMutationGate(
      SCOPE,
      async (gate) => gate.transition(open(), draining()),
    );
    expect(first).toEqual({
      state: { serial: 1, ...draining() },
      idempotent: false,
    });

    const retry = await gateModule.withPrivateVaultMutationGate(
      SCOPE,
      async (gate) => gate.transition(open(), draining()),
    );
    expect(retry).toEqual({ state: first.state, idempotent: true });

    const promoted = await gateModule.withPrivateVaultMutationGate(
      SCOPE,
      async (gate) => gate.transition(first.state, rotating()),
    );
    expect(promoted).toEqual({
      state: { serial: 2, ...rotating() },
      idempotent: false,
    });

    const completed = await gateModule.withPrivateVaultMutationGate(
      SCOPE,
      async (gate) => gate.transition(promoted.state, open(0)),
    );
    expect(completed).toEqual({ state: open(3), idempotent: false });
  });

  it("rejects a stale or merely similar retry", async () => {
    await gateModule.withPrivateVaultMutationGate(SCOPE, async (gate) =>
      gate.transition(open(), draining()),
    );
    await expect(
      gateModule.withPrivateVaultMutationGate(SCOPE, async (gate) =>
        gate.transition(open(), draining("ceremony:other")),
      ),
    ).rejects.toMatchObject({ code: "conflict" });
  });

  it("rolls a transition back when later transaction-scoped work fails", async () => {
    await expect(
      gateModule.withPrivateVaultMutationGate(SCOPE, async (gate) => {
        await gate.transition(open(), draining());
        throw new Error("synthetic later write failure");
      }),
    ).rejects.toThrow("synthetic later write failure");

    await expect(
      gateModule.withPrivateVaultMutationGate(SCOPE, async (gate) =>
        gate.current(),
      ),
    ).resolves.toEqual(open());
  });

  it("rejects forbidden phase transitions before writing", async () => {
    const { serial: _ignoredSerial, ...openDestination } = open();
    await expect(
      gateModule.withPrivateVaultMutationGate(SCOPE, async (gate) =>
        gate.transition(open(), openDestination),
      ),
    ).rejects.toMatchObject({ code: "invalid_transition" });

    const unchanged = await gateModule.withPrivateVaultMutationGate(
      SCOPE,
      async (gate) => gate.current(),
    );
    expect(unchanged).toEqual(open());
  });

  it("returns identical not-found behavior for absent and wrong-tenant scopes", async () => {
    const codes: string[] = [];
    for (const scope of [
      { ...SCOPE, vaultId: "vault:absent" },
      { ...SCOPE, ownerEmail: "other@example.com" },
      { ...SCOPE, accountId: "account:other" },
      { ...SCOPE, orgId: "org:other" },
      { ...SCOPE, workspaceId: "workspace:other" },
    ]) {
      try {
        await gateModule.withPrivateVaultMutationGate(scope, async () => null);
      } catch (error) {
        codes.push((error as { code?: string }).code ?? "unknown");
      }
    }
    expect(codes).toEqual(Array(5).fill("not_found"));
  });

  it("normalizes the authenticated email before taking the scoped lock", async () => {
    await expect(
      gateModule.withPrivateVaultMutationGate(
        { ...SCOPE, ownerEmail: " OWNER@EXAMPLE.COM " },
        async (gate) => gate.current(),
      ),
    ).resolves.toEqual(open());
  });

  it.each([
    ["unknown phase", { mutationPhase: "paused" }],
    ["fractional serial", { mutationSerial: 0.5 }],
    ["open metadata", { mutationKind: "remove_device" }],
    [
      "draining missing identity",
      {
        mutationPhase: "draining",
        mutationBaseEpoch: 7,
        mutationTargetEpoch: 8,
      },
    ],
    [
      "draining unknown kind",
      {
        mutationPhase: "draining",
        mutationKind: "endpoint_removal",
        mutationCeremonyId: "ceremony:corrupt",
        mutationBaseEpoch: 7,
        mutationTargetEpoch: 8,
      },
    ],
    [
      "draining manifest pin",
      {
        mutationPhase: "draining",
        mutationKind: "remove_device",
        mutationCeremonyId: "ceremony:corrupt",
        mutationBaseEpoch: 7,
        mutationTargetEpoch: 8,
        mutationManifestObjectId: "object:corrupt",
      },
    ],
    [
      "rotating invalid manifest identifier",
      {
        mutationPhase: "rotating",
        mutationKind: "remove_device",
        mutationCeremonyId: "ceremony:corrupt",
        mutationBaseEpoch: 7,
        mutationTargetEpoch: 8,
        mutationManifestObjectId: "not a valid id",
        mutationManifestRevisionId: "revision:corrupt",
        mutationManifestGeneration: 1,
      },
    ],
    [
      "non-consecutive epochs",
      {
        mutationPhase: "draining",
        mutationKind: "remove_device",
        mutationCeremonyId: "ceremony:corrupt",
        mutationBaseEpoch: 7,
        mutationTargetEpoch: 9,
      },
    ],
    [
      "rotating missing revision",
      {
        mutationPhase: "rotating",
        mutationKind: "remove_device",
        mutationCeremonyId: "ceremony:corrupt",
        mutationBaseEpoch: 7,
        mutationTargetEpoch: 8,
        mutationManifestObjectId: "object:corrupt",
        mutationManifestGeneration: 1,
      },
    ],
    [
      "zero manifest generation",
      {
        mutationPhase: "rotating",
        mutationKind: "remove_device",
        mutationCeremonyId: "ceremony:corrupt",
        mutationBaseEpoch: 7,
        mutationTargetEpoch: 8,
        mutationManifestObjectId: "object:corrupt",
        mutationManifestRevisionId: "revision:corrupt",
        mutationManifestGeneration: 0,
      },
    ],
  ])("fails closed on persisted %s", async (_label, corruption) => {
    await getDb().update(schema.contentEncryptedVaults).set(corruption);
    await expect(
      gateModule.withPrivateVaultMutationGate(SCOPE, async () => null),
    ).rejects.toMatchObject({ code: "invalid_state" });
  });
});

describe("Private Vault mutation gate SQLite serialization", () => {
  it("serializes concurrent writers and gives one conflicting ceremony the gate", async () => {
    let releaseFirst!: () => void;
    const holdFirst = new Promise<void>((resolve) => {
      releaseFirst = resolve;
    });
    let firstLocked!: () => void;
    const firstHasLock = new Promise<void>((resolve) => {
      firstLocked = resolve;
    });
    let secondEntered = false;

    const first = gateModule.withPrivateVaultMutationGate(
      SCOPE,
      async (gate) => {
        const result = await gate.transition(open(), draining());
        firstLocked();
        await holdFirst;
        return result;
      },
    );
    await firstHasLock;

    // A second physical SQLite connection cannot begin a writer while the
    // gate callback is open. This proves the framework transaction used above
    // really issued BEGIN IMMEDIATE; the in-process promise queue alone would
    // not block this independent connection.
    await expect(sqliteProbe.execute("BEGIN IMMEDIATE")).rejects.toThrow(
      /locked/i,
    );

    const second = gateModule.withPrivateVaultMutationGate(
      SCOPE,
      async (gate) => {
        secondEntered = true;
        return gate.transition(open(), draining("ceremony:other"));
      },
    );
    await new Promise((resolve) => setTimeout(resolve, 20));
    expect(secondEntered).toBe(false);

    releaseFirst();
    await expect(first).resolves.toMatchObject({ idempotent: false });
    await expect(second).rejects.toMatchObject({ code: "conflict" });
    expect(secondEntered).toBe(true);
  });
});
