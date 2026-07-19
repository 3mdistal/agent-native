import { createHash } from "node:crypto";
import { rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { and, eq } from "drizzle-orm";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

const TEST_DB_PATH = join(
  tmpdir(),
  `private-vault-rotation-evidence-${process.pid}-${Date.now()}.sqlite`,
);
const START = new Date("2026-07-19T12:00:00.000Z");
const DAY = 24 * 60 * 60 * 1_000;

let clock = START;
let getDb: (typeof import("../db/index.js"))["getDb"];
let schema: typeof import("../db/schema.js");
let createStore: (typeof import("./private-vault-rotation-evidence.js"))["createPrivateVaultRotationEvidenceStore"];
let RotationEvidenceError: (typeof import("./private-vault-rotation-evidence.js"))["PrivateVaultRotationEvidenceError"];

beforeAll(async () => {
  process.env.DATABASE_URL = `file:${TEST_DB_PATH}`;
  const dbModule = await import("../db/index.js");
  getDb = dbModule.getDb;
  schema = dbModule.schema;
  const evidence = await import("./private-vault-rotation-evidence.js");
  createStore = evidence.createPrivateVaultRotationEvidenceStore;
  RotationEvidenceError = evidence.PrivateVaultRotationEvidenceError;
  await (await import("../plugins/db.js")).default(undefined as never);
}, 60_000);

afterAll(() => {
  for (const suffix of ["", "-shm", "-wal"])
    rmSync(`${TEST_DB_PATH}${suffix}`, { force: true });
});

const bytes = (value: string) => Uint8Array.from(Buffer.from(value));
const ceremony = (value: number) => value.toString(16).padStart(32, "0");
const recipient = (value: number) =>
  (value + 1_000).toString(16).padStart(32, "0");
const blobBytes = new Map<string, Uint8Array>();
let blobSequence = 0;
let failBlobDelete = false;
const blobs = {
  async put(input: { data: Uint8Array | Buffer }) {
    const id = `blob:${++blobSequence}`;
    blobBytes.set(id, Uint8Array.from(input.data));
    return { id, provider: "test", opaque: true as const, encrypted: true };
  },
  async read(handle: { id: string; provider: string; opaque: true }) {
    const data = blobBytes.get(handle.id);
    if (!data) throw new Error();
    return { data: data.slice(), handle: { ...handle, encrypted: true } };
  },
  async delete(handle: { id: string; provider: string; opaque: true }) {
    if (failBlobDelete) throw new Error("injected blob delete interruption");
    return { deleted: blobBytes.delete(handle.id), provider: "test" };
  },
};

function bundleInput(suffix = "exact") {
  const signedEntry = bytes(`signed-entry:${suffix}`);
  const recoveryWrap = bytes(`recovery-wrap:${suffix}`);
  const encoded = encodeAncV1ControlLogRotationAppendRequest({
    version: 1,
    suite: "anc/v1",
    type: "control-log-rotation-append-request",
    signedEntry,
    recoveryWrap,
  });
  return {
    signedEntry,
    recoveryWrap,
    bundleSha256: createHash("sha256").update(encoded).digest("hex"),
  };
}

async function putBundle(
  store: ReturnType<typeof createStore>,
  scope: Awaited<ReturnType<typeof seed>>,
  ceremonyId: string,
  suffix = "exact",
) {
  return store.putControlBundle(scope, {
    ceremonyId,
    ...bundleInput(suffix),
  });
}

async function seed(suffix: string) {
  const scope = {
    ownerEmail: `${suffix}@example.test`,
    accountId: `account:${suffix}`,
    orgId: `org:${suffix}`,
    workspaceId: `workspace:${suffix}`,
    vaultId: `vault:${suffix}`,
  };
  await getDb()
    .insert(schema.contentEncryptedVaults)
    .values({
      ...scope,
      vaultState: "active",
      serverReceivedAt: START.toISOString(),
    });
  return scope;
}

async function complete(
  store: ReturnType<typeof createStore>,
  scope: Awaited<ReturnType<typeof seed>>,
  ceremonyId: string,
) {
  await store.establish(scope, {
    ceremonyId,
    expectedRecipientCount: 2,
    checkpoint: bytes(`checkpoint:${ceremonyId}`),
  });
  for (const value of [1, 2])
    await store.putRecipientOffer(scope, {
      ceremonyId,
      recipientEndpointId: recipient(value),
      offer: bytes(`offer:${value}`),
      eekWrap: bytes(`eek-wrap:${value}`),
    });
  await putBundle(store, scope, ceremonyId);
  for (const value of [1, 2])
    await store.putRecipientAcknowledgement(scope, {
      ceremonyId,
      recipientEndpointId: recipient(value),
      acknowledgement: bytes(`ack:${value}`),
    });
  for (const value of [1, 2])
    await store.putDestructionAttestation(scope, {
      ceremonyId,
      recipientEndpointId: recipient(value),
      destructionAttestation: bytes(`destruction:${value}`),
    });
  await store.putHostedReceipt(scope, {
    ceremonyId,
    hostedReceipt: bytes("hosted-receipt"),
  });
  return store.putCompletionAttestation(scope, {
    ceremonyId,
    completionAttestation: bytes("completion-attestation"),
  });
}

describe("Private Vault opaque rotation evidence store", () => {
  it("persists one exact bounded ceremony through the ordered public evidence phases", async () => {
    const scope = await seed("flow");
    const store = createStore({ now: () => clock, blobs });
    const ceremonyId = ceremony(1);
    let status = await store.establish(scope, {
      ceremonyId,
      expectedRecipientCount: 2,
      checkpoint: bytes("checkpoint"),
    });
    expect(status).toMatchObject({
      phase: "collecting_offers",
      expectedRecipientCount: 2,
      recipients: [],
    });
    await store.putRecipientOffer(scope, {
      ceremonyId,
      recipientEndpointId: recipient(2),
      offer: bytes("offer:2"),
      eekWrap: bytes("wrap:2"),
    });
    status = await store.putRecipientOffer(scope, {
      ceremonyId,
      recipientEndpointId: recipient(1),
      offer: bytes("offer:1"),
      eekWrap: bytes("wrap:1"),
    });
    expect(status.phase).toBe("awaiting_acknowledgements");
    status = await putBundle(store, scope, ceremonyId);
    expect(status.controlBundle).toMatchObject({
      recoveryWrapByteLength: bytes("recovery-wrap:exact").byteLength,
      bundleSha256: bundleInput().bundleSha256,
    });
    expect(status.recipients.map((value) => value.recipientEndpointId)).toEqual(
      [recipient(1), recipient(2)],
    );
    await store.putRecipientAcknowledgement(scope, {
      ceremonyId,
      recipientEndpointId: recipient(1),
      acknowledgement: bytes("ack:1"),
    });
    status = await store.putRecipientAcknowledgement(scope, {
      ceremonyId,
      recipientEndpointId: recipient(2),
      acknowledgement: bytes("ack:2"),
    });
    expect(status.phase).toBe("awaiting_destructions");
    await store.putDestructionAttestation(scope, {
      ceremonyId,
      recipientEndpointId: recipient(2),
      destructionAttestation: bytes("destroy:2"),
    });
    status = await store.putDestructionAttestation(scope, {
      ceremonyId,
      recipientEndpointId: recipient(1),
      destructionAttestation: bytes("destroy:1"),
    });
    expect(status.phase).toBe("awaiting_hosted_receipt");
    status = await store.putHostedReceipt(scope, {
      ceremonyId,
      hostedReceipt: bytes("receipt"),
    });
    expect(status.phase).toBe("awaiting_completion");
    status = await store.putCompletionAttestation(scope, {
      ceremonyId,
      completionAttestation: bytes("completion"),
    });
    expect(status).toMatchObject({
      phase: "completed",
      terminalAt: START.toISOString(),
      purgeEligibleAt: new Date(START.getTime() + 90 * DAY).toISOString(),
    });
    expect(await store.read(scope, ceremonyId)).toEqual(status);

    const rows = await getDb()
      .select()
      .from(schema.contentEncryptedVaultRotationEvidenceArtifacts)
      .where(
        and(
          eq(
            schema.contentEncryptedVaultRotationEvidenceArtifacts.vaultId,
            scope.vaultId,
          ),
          eq(
            schema.contentEncryptedVaultRotationEvidenceArtifacts.ceremonyId,
            ceremonyId,
          ),
        ),
      );
    expect(rows).toHaveLength(11);
    const bundleRow = rows.find(
      (row) => row.artifactKind === "control_bundle",
    )!;
    expect(bundleRow.evidenceBytesBase64url).toBeNull();
    expect(bundleRow.eekWrapBytesBase64url).toBeNull();
    expect(bundleRow.privateBlobHandleJson).not.toContain(
      "recovery-wrap:exact",
    );
    expect(
      Object.keys(rows[0]!).some((key) =>
        /plaintext|private.*key|epoch.*key/i.test(key),
      ),
    ).toBe(false);
  });

  it("makes exact retries idempotent while rejecting substitutions, duplicates, and phase skips", async () => {
    const scope = await seed("hostile");
    const store = createStore({ now: () => clock, blobs });
    const ceremonyId = ceremony(2);
    const established = await store.establish(scope, {
      ceremonyId,
      expectedRecipientCount: 1,
      checkpoint: bytes("checkpoint:exact"),
    });
    await expect(
      store.establish(scope, {
        ceremonyId,
        expectedRecipientCount: 1,
        checkpoint: bytes("checkpoint:exact"),
      }),
    ).resolves.toEqual(established);
    await expect(
      store.establish(scope, {
        ceremonyId,
        expectedRecipientCount: 1,
        checkpoint: bytes("checkpoint:substitution"),
      }),
    ).rejects.toBeInstanceOf(RotationEvidenceError);
    await expect(
      store.putRecipientAcknowledgement(scope, {
        ceremonyId,
        recipientEndpointId: recipient(1),
        acknowledgement: bytes("ack:early"),
      }),
    ).rejects.toMatchObject({ code: "conflict" });

    const offerInput = {
      ceremonyId,
      recipientEndpointId: recipient(1),
      offer: bytes("offer:exact"),
      eekWrap: bytes("wrap:exact"),
    };
    const offered = await store.putRecipientOffer(scope, offerInput);
    await expect(store.putRecipientOffer(scope, offerInput)).resolves.toEqual(
      offered,
    );
    await expect(
      store.putRecipientOffer(scope, {
        ...offerInput,
        offer: bytes("offer:substitution"),
      }),
    ).rejects.toMatchObject({ code: "conflict" });
    const bundled = await putBundle(store, scope, ceremonyId);
    await expect(putBundle(store, scope, ceremonyId)).resolves.toEqual(bundled);
    await expect(
      store.assertAuthoritativeControlBundle({
        ownerEmail: scope.ownerEmail,
        orgId: scope.orgId,
        vaultId: scope.vaultId,
        signedEntry: bytes("signed-entry:exact"),
        recoveryWrap: bytes("recovery-wrap:exact"),
        bundleSha256: bundleInput().bundleSha256,
      }),
    ).resolves.toBe(true);
    await expect(
      store.assertAuthoritativeControlBundle({
        ownerEmail: scope.ownerEmail,
        orgId: scope.orgId,
        vaultId: scope.vaultId,
        signedEntry: bytes("different-signed-entry"),
        recoveryWrap: bytes("recovery-wrap:exact"),
        bundleSha256: bundleInput().bundleSha256,
      }),
    ).rejects.toMatchObject({ code: "conflict" });
    await expect(
      putBundle(store, scope, ceremonyId, "substitution"),
    ).rejects.toMatchObject({ code: "conflict" });
    await expect(
      store.putDestructionAttestation(scope, {
        ceremonyId,
        recipientEndpointId: recipient(1),
        destructionAttestation: bytes("destroy:early"),
      }),
    ).rejects.toMatchObject({ code: "conflict" });
    await expect(
      store.putHostedReceipt(scope, {
        ceremonyId,
        hostedReceipt: bytes("receipt:early"),
      }),
    ).rejects.toMatchObject({ code: "conflict" });
  });

  it("enforces stable scope, recipient limits, and artifact bounds", async () => {
    const scope = await seed("scope");
    const store = createStore({ now: () => clock, blobs });
    const ceremonyId = ceremony(3);
    await store.establish(scope, {
      ceremonyId,
      expectedRecipientCount: 1,
      checkpoint: bytes("checkpoint"),
    });
    const foreignScope = { ...scope, accountId: "account:foreign" };
    await expect(store.read(foreignScope, ceremonyId)).rejects.toMatchObject({
      code: "not_found",
    });
    await expect(
      store.putRecipientOffer(foreignScope, {
        ceremonyId,
        recipientEndpointId: recipient(1),
        offer: bytes("offer"),
        eekWrap: bytes("wrap"),
      }),
    ).rejects.toMatchObject({ code: "not_found" });
    await expect(
      store.establish(scope, {
        ceremonyId: ceremony(4),
        expectedRecipientCount: 65,
        checkpoint: bytes("checkpoint"),
      }),
    ).rejects.toMatchObject({ code: "invalid_request" });
    await expect(
      store.establish(scope, {
        ceremonyId: ceremony(5),
        expectedRecipientCount: 1,
        checkpoint: new Uint8Array(1_025),
      }),
    ).rejects.toMatchObject({ code: "invalid_request" });
    await expect(
      store.putRecipientOffer(scope, {
        ceremonyId,
        recipientEndpointId: recipient(1),
        offer: bytes("offer"),
        eekWrap: new Uint8Array(2_049),
      }),
    ).rejects.toMatchObject({ code: "invalid_request" });
  });

  it("fails closed without protected blob storage and detects stored wrap tampering", async () => {
    const scope = await seed("blob-fail-closed");
    const ceremonyId = ceremony(30);
    const unavailable = createStore({
      now: () => clock,
      blobs: {
        put: async () => null,
        read: blobs.read as never,
        delete: blobs.delete as never,
      },
    });
    await expect(
      unavailable.assertAuthoritativeControlBundle({
        ownerEmail: scope.ownerEmail,
        orgId: scope.orgId,
        vaultId: scope.vaultId,
        ...bundleInput(),
      }),
    ).rejects.toMatchObject({ code: "conflict" });
    await unavailable.establish(scope, {
      ceremonyId,
      expectedRecipientCount: 1,
      checkpoint: bytes("checkpoint"),
    });
    await unavailable.putRecipientOffer(scope, {
      ceremonyId,
      recipientEndpointId: recipient(1),
      offer: bytes("offer"),
      eekWrap: bytes("eek-wrap"),
    });
    await expect(
      putBundle(unavailable, scope, ceremonyId),
    ).rejects.toMatchObject({ code: "unavailable" });

    const store = createStore({ now: () => clock, blobs });
    await putBundle(store, scope, ceremonyId);
    const row = (
      await getDb()
        .select()
        .from(schema.contentEncryptedVaultRotationEvidenceArtifacts)
        .where(
          eq(
            schema.contentEncryptedVaultRotationEvidenceArtifacts.artifactKind,
            "control_bundle",
          ),
        )
    ).find((candidate) => candidate.ceremonyId === ceremonyId)!;
    const handle = JSON.parse(row.privateBlobHandleJson!) as { id: string };
    blobBytes.set(handle.id, bytes("tampered-wrap"));
    await expect(
      store.readControlBundle(scope, ceremonyId),
    ).rejects.toMatchObject({ code: "unavailable" });
  });

  it("fails closed on unknown or unsupported persisted artifact formats", async () => {
    const scope = await seed("corrupt");
    const store = createStore({ now: () => clock, blobs });
    const ceremonyId = ceremony(8);
    await store.establish(scope, {
      ceremonyId,
      expectedRecipientCount: 1,
      checkpoint: bytes("checkpoint"),
    });
    const table = schema.contentEncryptedVaultRotationEvidenceArtifacts;
    await getDb()
      .update(table)
      .set({ artifactKind: "future_artifact" })
      .where(
        and(
          eq(table.vaultId, scope.vaultId),
          eq(table.ceremonyId, ceremonyId),
          eq(table.artifactKind, "checkpoint"),
        ),
      );
    await expect(store.read(scope, ceremonyId)).rejects.toMatchObject({
      code: "unavailable",
    });

    await getDb()
      .update(table)
      .set({ artifactKind: "checkpoint", formatVersion: 2 })
      .where(
        and(
          eq(table.vaultId, scope.vaultId),
          eq(table.ceremonyId, ceremonyId),
          eq(table.artifactKind, "future_artifact"),
        ),
      );
    await expect(store.read(scope, ceremonyId)).rejects.toMatchObject({
      code: "unavailable",
    });
  });

  it("never purges active ceremonies and retains terminal evidence for 90 days", async () => {
    const scope = await seed("retention");
    const store = createStore({ now: () => clock, blobs });
    const activeCeremony = ceremony(6);
    const completedCeremony = ceremony(7);
    await store.establish(scope, {
      ceremonyId: activeCeremony,
      expectedRecipientCount: 1,
      checkpoint: bytes("checkpoint:active"),
    });
    await complete(store, scope, completedCeremony);

    expect(
      await store.purgeEligibleTerminalEvidence(scope, {
        at: new Date(START.getTime() + 89 * DAY),
      }),
    ).toEqual({ ceremoniesDeleted: 0, artifactsDeleted: 0 });
    await expect(store.read(scope, completedCeremony)).resolves.toBeDefined();

    failBlobDelete = true;
    const purged = await store.purgeEligibleTerminalEvidence(scope, {
      at: new Date(START.getTime() + 90 * DAY),
    });
    failBlobDelete = false;
    expect(purged).toEqual({ ceremoniesDeleted: 1, artifactsDeleted: 11 });
    await expect(store.read(scope, completedCeremony)).rejects.toMatchObject({
      code: "not_found",
    });
    await expect(store.read(scope, activeCeremony)).resolves.toMatchObject({
      phase: "collecting_offers",
    });

    clock = new Date(START.getTime() + 365 * DAY);
    expect(await store.purgeEligibleTerminalEvidence(scope)).toEqual({
      ceremoniesDeleted: 0,
      artifactsDeleted: 0,
    });
    await expect(store.read(scope, activeCeremony)).resolves.toBeDefined();
  });
});
import { encodeAncV1ControlLogRotationAppendRequest } from "@agent-native/core/e2ee";
