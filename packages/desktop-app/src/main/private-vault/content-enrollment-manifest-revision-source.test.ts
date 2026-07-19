import { describe, expect, it, vi } from "vitest";

import {
  PrivateVaultContentEnrollmentManifestRevisionSource,
  PrivateVaultContentEnrollmentManifestRevisionSourceError,
} from "./content-enrollment-manifest-revision-source.js";

const vaultId = "11".repeat(16);
const objectId = "22".repeat(16);
const revisionId = "33".repeat(32);
const ciphertext = Uint8Array.of(1, 2, 3);

function metadata(input?: { objectType?: "document" | "vault-manifest" }) {
  return {
    vaultId,
    objectId,
    revisionId,
    revision: 1,
    objectType: input?.objectType ?? ("vault-manifest" as const),
    algorithmId: "anc/v1" as const,
    epoch: 1,
    parentRevisionIds: [] as string[],
    ciphertextByteLength: ciphertext.byteLength,
  };
}

function source(input?: { verify?: "accept" | "reject" }) {
  const index = {
    initialize: vi.fn(async () => undefined),
    readManifest: vi.fn(async () => ({
      version: 1 as const,
      objectId,
      revisionId,
      manifest: { vaultId, previousManifest: null },
    })),
  };
  const transport = {
    list: vi.fn(async () => [
      {
        objectId,
        objectType: "vault-manifest" as const,
        latestRevision: metadata(),
      },
    ]),
    get: vi.fn(async () => ({
      ciphertext: ciphertext.slice(),
      metadata: metadata(),
    })),
  };
  const native = {
    verifyBrokerEnrollmentManifest:
      input?.verify === "reject"
        ? vi.fn(async () => {
            throw new Error();
          })
        : vi.fn(async () => ({
            version: 1 as const,
            suite: "anc/v1" as const,
            operation: "verify_manifest" as const,
            state: "verified" as const,
            vaultId,
            checkpointDigest: new Uint8Array(32).fill(4),
          })),
  };
  return {
    index,
    transport,
    native,
    value: new PrivateVaultContentEnrollmentManifestRevisionSource({
      index: index as never,
      transport: transport as never,
      native: native as never,
    }),
  };
}

describe("PrivateVaultContentEnrollmentManifestRevisionSource", () => {
  it("reads the exact local manifest coordinate and returns only opaque bytes", async () => {
    const fixture = source();
    await expect(
      fixture.value.readTrustedCurrentRevision(vaultId),
    ).resolves.toEqual(ciphertext);
    expect(fixture.index.initialize).toHaveBeenCalledOnce();
    expect(fixture.transport.get).toHaveBeenCalledWith({
      vaultId,
      objectId,
      revisionId,
    });
  });

  it("fails closed on a missing or stale local manifest head", async () => {
    const missing = source();
    missing.index.readManifest.mockResolvedValueOnce(null as never);
    await expect(
      missing.value.readTrustedCurrentRevision(vaultId),
    ).rejects.toBeInstanceOf(
      PrivateVaultContentEnrollmentManifestRevisionSourceError,
    );
    expect(missing.transport.get).not.toHaveBeenCalled();

    const stale = source();
    const staleCiphertext = Uint8Array.of(9, 9, 9);
    stale.transport.get.mockResolvedValueOnce({
      ciphertext: staleCiphertext,
      metadata: { ...metadata(), parentRevisionIds: ["66".repeat(32)] },
    });
    await expect(
      stale.value.readTrustedCurrentRevision(vaultId),
    ).rejects.toBeInstanceOf(
      PrivateVaultContentEnrollmentManifestRevisionSourceError,
    );
    expect(staleCiphertext).toEqual(new Uint8Array(3));
  });

  it("accepts exactly one hosted candidate verified by native custody", async () => {
    const fixture = source();
    await expect(
      fixture.value.verifyUniqueHostedRevision({
        vaultId,
        challenge: Uint8Array.of(5),
        authorization: Uint8Array.of(6),
        manifestCheckpoint: Uint8Array.of(7),
        manifestAuthorization: Uint8Array.of(8),
      }),
    ).resolves.toMatchObject({ state: "verified", vaultId });
    expect(fixture.native.verifyBrokerEnrollmentManifest).toHaveBeenCalledWith({
      vaultId,
      challenge: Uint8Array.of(5),
      authorization: Uint8Array.of(6),
      manifestCheckpoint: Uint8Array.of(7),
      manifestAuthorization: Uint8Array.of(8),
      manifestRevision: ciphertext,
    });
  });

  it("fails closed when no candidate verifies or two candidates verify", async () => {
    const rejected = source({ verify: "reject" });
    const input = {
      vaultId,
      challenge: Uint8Array.of(5),
      authorization: Uint8Array.of(6),
      manifestCheckpoint: Uint8Array.of(7),
      manifestAuthorization: Uint8Array.of(8),
    };
    await expect(
      rejected.value.verifyUniqueHostedRevision(input),
    ).rejects.toBeInstanceOf(
      PrivateVaultContentEnrollmentManifestRevisionSourceError,
    );

    const duplicated = source();
    duplicated.transport.list.mockResolvedValue([
      { objectId, objectType: "vault-manifest", latestRevision: metadata() },
      {
        objectId: "44".repeat(16),
        objectType: "vault-manifest",
        latestRevision: {
          ...metadata(),
          objectId: "44".repeat(16),
          revisionId: "55".repeat(32),
        },
      },
    ]);
    await expect(
      duplicated.value.verifyUniqueHostedRevision(input),
    ).rejects.toBeInstanceOf(
      PrivateVaultContentEnrollmentManifestRevisionSourceError,
    );
  });

  it("rejects substituted hosted metadata before native verification", async () => {
    const fixture = source();
    fixture.transport.get.mockResolvedValueOnce({
      ciphertext: ciphertext.slice(),
      metadata: { ...metadata(), epoch: 2 },
    });
    await expect(
      fixture.value.verifyUniqueHostedRevision({
        vaultId,
        challenge: Uint8Array.of(5),
        authorization: Uint8Array.of(6),
        manifestCheckpoint: Uint8Array.of(7),
        manifestAuthorization: Uint8Array.of(8),
      }),
    ).rejects.toBeInstanceOf(
      PrivateVaultContentEnrollmentManifestRevisionSourceError,
    );
    expect(
      fixture.native.verifyBrokerEnrollmentManifest,
    ).not.toHaveBeenCalled();
  });
});
