import { createHash } from "node:crypto";

import { describe, expect, it, vi } from "vitest";

import { PrivateVaultContentObjectRuntime } from "./content-object-runtime.js";

const vaultId = "10".repeat(16);
const objectId = "20".repeat(16);
const revisionId = "30".repeat(32);

function transport() {
  return {
    put: vi.fn(async (input) => ({
      ...input.coordinate,
      objectType: "document" as const,
      algorithmId: "anc/v1" as const,
      revision: input.revision,
      epoch: input.epoch,
      parentRevisionIds: input.parentRevisionIds ?? [],
      ciphertextByteLength: input.ciphertext.byteLength,
    })),
    get: vi.fn(async () => ({
      ciphertext: Uint8Array.of(0xa4, 1, 2, 3),
      metadata: {
        objectType: "document" as const,
        algorithmId: "anc/v1" as const,
        revision: 3,
        epoch: 7,
        parentRevisionIds: [],
        ciphertextByteLength: 4,
      },
    })),
  };
}

describe("Private Vault Content object runtime", () => {
  it("binds a vault manifest MIME type to its distinct hosted object type", async () => {
    const encodedRevision = Uint8Array.of(0xa4, 1, 2, 3);
    const ciphertextHash = createHash("sha256")
      .update(encodedRevision)
      .digest("hex");
    const native = {
      sealContentObjectRevision: vi.fn(async (input) => ({
        version: 1 as const,
        suite: "anc/v1" as const,
        operation: "seal_object" as const,
        state: "sealed" as const,
        vaultId,
        objectId,
        revision: input.revision,
        epoch: 7,
        revisionId: Buffer.from(revisionId, "hex"),
        contentType: input.contentType!,
        plaintextLength: input.plaintext.byteLength,
        encodedRevision,
      })),
      openContentObjectRevision: vi.fn(),
      rewrapContentObjectRevision: vi.fn(),
      sealRotationManifest: vi.fn(),
    };
    const hosted = transport();
    const runtime = new PrivateVaultContentObjectRuntime(native);

    const uploaded = await runtime.sealAndUpload({
      transport: hosted as never,
      vaultId,
      objectId,
      revision: 1,
      contentType: "application/vnd.agent-native.content-vault-manifest+json",
      plaintext: Uint8Array.from(Buffer.from('{"kind":"manifest"}')),
      parentRevisionIds: [],
    });
    expect(uploaded.ciphertextHash).toBe(ciphertextHash);

    expect(hosted.put).toHaveBeenCalledWith(
      expect.objectContaining({ objectType: "vault-manifest", revision: 1 }),
    );
    expect(encodedRevision).toEqual(new Uint8Array(4));
  });

  it("seals before upload and returns content-free coordinates", async () => {
    const encodedRevision = Uint8Array.of(0xa4, 1, 2, 3);
    const native = {
      sealContentObjectRevision: vi.fn(async () => ({
        version: 1 as const,
        suite: "anc/v1" as const,
        operation: "seal_object" as const,
        state: "sealed" as const,
        vaultId,
        objectId,
        revision: 3,
        epoch: 7,
        revisionId: Buffer.from(revisionId, "hex"),
        contentType:
          "application/vnd.agent-native.content-document+json" as const,
        plaintextLength: 16,
        encodedRevision,
      })),
      openContentObjectRevision: vi.fn(),
      rewrapContentObjectRevision: vi.fn(),
      sealRotationManifest: vi.fn(),
    };
    const hosted = transport();
    let uploaded = new Uint8Array();
    hosted.put.mockImplementationOnce(async (input) => {
      uploaded = input.ciphertext.slice();
      return {
        ...input.coordinate,
        objectType: "document" as const,
        algorithmId: "anc/v1" as const,
        revision: input.revision,
        epoch: input.epoch,
        parentRevisionIds: input.parentRevisionIds ?? [],
        ciphertextByteLength: input.ciphertext.byteLength,
      };
    });
    const runtime = new PrivateVaultContentObjectRuntime(native);
    await expect(
      runtime.sealAndUpload({
        transport: hosted as never,
        vaultId,
        objectId,
        revision: 3,
        plaintext: Uint8Array.from(Buffer.from('{"title":"Moon"}')),
      }),
    ).resolves.toEqual({
      revisionId,
      ciphertextHash: createHash("sha256")
        .update(Uint8Array.of(0xa4, 1, 2, 3))
        .digest("hex"),
      epoch: 7,
      plaintextLength: 16,
      ciphertextByteLength: 4,
    });
    expect(hosted.put).toHaveBeenCalledWith(
      expect.objectContaining({
        coordinate: { vaultId, objectId, revisionId },
        objectType: "document",
        revision: 3,
        epoch: 7,
        ciphertext: Uint8Array.from([0, 0, 0, 0]),
      }),
    );
    expect(uploaded).toEqual(Uint8Array.of(0xa4, 1, 2, 3));
    expect(encodedRevision).toEqual(new Uint8Array(4));
  });

  it("opens only after hosted and native metadata agree", async () => {
    const expectedPlaintext = Uint8Array.from(Buffer.from('{"title":"Moon"}'));
    const openedBytes = expectedPlaintext.slice();
    const opened = {
      version: 1 as const,
      suite: "anc/v1" as const,
      operation: "open_object" as const,
      state: "opened" as const,
      vaultId,
      objectId,
      revision: 3,
      epoch: 7,
      revisionId: Buffer.from(revisionId, "hex"),
      contentType:
        "application/vnd.agent-native.content-document+json" as const,
      plaintextLength: openedBytes.byteLength,
      writerEndpointId: Buffer.alloc(16, 4),
      plaintext: openedBytes,
    };
    const native = {
      sealContentObjectRevision: vi.fn(),
      openContentObjectRevision: vi.fn(async () => opened),
      rewrapContentObjectRevision: vi.fn(),
      sealRotationManifest: vi.fn(),
    };
    const hosted = transport();
    const runtime = new PrivateVaultContentObjectRuntime(native);
    await expect(
      runtime.downloadAndOpen({
        transport: hosted as never,
        vaultId,
        objectId,
        revisionId,
      }),
    ).resolves.toMatchObject({
      plaintext: expectedPlaintext,
      epoch: 7,
      writerEndpointId: "04".repeat(16),
    });
    expect(openedBytes).toEqual(new Uint8Array(openedBytes.byteLength));

    const rejectedBytes = expectedPlaintext.slice();
    native.openContentObjectRevision.mockResolvedValueOnce({
      ...opened,
      epoch: 8,
      plaintext: rejectedBytes,
    });
    await expect(
      runtime.downloadAndOpen({
        transport: hosted as never,
        vaultId,
        objectId,
        revisionId,
      }),
    ).rejects.toThrow("object binding failed");
    expect(rejectedBytes).toEqual(new Uint8Array(rejectedBytes.byteLength));
  });

  it("returns one rewrapped encrypted revision only after metadata binding", async () => {
    const encodedRevision = Uint8Array.of(0xa4, 4, 5, 6);
    const native = {
      sealContentObjectRevision: vi.fn(),
      openContentObjectRevision: vi.fn(),
      rewrapContentObjectRevision: vi.fn(async () => ({
        version: 1 as const,
        suite: "anc/v1" as const,
        operation: "rewrap_revision" as const,
        state: "rewrapped" as const,
        vaultId,
        objectId,
        revision: 3,
        epoch: 8,
        revisionId: Buffer.from(revisionId, "hex"),
        contentType:
          "application/vnd.agent-native.content-document+json" as const,
        plaintextLength: 16,
        encodedRevision,
      })),
      sealRotationManifest: vi.fn(),
    };
    const runtime = new PrivateVaultContentObjectRuntime(native);
    const source = Uint8Array.of(0xa4, 1, 2, 3);

    const result = await runtime.rewrapRevisionForPreparedRotation({
      vaultId,
      objectId,
      revision: 3,
      epoch: 7,
      objectType: "document",
      encodedRevision: source,
    });
    expect(native.rewrapContentObjectRevision).toHaveBeenCalledWith({
      vaultId,
      objectId,
      encodedRevision: source,
    });
    expect(result).toEqual({
      revisionId,
      revision: 3,
      epoch: 8,
      objectType: "document",
      plaintextLength: 16,
      ciphertext: Uint8Array.of(0xa4, 4, 5, 6),
      ciphertextHash: createHash("sha256")
        .update(Uint8Array.of(0xa4, 4, 5, 6))
        .digest("hex"),
      ciphertextByteLength: 4,
    });
    expect(encodedRevision).toEqual(new Uint8Array(4));
  });

  it("fails closed when native rewrap metadata does not match the source", async () => {
    const base = {
      version: 1 as const,
      suite: "anc/v1" as const,
      operation: "rewrap_revision" as const,
      state: "rewrapped" as const,
      vaultId,
      objectId,
      revision: 3,
      epoch: 8,
      revisionId: Buffer.from(revisionId, "hex"),
      contentType:
        "application/vnd.agent-native.content-document+json" as const,
      plaintextLength: 16,
    };
    for (const mutation of [
      { revision: 4 },
      { epoch: 7 },
      {
        contentType:
          "application/vnd.agent-native.content-vault-manifest+json" as const,
      },
    ]) {
      const encodedRevision = Uint8Array.of(0xa4, 4, 5, 6);
      const runtime = new PrivateVaultContentObjectRuntime({
        sealContentObjectRevision: vi.fn(),
        openContentObjectRevision: vi.fn(),
        rewrapContentObjectRevision: vi.fn(async () => ({
          ...base,
          ...mutation,
          encodedRevision,
        })),
        sealRotationManifest: vi.fn(),
      });
      await expect(
        runtime.rewrapRevisionForPreparedRotation({
          vaultId,
          objectId,
          revision: 3,
          epoch: 7,
          objectType: "document",
          encodedRevision: Uint8Array.of(0xa4, 1, 2, 3),
        }),
      ).rejects.toThrow("object rewrap binding failed");
      expect(encodedRevision).toEqual(new Uint8Array(4));
    }

    const native = {
      sealContentObjectRevision: vi.fn(),
      openContentObjectRevision: vi.fn(),
      rewrapContentObjectRevision: vi.fn(),
      sealRotationManifest: vi.fn(),
    };
    const runtime = new PrivateVaultContentObjectRuntime(native);
    await expect(
      runtime.rewrapRevisionForPreparedRotation({
        vaultId,
        objectId,
        revision: 3,
        epoch: 0,
        objectType: "document",
        encodedRevision: Uint8Array.of(1),
      }),
    ).rejects.toThrow("object rewrap binding failed");
    expect(native.rewrapContentObjectRevision).not.toHaveBeenCalled();
  });

  it("normalizes a prepared rotation manifest without retaining native bytes", async () => {
    const encodedRevision = Uint8Array.of(0xa4, 7, 8, 9);
    const plaintext = Uint8Array.from(Buffer.from('{"version":1}'));
    const targetEndpointId = "ff".repeat(16);
    const native = {
      sealContentObjectRevision: vi.fn(),
      openContentObjectRevision: vi.fn(),
      rewrapContentObjectRevision: vi.fn(),
      sealRotationManifest: vi.fn(async () => ({
        version: 1 as const,
        suite: "anc/v1" as const,
        operation: "seal_rot_mfst" as const,
        state: "sealed" as const,
        vaultId,
        objectId,
        revision: 4,
        epoch: 8,
        revisionId: Buffer.from(revisionId, "hex"),
        contentType:
          "application/vnd.agent-native.content-vault-manifest+json" as const,
        plaintextLength: plaintext.byteLength,
        encodedRevision,
      })),
    };
    const runtime = new PrivateVaultContentObjectRuntime(native);
    const result = await runtime.sealManifestForPreparedRotation({
      vaultId,
      targetEndpointId,
      objectId,
      revision: 4,
      plaintext,
    });
    expect(native.sealRotationManifest).toHaveBeenCalledWith({
      vaultId,
      targetEndpointId,
      objectId,
      revision: 4,
      plaintext,
    });
    expect(result).toEqual({
      revisionId,
      revision: 4,
      epoch: 8,
      objectType: "vault-manifest",
      plaintextLength: plaintext.byteLength,
      ciphertext: Uint8Array.of(0xa4, 7, 8, 9),
      ciphertextHash: createHash("sha256")
        .update(Uint8Array.of(0xa4, 7, 8, 9))
        .digest("hex"),
      ciphertextByteLength: 4,
    });
    expect(encodedRevision).toEqual(new Uint8Array(4));
  });
});
