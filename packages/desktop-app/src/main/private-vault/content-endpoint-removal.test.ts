import { describe, expect, it, vi } from "vitest";

import type { PrivateVaultLocalManifestHead } from "./content-document-codec";
import {
  PrivateVaultContentEndpointRemovalPreparer,
  PrivateVaultEndpointRemovalError,
} from "./content-endpoint-removal";

const vaultId = "00".repeat(16);
const targetEndpointId = "11".repeat(16);
const manifestObjectId = "22".repeat(16);
const documentObjectId = "33".repeat(16);
const baseManifestRevisionId = "44".repeat(32);
const oldRevisionOne = "55".repeat(32);
const oldRevisionTwo = "66".repeat(32);
const newRevisionOne = "77".repeat(32);
const newRevisionTwo = "88".repeat(32);
const newManifestRevisionId = "99".repeat(32);

function head(): PrivateVaultLocalManifestHead {
  return {
    version: 1,
    objectId: manifestObjectId,
    revisionId: baseManifestRevisionId,
    manifest: {
      version: 1,
      kind: "content-vault-manifest",
      vaultId,
      generation: 2,
      previousManifest: {
        objectId: manifestObjectId,
        revisionId: "aa".repeat(32),
      },
      documents: [
        {
          objectId: documentObjectId,
          parentId: null,
          position: 0,
          revisions: [
            {
              revision: 1,
              revisionId: oldRevisionOne,
              parentRevisionIds: [],
            },
            {
              revision: 2,
              revisionId: oldRevisionTwo,
              parentRevisionIds: [oldRevisionOne],
            },
          ],
        },
      ],
      committedAt: "2024-07-18T10:00:00.000Z",
    },
  };
}

function downloaded(
  objectType: "document" | "vault-manifest",
  revision: number,
  parentRevisionIds: readonly string[],
) {
  return {
    ciphertext: Uint8Array.of(1, 2, 3),
    metadata: {
      objectType,
      algorithmId: "anc/v1" as const,
      revision,
      epoch: 7,
      parentRevisionIds,
      ciphertextByteLength: 3,
    },
  };
}

describe("Private Vault endpoint removal preparation", () => {
  it("rewraps the complete retained revision set and commits one target manifest", async () => {
    const baseHead = head();
    const index = {
      readManifest: vi.fn(async () => structuredClone(baseHead)),
    };
    const downloads = [
      downloaded("vault-manifest", 3, ["aa".repeat(32)]),
      downloaded("document", 1, []),
      downloaded("document", 2, [oldRevisionOne]),
    ];
    const transport = {
      get: vi.fn(async () => downloads.shift()!),
      put: vi.fn(async (input: any) => ({
        ...input.coordinate,
        objectType: input.objectType,
        algorithmId: "anc/v1" as const,
        revision: input.revision,
        epoch: input.epoch,
        parentRevisionIds: input.parentRevisionIds,
        ciphertextByteLength: input.ciphertext.byteLength,
      })),
    };
    const rewraps = [newRevisionOne, newRevisionTwo];
    const objects = {
      rewrapRevisionForPreparedRotation: vi.fn(async (input: any) => ({
        revisionId: rewraps.shift()!,
        revision: input.revision,
        epoch: 8,
        objectType: "document" as const,
        plaintextLength: 20,
        ciphertext: Uint8Array.of(4, 5, 6),
        ciphertextHash: "ab".repeat(32),
        ciphertextByteLength: 3,
      })),
      sealManifestForPreparedRotation: vi.fn(async (input: any) => ({
        revisionId: newManifestRevisionId,
        revision: input.revision,
        epoch: 8,
        objectType: "vault-manifest" as const,
        plaintextLength: input.plaintext.byteLength,
        ciphertext: Uint8Array.of(7, 8, 9),
        ciphertextHash: "cd".repeat(32),
        ciphertextByteLength: 3,
      })),
    };
    const native = {
      removeVaultEndpoint: vi.fn(async () => ({
        version: 1 as const,
        suite: "anc/v1" as const,
        operation: "remove_endpoint" as const,
        state: "pending" as const,
        vaultId,
        targetEndpointId,
        createdAt: 1_721_296_802,
      })),
    };
    const preparer = new PrivateVaultContentEndpointRemovalPreparer({
      native,
      index,
      transport,
      objects,
    });

    const result = await preparer.prepare(vaultId, targetEndpointId);
    expect(result).toMatchObject({
      vaultId,
      targetEndpointId,
      baseEpoch: 7,
      targetEpoch: 8,
      liveObjectCount: 1,
      liveRevisionCount: 2,
      targetManifest: {
        revisionId: newManifestRevisionId,
        revision: 4,
        ciphertextHash: "cd".repeat(32),
      },
    });
    expect(result.targetManifest.manifest).toMatchObject({
      generation: 3,
      previousManifest: {
        objectId: manifestObjectId,
        revisionId: baseManifestRevisionId,
      },
      documents: [
        {
          objectId: documentObjectId,
          revisions: [
            { revisionId: newRevisionOne, parentRevisionIds: [] },
            {
              revisionId: newRevisionTwo,
              parentRevisionIds: [newRevisionOne],
            },
          ],
        },
      ],
    });
    expect(transport.put).toHaveBeenNthCalledWith(
      2,
      expect.objectContaining({ parentRevisionIds: [newRevisionOne] }),
    );
    expect(objects.sealManifestForPreparedRotation).toHaveBeenCalledWith(
      expect.objectContaining({
        vaultId,
        targetEndpointId,
        objectId: manifestObjectId,
        revision: 4,
      }),
    );
    expect(index.readManifest).toHaveBeenCalledTimes(3);
  });

  it("fails closed when the local manifest changes during preparation", async () => {
    const base = head();
    const changed = head();
    changed.manifest.generation += 1;
    const index = {
      readManifest: vi
        .fn()
        .mockResolvedValueOnce(base)
        .mockResolvedValueOnce(changed),
    };
    const transport = {
      get: vi
        .fn()
        .mockResolvedValueOnce(
          downloaded("vault-manifest", 3, ["aa".repeat(32)]),
        )
        .mockResolvedValueOnce(downloaded("document", 1, []))
        .mockResolvedValueOnce(downloaded("document", 2, [oldRevisionOne])),
      put: vi.fn(async (input: any) => ({
        ...input.coordinate,
        objectType: input.objectType,
        algorithmId: "anc/v1" as const,
        revision: input.revision,
        epoch: input.epoch,
        parentRevisionIds: input.parentRevisionIds,
        ciphertextByteLength: input.ciphertext.byteLength,
      })),
    };
    const ids = [newRevisionOne, newRevisionTwo];
    const preparer = new PrivateVaultContentEndpointRemovalPreparer({
      native: {
        removeVaultEndpoint: vi.fn(async () => ({
          version: 1 as const,
          suite: "anc/v1" as const,
          operation: "remove_endpoint" as const,
          state: "pending" as const,
          vaultId,
          targetEndpointId,
          createdAt: 1_721_296_802,
        })),
      },
      index,
      transport,
      objects: {
        rewrapRevisionForPreparedRotation: vi.fn(async (input: any) => ({
          revisionId: ids.shift()!,
          revision: input.revision,
          epoch: 8,
          objectType: "document" as const,
          plaintextLength: 20,
          ciphertext: Uint8Array.of(4),
          ciphertextHash: "ab".repeat(32),
          ciphertextByteLength: 1,
        })),
        sealManifestForPreparedRotation: vi.fn(),
      },
    });
    await expect(preparer.prepare(vaultId, targetEndpointId)).rejects.toEqual(
      new PrivateVaultEndpointRemovalError(),
    );
  });
});
