import {
  encodePrivateVaultContentManifest,
  type PrivateVaultContentManifest,
  type PrivateVaultLocalManifestHead,
} from "./content-document-codec.js";
import type { PrivateVaultContentObjectRuntime } from "./content-object-runtime.js";
import type {
  PrivateVaultContentObjectMetadata,
  PrivateVaultContentObjectTransport,
} from "./content-object-transport.js";
import type { EncryptedContentIndexStore } from "./encrypted-content-index-store.js";
import type {
  NativeEndpointRemovalEekWrap,
  PrivateVaultNativeServiceClient,
} from "./native-service-client.js";

const MAXIMUM_ROTATION_REVISIONS = 10_000;

export class PrivateVaultEndpointRemovalError extends Error {
  constructor() {
    super("Private Vault endpoint removal requires attention");
    this.name = "PrivateVaultEndpointRemovalError";
  }
}

function sameStrings(left: readonly string[], right: readonly string[]) {
  return (
    left.length === right.length &&
    left.every((value, index) => value === right[index])
  );
}

function sameHead(
  left: PrivateVaultLocalManifestHead | null,
  right: PrivateVaultLocalManifestHead,
) {
  return (
    left?.objectId === right.objectId &&
    left.revisionId === right.revisionId &&
    JSON.stringify(left.manifest) === JSON.stringify(right.manifest)
  );
}

export interface PrivateVaultPreparedEndpointRemoval {
  readonly vaultId: string;
  readonly targetEndpointId: string;
  readonly createdAt: number;
  readonly baseEpoch: number;
  readonly targetEpoch: number;
  readonly baseManifest: Readonly<{
    objectId: string;
    revisionId: string;
    revision: number;
  }>;
  readonly targetManifest: Readonly<{
    objectId: string;
    revisionId: string;
    revision: number;
    ciphertextHash: string;
    ciphertextByteLength: number;
    manifest: PrivateVaultContentManifest;
  }>;
  readonly liveObjectCount: number;
  readonly liveRevisionCount: number;
  readonly liveRevisions: readonly Readonly<{
    objectId: string;
    revision: number;
    priorRevisionId: string;
    rotatedRevisionId: string;
  }>[];
  readonly ceremony: Readonly<{
    ceremonyId: Uint8Array;
    signedEntry: Uint8Array;
    recoveryWrap: Uint8Array;
    transcriptDigest: Uint8Array;
    baseSequence: number;
    baseHead: Uint8Array;
    baseMembership: Uint8Array;
    recipientEekWraps: readonly NativeEndpointRemovalEekWrap[];
  }>;
}

/**
 * Builds the complete target-epoch object set, but deliberately does not
 * advance the native preparation record. Recipient acknowledgements and old
 * epoch destruction still have to be proven before the control edge may arm.
 */
export class PrivateVaultContentEndpointRemovalPreparer {
  readonly #native: Pick<
    PrivateVaultNativeServiceClient,
    "removeVaultEndpoint"
  >;
  readonly #index: Pick<EncryptedContentIndexStore, "readManifest">;
  readonly #transport: Pick<PrivateVaultContentObjectTransport, "get" | "put">;
  readonly #objects: Pick<
    PrivateVaultContentObjectRuntime,
    "rewrapRevisionForPreparedRotation" | "sealManifestForPreparedRotation"
  >;

  constructor(input: {
    native: Pick<PrivateVaultNativeServiceClient, "removeVaultEndpoint">;
    index: Pick<EncryptedContentIndexStore, "readManifest">;
    transport: Pick<PrivateVaultContentObjectTransport, "get" | "put">;
    objects: Pick<
      PrivateVaultContentObjectRuntime,
      "rewrapRevisionForPreparedRotation" | "sealManifestForPreparedRotation"
    >;
  }) {
    this.#native = input.native;
    this.#index = input.index;
    this.#transport = input.transport;
    this.#objects = input.objects;
  }

  async prepare(
    vaultId: string,
    targetEndpointId: string,
  ): Promise<PrivateVaultPreparedEndpointRemoval> {
    try {
      const baseHead = await this.#index.readManifest(vaultId);
      if (!baseHead || baseHead.manifest.vaultId !== vaultId) throw new Error();
      const started = await this.#native.removeVaultEndpoint(
        vaultId,
        targetEndpointId,
      );
      const baseManifestRevision = await this.#transport.get({
        vaultId,
        objectId: baseHead.objectId,
        revisionId: baseHead.revisionId,
      });
      try {
        if (
          baseManifestRevision.metadata.objectType !== "vault-manifest" ||
          !sameStrings(
            baseManifestRevision.metadata.parentRevisionIds,
            baseHead.manifest.previousManifest
              ? [baseHead.manifest.previousManifest.revisionId]
              : [],
          ) ||
          baseHead.manifest.generation >= Number.MAX_SAFE_INTEGER ||
          baseManifestRevision.metadata.revision >= Number.MAX_SAFE_INTEGER
        )
          throw new Error();
        const baseEpoch = baseManifestRevision.metadata.epoch;
        const targetEpoch = baseEpoch + 1;
        if (!Number.isSafeInteger(targetEpoch)) throw new Error();
        const revisionIdMap = new Map<string, string>();
        const liveRevisions: Array<{
          objectId: string;
          revision: number;
          priorRevisionId: string;
          rotatedRevisionId: string;
        }> = [];
        let revisionCount = 0;
        const documents = [] as PrivateVaultContentManifest["documents"];

        for (const document of [...baseHead.manifest.documents].sort(
          (left, right) => left.objectId.localeCompare(right.objectId),
        )) {
          const revisions = [] as typeof document.revisions;
          for (const revision of document.revisions) {
            revisionCount += 1;
            if (revisionCount > MAXIMUM_ROTATION_REVISIONS) throw new Error();
            const downloaded = await this.#transport.get({
              vaultId,
              objectId: document.objectId,
              revisionId: revision.revisionId,
            });
            try {
              if (
                downloaded.metadata.objectType !== "document" ||
                downloaded.metadata.revision !== revision.revision ||
                downloaded.metadata.epoch !== baseEpoch ||
                !sameStrings(
                  downloaded.metadata.parentRevisionIds,
                  revision.parentRevisionIds,
                )
              )
                throw new Error();
              const parents = revision.parentRevisionIds.map((parent) => {
                const mapped = revisionIdMap.get(parent);
                if (!mapped) throw new Error();
                return mapped;
              });
              const rewrapped =
                await this.#objects.rewrapRevisionForPreparedRotation({
                  vaultId,
                  objectId: document.objectId,
                  revision: revision.revision,
                  epoch: baseEpoch,
                  objectType: "document",
                  encodedRevision: downloaded.ciphertext,
                });
              try {
                if (rewrapped.epoch !== targetEpoch) throw new Error();
                const stored = await this.#transport.put({
                  coordinate: {
                    vaultId,
                    objectId: document.objectId,
                    revisionId: rewrapped.revisionId,
                  },
                  objectType: "document",
                  revision: revision.revision,
                  epoch: targetEpoch,
                  parentRevisionIds: parents,
                  ciphertext: rewrapped.ciphertext,
                });
                this.#assertStored(stored, rewrapped, parents);
                revisionIdMap.set(revision.revisionId, rewrapped.revisionId);
                liveRevisions.push({
                  objectId: document.objectId,
                  revision: revision.revision,
                  priorRevisionId: revision.revisionId,
                  rotatedRevisionId: rewrapped.revisionId,
                });
                revisions.push({
                  revision: revision.revision,
                  revisionId: rewrapped.revisionId,
                  parentRevisionIds: parents,
                });
              } finally {
                rewrapped.ciphertext.fill(0);
              }
            } finally {
              downloaded.ciphertext.fill(0);
            }
          }
          documents.push({
            objectId: document.objectId,
            ...(document.parentId === undefined
              ? {}
              : { parentId: document.parentId }),
            ...(document.position === undefined
              ? {}
              : { position: document.position }),
            revisions,
          });
        }

        if (!(await this.#unchanged(baseHead))) throw new Error();
        const targetManifest: PrivateVaultContentManifest = {
          version: 1,
          kind: "content-vault-manifest",
          vaultId,
          generation: baseHead.manifest.generation + 1,
          previousManifest: {
            objectId: baseHead.objectId,
            revisionId: baseHead.revisionId,
          },
          documents,
          committedAt: new Date(started.createdAt * 1000).toISOString(),
        };
        const plaintext = encodePrivateVaultContentManifest(targetManifest);
        const manifestRevision = baseManifestRevision.metadata.revision + 1;
        try {
          const sealed = await this.#objects.sealManifestForPreparedRotation({
            vaultId,
            targetEndpointId,
            objectId: baseHead.objectId,
            revision: manifestRevision,
            plaintext,
          });
          try {
            if (sealed.epoch !== targetEpoch) throw new Error();
            const parents = [baseHead.revisionId];
            const stored = await this.#transport.put({
              coordinate: {
                vaultId,
                objectId: baseHead.objectId,
                revisionId: sealed.revisionId,
              },
              objectType: "vault-manifest",
              revision: manifestRevision,
              epoch: targetEpoch,
              parentRevisionIds: parents,
              ciphertext: sealed.ciphertext,
            });
            this.#assertStored(stored, sealed, parents);
            if (!(await this.#unchanged(baseHead))) throw new Error();
            return Object.freeze({
              vaultId,
              targetEndpointId,
              createdAt: started.createdAt,
              baseEpoch,
              targetEpoch,
              baseManifest: Object.freeze({
                objectId: baseHead.objectId,
                revisionId: baseHead.revisionId,
                revision: baseManifestRevision.metadata.revision,
              }),
              targetManifest: Object.freeze({
                objectId: baseHead.objectId,
                revisionId: sealed.revisionId,
                revision: manifestRevision,
                ciphertextHash: sealed.ciphertextHash,
                ciphertextByteLength: sealed.ciphertextByteLength,
                manifest: targetManifest,
              }),
              liveObjectCount: documents.length,
              liveRevisionCount: revisionCount,
              liveRevisions: Object.freeze(
                liveRevisions.map((revision) => Object.freeze(revision)),
              ),
              ceremony: Object.freeze({
                ceremonyId: started.ceremonyId.slice(),
                signedEntry: started.signedEntry.slice(),
                recoveryWrap: started.recoveryWrap.slice(),
                transcriptDigest: started.transcriptDigest.slice(),
                baseSequence: started.baseSequence,
                baseHead: started.baseHead.slice(),
                baseMembership: started.baseMembership.slice(),
                recipientEekWraps: started.recipientEekWraps,
              }),
            });
          } finally {
            sealed.ciphertext.fill(0);
          }
        } finally {
          plaintext.fill(0);
        }
      } finally {
        baseManifestRevision.ciphertext.fill(0);
      }
    } catch {
      throw new PrivateVaultEndpointRemovalError();
    }
  }

  async #unchanged(base: PrivateVaultLocalManifestHead) {
    return sameHead(
      await this.#index.readManifest(base.manifest.vaultId),
      base,
    );
  }

  #assertStored(
    stored: PrivateVaultContentObjectMetadata,
    expected: {
      readonly revisionId: string;
      readonly revision: number;
      readonly epoch: number;
      readonly ciphertextByteLength: number;
    },
    parents: readonly string[],
  ) {
    if (
      stored.revisionId !== expected.revisionId ||
      stored.revision !== expected.revision ||
      stored.epoch !== expected.epoch ||
      stored.ciphertextByteLength !== expected.ciphertextByteLength ||
      !sameStrings(stored.parentRevisionIds, parents)
    )
      throw new Error();
  }
}
