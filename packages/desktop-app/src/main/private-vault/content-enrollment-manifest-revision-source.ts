import type { PrivateVaultContentObjectTransport } from "./content-object-transport.js";
import type { EncryptedContentIndexStore } from "./encrypted-content-index-store.js";
import type {
  NativeVerifyEnrollmentManifestResult,
  PrivateVaultNativeServiceClient,
} from "./native-service-client.js";

const MAXIMUM_MANIFEST_CANDIDATES = 2_048;

type ManifestIndex = Pick<
  EncryptedContentIndexStore,
  "initialize" | "readManifest"
>;

type ManifestTransport = Pick<
  PrivateVaultContentObjectTransport,
  "get" | "list"
>;

type ManifestVerifier = Pick<
  PrivateVaultNativeServiceClient,
  "verifyBrokerEnrollmentManifest"
>;

export class PrivateVaultContentEnrollmentManifestRevisionSourceError extends Error {
  constructor() {
    super("Private Vault enrollment manifest evidence is unavailable");
    this.name = "PrivateVaultContentEnrollmentManifestRevisionSourceError";
  }
}

function expectedParents(
  previousManifest: { readonly revisionId: string } | null,
): readonly string[] {
  return previousManifest ? [previousManifest.revisionId] : [];
}

function sameStrings(left: readonly string[], right: readonly string[]) {
  return (
    left.length === right.length &&
    left.every((value, index) => value === right[index])
  );
}

/**
 * Supplies opaque encrypted manifest revisions to the signed native verifier.
 * This layer never opens or interprets their plaintext.
 */
export class PrivateVaultContentEnrollmentManifestRevisionSource {
  readonly #index: ManifestIndex;
  readonly #transport: ManifestTransport;
  readonly #native: ManifestVerifier;
  #initialization: Promise<void> | null = null;

  constructor(input: {
    readonly index: ManifestIndex;
    readonly transport: ManifestTransport;
    readonly native: ManifestVerifier;
  }) {
    this.#index = input.index;
    this.#transport = input.transport;
    this.#native = input.native;
  }

  async readTrustedCurrentRevision(vaultId: string): Promise<Uint8Array> {
    try {
      await this.#initialize();
      const head = await this.#index.readManifest(vaultId);
      if (!head || head.manifest.vaultId !== vaultId) throw new Error();
      const downloaded = await this.#transport.get({
        vaultId,
        objectId: head.objectId,
        revisionId: head.revisionId,
      });
      if (
        downloaded.metadata.objectType !== "vault-manifest" ||
        downloaded.metadata.revision !== 1 ||
        !sameStrings(
          downloaded.metadata.parentRevisionIds,
          expectedParents(head.manifest.previousManifest),
        )
      ) {
        downloaded.ciphertext.fill(0);
        throw new Error();
      }
      return downloaded.ciphertext;
    } catch {
      throw new PrivateVaultContentEnrollmentManifestRevisionSourceError();
    }
  }

  async verifyUniqueHostedRevision(input: {
    readonly vaultId: string;
    readonly challenge: Uint8Array;
    readonly authorization: Uint8Array;
    readonly manifestCheckpoint: Uint8Array;
    readonly manifestAuthorization: Uint8Array;
  }): Promise<NativeVerifyEnrollmentManifestResult> {
    try {
      const objects = await this.#transport.list(input.vaultId);
      const candidates = objects.filter(
        (object) => object.objectType === "vault-manifest",
      );
      if (
        candidates.length === 0 ||
        candidates.length > MAXIMUM_MANIFEST_CANDIDATES
      ) {
        throw new Error();
      }

      const verified: NativeVerifyEnrollmentManifestResult[] = [];
      for (const candidate of candidates) {
        if (
          candidate.latestRevision.objectType !== "vault-manifest" ||
          candidate.latestRevision.revision !== 1
        ) {
          continue;
        }
        const downloaded = await this.#transport.get({
          vaultId: input.vaultId,
          objectId: candidate.objectId,
          revisionId: candidate.latestRevision.revisionId,
        });
        try {
          if (
            downloaded.metadata.objectType !== "vault-manifest" ||
            downloaded.metadata.revision !== 1 ||
            downloaded.metadata.epoch !== candidate.latestRevision.epoch ||
            downloaded.metadata.ciphertextByteLength !==
              candidate.latestRevision.ciphertextByteLength ||
            !sameStrings(
              downloaded.metadata.parentRevisionIds,
              candidate.latestRevision.parentRevisionIds,
            )
          ) {
            continue;
          }
          try {
            verified.push(
              await this.#native.verifyBrokerEnrollmentManifest({
                vaultId: input.vaultId,
                challenge: input.challenge.slice(),
                authorization: input.authorization.slice(),
                manifestCheckpoint: input.manifestCheckpoint.slice(),
                manifestAuthorization: input.manifestAuthorization.slice(),
                manifestRevision: downloaded.ciphertext.slice(),
              }),
            );
          } catch {
            // An untrusted hosted candidate is simply not verified evidence.
          }
        } finally {
          downloaded.ciphertext.fill(0);
        }
      }
      if (verified.length !== 1) throw new Error();
      return verified[0]!;
    } catch {
      throw new PrivateVaultContentEnrollmentManifestRevisionSourceError();
    }
  }

  #initialize(): Promise<void> {
    this.#initialization ??= this.#index.initialize();
    return this.#initialization;
  }
}
