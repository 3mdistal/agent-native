import { createHash } from "node:crypto";

import {
  PRIVATE_VAULT_CONTENT_TYPE,
  PRIVATE_VAULT_MANIFEST_CONTENT_TYPE,
} from "./content-document-codec.js";
import {
  PrivateVaultContentObjectTransport,
  type PrivateVaultContentObjectMetadata,
  type PrivateVaultContentHostedObjectType,
} from "./content-object-transport.js";
import {
  createPrivateVaultNativeServiceClient,
  type PrivateVaultNativeServiceClient,
} from "./native-service-client.js";

function hex(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("hex");
}

type ContentType =
  | typeof PRIVATE_VAULT_CONTENT_TYPE
  | typeof PRIVATE_VAULT_MANIFEST_CONTENT_TYPE;

function hostedObjectType(
  contentType: ContentType,
): PrivateVaultContentHostedObjectType {
  return contentType === PRIVATE_VAULT_CONTENT_TYPE
    ? "document"
    : "vault-manifest";
}

export class PrivateVaultContentObjectRuntime {
  readonly #native: Pick<
    PrivateVaultNativeServiceClient,
    | "sealContentObjectRevision"
    | "openContentObjectRevision"
    | "rewrapContentObjectRevision"
    | "sealRotationManifest"
  >;

  constructor(
    native: Pick<
      PrivateVaultNativeServiceClient,
      | "sealContentObjectRevision"
      | "openContentObjectRevision"
      | "rewrapContentObjectRevision"
      | "sealRotationManifest"
    >,
  ) {
    this.#native = native;
  }

  async sealAndUpload(input: {
    readonly transport: PrivateVaultContentObjectTransport;
    readonly vaultId: string;
    readonly objectId: string;
    readonly revision: number;
    readonly contentType?: ContentType;
    readonly plaintext: Uint8Array;
    readonly parentRevisionIds?: readonly string[];
  }): Promise<{
    readonly revisionId: string;
    readonly ciphertextHash: string;
    readonly epoch: number;
    readonly plaintextLength: number;
    readonly ciphertextByteLength: number;
  }> {
    const contentType = input.contentType ?? PRIVATE_VAULT_CONTENT_TYPE;
    const sealed = await this.#native.sealContentObjectRevision({
      vaultId: input.vaultId,
      objectId: input.objectId,
      revision: input.revision,
      contentType,
      plaintext: input.plaintext,
    });
    const revisionId = hex(sealed.revisionId);
    const ciphertextHash = createHash("sha256")
      .update(sealed.encodedRevision)
      .digest("hex");
    try {
      const metadata = await input.transport.put({
        coordinate: {
          vaultId: sealed.vaultId,
          objectId: sealed.objectId,
          revisionId,
        },
        revision: sealed.revision,
        objectType: hostedObjectType(sealed.contentType),
        epoch: sealed.epoch,
        parentRevisionIds: input.parentRevisionIds,
        ciphertext: sealed.encodedRevision,
      });
      return Object.freeze({
        revisionId,
        ciphertextHash,
        epoch: metadata.epoch,
        plaintextLength: sealed.plaintextLength,
        ciphertextByteLength: metadata.ciphertextByteLength,
      });
    } finally {
      sealed.encodedRevision.fill(0);
    }
  }

  async downloadAndOpen(input: {
    readonly transport: PrivateVaultContentObjectTransport;
    readonly vaultId: string;
    readonly objectId: string;
    readonly revisionId: string;
  }): Promise<{
    readonly plaintext: Uint8Array;
    readonly epoch: number;
    readonly writerEndpointId: string;
    readonly metadata: Omit<
      PrivateVaultContentObjectMetadata,
      "vaultId" | "objectId" | "revisionId" | "serverReceivedAt"
    >;
  }> {
    const downloaded = await input.transport.get(input);
    const ciphertext = Uint8Array.from(downloaded.ciphertext);
    try {
      const opened = await this.#native.openContentObjectRevision({
        vaultId: input.vaultId,
        objectId: input.objectId,
        revision: downloaded.metadata.revision,
        encodedRevision: ciphertext,
      });
      try {
        if (
          hex(opened.revisionId) !== input.revisionId ||
          opened.epoch !== downloaded.metadata.epoch ||
          hostedObjectType(opened.contentType) !==
            downloaded.metadata.objectType ||
          opened.plaintextLength !== opened.plaintext.byteLength
        )
          throw new Error("object binding failed");
        return Object.freeze({
          plaintext: opened.plaintext.slice(),
          epoch: opened.epoch,
          writerEndpointId: hex(opened.writerEndpointId),
          metadata: downloaded.metadata,
        });
      } finally {
        opened.plaintext.fill(0);
      }
    } finally {
      ciphertext.fill(0);
      downloaded.ciphertext.fill(0);
    }
  }

  async rewrapRevisionForPreparedRotation(input: {
    readonly vaultId: string;
    readonly objectId: string;
    readonly revision: number;
    readonly epoch: number;
    readonly objectType: PrivateVaultContentHostedObjectType;
    readonly encodedRevision: Uint8Array;
  }): Promise<{
    readonly revisionId: string;
    readonly revision: number;
    readonly epoch: number;
    readonly objectType: PrivateVaultContentHostedObjectType;
    readonly plaintextLength: number;
    readonly ciphertext: Uint8Array;
    readonly ciphertextHash: string;
    readonly ciphertextByteLength: number;
  }> {
    if (
      !Number.isSafeInteger(input.revision) ||
      input.revision <= 0 ||
      !Number.isSafeInteger(input.epoch) ||
      input.epoch <= 0 ||
      input.epoch >= Number.MAX_SAFE_INTEGER ||
      (input.objectType !== "document" && input.objectType !== "vault-manifest")
    )
      throw new Error("object rewrap binding failed");
    const rewrapped = await this.#native.rewrapContentObjectRevision({
      vaultId: input.vaultId,
      objectId: input.objectId,
      encodedRevision: input.encodedRevision,
    });
    try {
      if (
        rewrapped.revision !== input.revision ||
        rewrapped.epoch !== input.epoch + 1 ||
        hostedObjectType(rewrapped.contentType) !== input.objectType
      )
        throw new Error("object rewrap binding failed");
      const ciphertext = rewrapped.encodedRevision.slice();
      return Object.freeze({
        revisionId: hex(rewrapped.revisionId),
        revision: rewrapped.revision,
        epoch: rewrapped.epoch,
        objectType: hostedObjectType(rewrapped.contentType),
        plaintextLength: rewrapped.plaintextLength,
        ciphertext,
        ciphertextHash: createHash("sha256").update(ciphertext).digest("hex"),
        ciphertextByteLength: ciphertext.byteLength,
      });
    } finally {
      rewrapped.encodedRevision.fill(0);
    }
  }

  async sealManifestForPreparedRotation(input: {
    readonly vaultId: string;
    readonly targetEndpointId: string;
    readonly objectId: string;
    readonly revision: number;
    readonly plaintext: Uint8Array;
  }): Promise<{
    readonly revisionId: string;
    readonly revision: number;
    readonly epoch: number;
    readonly objectType: "vault-manifest";
    readonly plaintextLength: number;
    readonly ciphertext: Uint8Array;
    readonly ciphertextHash: string;
    readonly ciphertextByteLength: number;
  }> {
    const sealed = await this.#native.sealRotationManifest(input);
    try {
      if (
        sealed.contentType !== PRIVATE_VAULT_MANIFEST_CONTENT_TYPE ||
        sealed.revision !== input.revision ||
        sealed.plaintextLength !== input.plaintext.byteLength
      )
        throw new Error("rotation manifest binding failed");
      const ciphertext = sealed.encodedRevision.slice();
      return Object.freeze({
        revisionId: hex(sealed.revisionId),
        revision: sealed.revision,
        epoch: sealed.epoch,
        objectType: "vault-manifest" as const,
        plaintextLength: sealed.plaintextLength,
        ciphertext,
        ciphertextHash: createHash("sha256").update(ciphertext).digest("hex"),
        ciphertextByteLength: ciphertext.byteLength,
      });
    } finally {
      sealed.encodedRevision.fill(0);
    }
  }
}

export function createPrivateVaultContentObjectRuntime() {
  return new PrivateVaultContentObjectRuntime(
    createPrivateVaultNativeServiceClient(),
  );
}
