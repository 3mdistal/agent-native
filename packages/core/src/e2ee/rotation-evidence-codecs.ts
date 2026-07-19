import sodium from "libsodium-wrappers-sumo";

import {
  type AncV1CanonicalValue,
  decodeAncV1Envelope,
  encodeAncV1Canonical,
} from "./canonical.js";
import { decodeAncV1ControlLogRotationAppendReceipt } from "./control-log-append.js";
import { E2EE_ENVELOPE_FIELDS } from "./suite.js";

const COMMON = E2EE_ENVELOPE_FIELDS.common;
export const ANC_ROTATION_EVIDENCE_SUITE_ID = "anc/rotation/v1" as const;
export const ANC_ROTATION_EVIDENCE_FIELDS = Object.freeze({
  checkpoint: Object.freeze({
    ceremonyId: 10,
    baseSequence: 11,
    baseHeadHash: 12,
    targetEpoch: 13,
    manifestObjectId: 14,
    revisionId: 15,
    generation: 16,
    ciphertextHash: 17,
    liveObjectCount: 18,
    liveRevisionSetHash: 19,
    signerEndpointId: 20,
    removedEndpointId: 21,
    signature: 22,
    baseEpoch: 23,
    liveRevisionCount: 24,
    recipientSetHash: 25,
    controlEntryHash: 26,
  }),
  offer: Object.freeze({
    ceremonyId: 30,
    checkpointHash: 31,
    eekWrapHash: 32,
    recipientEndpointId: 33,
    issuerEndpointId: 34,
    targetEpoch: 35,
    expiresAt: 36,
    signature: 37,
  }),
  acknowledgement: Object.freeze({
    ceremonyId: 40,
    checkpointHash: 41,
    eekWrapHash: 42,
    recipientEndpointId: 43,
    targetEpoch: 44,
    possessionMac: 45,
    signature: 46,
    offerHash: 47,
  }),
  destruction: Object.freeze({
    ceremonyId: 50,
    checkpointHash: 51,
    controlEntryHash: 52,
    endpointId: 53,
    destroyedEpoch: 54,
    activatedEpoch: 55,
    custodyGeneration: 56,
    signature: 57,
  }),
  completion: Object.freeze({
    ceremonyId: 60,
    checkpointHash: 61,
    controlEntryHash: 62,
    hostedReceiptHash: 63,
    signerEndpointId: 64,
    committedSequence: 65,
    committedHeadHash: 66,
    recipientSetHash: 67,
    signature: 68,
  }),
});
export const ANC_ROTATION_EVIDENCE_SIZE_LIMITS = Object.freeze({
  checkpointBytes: 1_024,
  offerBytes: 1_024,
  acknowledgementBytes: 1_024,
  destructionBytes: 1_024,
  completionBytes: 1_024,
  acknowledgements: 64,
  liveRevisions: 10_000,
  clockSkewSeconds: 60,
  timestampUnit: "unix-seconds",
});

const CHECKPOINT = ANC_ROTATION_EVIDENCE_FIELDS.checkpoint;
const OFFER = ANC_ROTATION_EVIDENCE_FIELDS.offer;
const ACK = ANC_ROTATION_EVIDENCE_FIELDS.acknowledgement;
const DESTRUCTION = ANC_ROTATION_EVIDENCE_FIELDS.destruction;
const COMPLETION = ANC_ROTATION_EVIDENCE_FIELDS.completion;
const ID_BYTES = 16;
const HASH_BYTES = 32;
const REVISION_ID_BYTES = 32;
const SIGNATURE_BYTES = 64;
const KEY_BYTES = 32;

type RotationType =
  | "rotation-manifest-checkpoint"
  | "rotation-recipient-offer"
  | "rotation-recipient-acknowledgement"
  | "rotation-epoch-destruction-attestation"
  | "rotation-control-commit-attestation";
type RotationHashDomain =
  | "rotation-live-revision-set-hash"
  | "rotation-recipient-set-hash"
  | "rotation-manifest-checkpoint-hash"
  | "rotation-recipient-offer-hash"
  | "rotation-hosted-receipt-hash"
  | "rotation-recipient-acknowledgement-mac";
type RotationDomain = RotationType | RotationHashDomain;

interface RotationCommon {
  readonly suite: typeof ANC_ROTATION_EVIDENCE_SUITE_ID;
  readonly vaultId: Uint8Array;
  readonly type: RotationType;
  readonly createdAt: number;
  readonly envelopeId: Uint8Array;
}

export interface AncV1UnsignedRotationManifestCheckpoint extends RotationCommon {
  readonly type: "rotation-manifest-checkpoint";
  readonly ceremonyId: Uint8Array;
  readonly baseSequence: number;
  readonly baseHeadHash: Uint8Array;
  readonly baseEpoch: number;
  readonly targetEpoch: number;
  readonly manifestObjectId: Uint8Array;
  readonly revisionId: Uint8Array;
  readonly generation: number;
  readonly ciphertextHash: Uint8Array;
  readonly liveObjectCount: number;
  readonly liveRevisionCount: number;
  readonly liveRevisionSetHash: Uint8Array;
  readonly recipientSetHash: Uint8Array;
  readonly controlEntryHash: Uint8Array;
  readonly signerEndpointId: Uint8Array;
  readonly removedEndpointId: Uint8Array;
}

export interface AncV1RotationManifestCheckpoint extends AncV1UnsignedRotationManifestCheckpoint {
  readonly signature: Uint8Array;
}

export interface AncV1UnsignedRotationRecipientOffer extends RotationCommon {
  readonly type: "rotation-recipient-offer";
  readonly ceremonyId: Uint8Array;
  readonly checkpointHash: Uint8Array;
  readonly eekWrapHash: Uint8Array;
  readonly recipientEndpointId: Uint8Array;
  readonly issuerEndpointId: Uint8Array;
  readonly targetEpoch: number;
  readonly expiresAt: number;
}

export interface AncV1RotationRecipientOffer extends AncV1UnsignedRotationRecipientOffer {
  readonly signature: Uint8Array;
}

export interface AncV1UnsignedRotationRecipientAcknowledgement extends RotationCommon {
  readonly type: "rotation-recipient-acknowledgement";
  readonly ceremonyId: Uint8Array;
  readonly checkpointHash: Uint8Array;
  readonly eekWrapHash: Uint8Array;
  readonly offerHash: Uint8Array;
  readonly recipientEndpointId: Uint8Array;
  readonly targetEpoch: number;
}

export interface AncV1RotationRecipientAcknowledgement extends AncV1UnsignedRotationRecipientAcknowledgement {
  readonly possessionMac: Uint8Array;
  readonly signature: Uint8Array;
}

export interface AncV1UnsignedRotationEpochDestructionAttestation extends RotationCommon {
  readonly type: "rotation-epoch-destruction-attestation";
  readonly ceremonyId: Uint8Array;
  readonly checkpointHash: Uint8Array;
  readonly controlEntryHash: Uint8Array;
  readonly endpointId: Uint8Array;
  readonly destroyedEpoch: number;
  readonly activatedEpoch: number;
  readonly custodyGeneration: number;
}

export interface AncV1RotationEpochDestructionAttestation extends AncV1UnsignedRotationEpochDestructionAttestation {
  readonly signature: Uint8Array;
}

export interface AncV1UnsignedRotationControlCommitAttestation extends RotationCommon {
  readonly type: "rotation-control-commit-attestation";
  readonly ceremonyId: Uint8Array;
  readonly checkpointHash: Uint8Array;
  readonly controlEntryHash: Uint8Array;
  readonly hostedReceiptHash: Uint8Array;
  readonly signerEndpointId: Uint8Array;
  readonly committedSequence: number;
  readonly committedHeadHash: Uint8Array;
  readonly recipientSetHash: Uint8Array;
}

export interface AncV1RotationControlCommitAttestation extends AncV1UnsignedRotationControlCommitAttestation {
  readonly signature: Uint8Array;
}

export class AncV1RotationEvidenceError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "AncV1RotationEvidenceError";
  }
}

const commonKeys = Object.values(COMMON);
const checkpointKeys = [...commonKeys, ...Object.values(CHECKPOINT)];
const offerKeys = [...commonKeys, ...Object.values(OFFER)];
const acknowledgementKeys = [...commonKeys, ...Object.values(ACK)];
const destructionKeys = [...commonKeys, ...Object.values(DESTRUCTION)];
const completionKeys = [...commonKeys, ...Object.values(COMPLETION)];

function fail(message: string): never {
  throw new AncV1RotationEvidenceError(message);
}

function exact(value: object, expected: readonly string[], name: string) {
  const actual = Object.keys(value).sort();
  const fields = [...expected].sort();
  if (
    actual.length !== fields.length ||
    actual.some((field, index) => field !== fields[index])
  )
    fail(`${name} must contain exactly its versioned fields`);
}

function bytes(value: unknown, length: number, name: string): Uint8Array {
  if (!(value instanceof Uint8Array) || value.byteLength !== length)
    fail(`${name} must be exactly ${length} bytes`);
  return value.slice();
}

function positive(value: unknown, name: string): number {
  if (!Number.isSafeInteger(value) || (value as number) < 1)
    fail(`${name} must be a positive safe integer`);
  return value as number;
}

function nonnegative(value: unknown, name: string): number {
  if (!Number.isSafeInteger(value) || (value as number) < 0)
    fail(`${name} must be a non-negative safe integer`);
  return value as number;
}

function boundedCount(value: unknown, name: string): number {
  const count = nonnegative(value, name);
  if (count > ANC_ROTATION_EVIDENCE_SIZE_LIMITS.liveRevisions)
    fail(`${name} exceeds the v1 rotation limit`);
  return count;
}

function same(left: Uint8Array, right: Uint8Array): boolean {
  if (left.byteLength !== right.byteLength) return false;
  let difference = 0;
  for (let index = 0; index < left.byteLength; index += 1)
    difference |= left[index]! ^ right[index]!;
  return difference === 0;
}

function field(
  map: ReadonlyMap<number, AncV1CanonicalValue>,
  key: number,
  name: string,
): AncV1CanonicalValue {
  if (!map.has(key)) fail(`${name} is required`);
  return map.get(key)!;
}

function commonMap(
  value: RotationCommon,
  type: RotationType,
): Map<number, AncV1CanonicalValue> {
  if (value.suite !== ANC_ROTATION_EVIDENCE_SUITE_ID || value.type !== type)
    fail("Rotation evidence suite or type is invalid");
  return new Map<number, AncV1CanonicalValue>([
    [COMMON.suite, ANC_ROTATION_EVIDENCE_SUITE_ID],
    [COMMON.vaultId, bytes(value.vaultId, ID_BYTES, "vaultId")],
    [COMMON.type, type],
    [COMMON.createdAt, positive(value.createdAt, "createdAt")],
    [COMMON.envelopeId, bytes(value.envelopeId, ID_BYTES, "envelopeId")],
  ]);
}

function decodeCommon(
  map: ReadonlyMap<number, AncV1CanonicalValue>,
  type: RotationType,
  expectedVaultId: Uint8Array,
): RotationCommon {
  const vaultId = bytes(field(map, COMMON.vaultId, "vaultId"), 16, "vaultId");
  if (!same(vaultId, bytes(expectedVaultId, 16, "expectedVaultId")))
    fail("vaultId does not match the expected vault");
  if (
    field(map, COMMON.suite, "suite") !== ANC_ROTATION_EVIDENCE_SUITE_ID ||
    field(map, COMMON.type, "type") !== type
  )
    fail("Rotation evidence suite or type is invalid");
  return {
    suite: ANC_ROTATION_EVIDENCE_SUITE_ID,
    vaultId,
    type,
    createdAt: positive(field(map, COMMON.createdAt, "createdAt"), "createdAt"),
    envelopeId: bytes(
      field(map, COMMON.envelopeId, "envelopeId"),
      ID_BYTES,
      "envelopeId",
    ),
  };
}

function preimage(type: RotationDomain, encoded: Uint8Array): Uint8Array {
  const prefix = new TextEncoder().encode(
    `${ANC_ROTATION_EVIDENCE_SUITE_ID}/${type}\0`,
  );
  const output = new Uint8Array(prefix.byteLength + encoded.byteLength);
  output.set(prefix);
  output.set(encoded, prefix.byteLength);
  return output;
}

async function hash(type: RotationHashDomain, encoded: Uint8Array) {
  await sodium.ready;
  const message = preimage(type, encoded);
  try {
    return sodium.crypto_generichash(HASH_BYTES, message, null);
  } finally {
    message.fill(0);
  }
}

async function sign(
  type: RotationType,
  encoded: Uint8Array,
  privateKey: Uint8Array,
) {
  await sodium.ready;
  const message = preimage(type, encoded);
  const key = bytes(privateKey, 64, "signingPrivateKey");
  try {
    return sodium.crypto_sign_detached(message, key);
  } finally {
    message.fill(0);
    key.fill(0);
  }
}

async function verify(
  type: RotationType,
  encoded: Uint8Array,
  signature: Uint8Array,
  publicKey: Uint8Array,
) {
  await sodium.ready;
  const message = preimage(type, encoded);
  try {
    return sodium.crypto_sign_verify_detached(
      bytes(signature, SIGNATURE_BYTES, "signature"),
      message,
      bytes(publicKey, 32, "signingPublicKey"),
    );
  } finally {
    message.fill(0);
  }
}

const checkpointUnsignedFields = [
  "suite",
  "vaultId",
  "type",
  "createdAt",
  "envelopeId",
  "ceremonyId",
  "baseSequence",
  "baseHeadHash",
  "baseEpoch",
  "targetEpoch",
  "manifestObjectId",
  "revisionId",
  "generation",
  "ciphertextHash",
  "liveObjectCount",
  "liveRevisionCount",
  "liveRevisionSetHash",
  "recipientSetHash",
  "controlEntryHash",
  "signerEndpointId",
  "removedEndpointId",
] as const;
const checkpointFields = [...checkpointUnsignedFields, "signature"] as const;
const offerUnsignedFields = [
  "suite",
  "vaultId",
  "type",
  "createdAt",
  "envelopeId",
  "ceremonyId",
  "checkpointHash",
  "eekWrapHash",
  "recipientEndpointId",
  "issuerEndpointId",
  "targetEpoch",
  "expiresAt",
] as const;
const offerFields = [...offerUnsignedFields, "signature"] as const;
const acknowledgementUnsignedFields = [
  "suite",
  "vaultId",
  "type",
  "createdAt",
  "envelopeId",
  "ceremonyId",
  "checkpointHash",
  "eekWrapHash",
  "offerHash",
  "recipientEndpointId",
  "targetEpoch",
] as const;
const acknowledgementFields = [
  ...acknowledgementUnsignedFields,
  "possessionMac",
  "signature",
] as const;
const destructionUnsignedFields = [
  "suite",
  "vaultId",
  "type",
  "createdAt",
  "envelopeId",
  "ceremonyId",
  "checkpointHash",
  "controlEntryHash",
  "endpointId",
  "destroyedEpoch",
  "activatedEpoch",
  "custodyGeneration",
] as const;
const destructionFields = [...destructionUnsignedFields, "signature"] as const;
const completionUnsignedFields = [
  "suite",
  "vaultId",
  "type",
  "createdAt",
  "envelopeId",
  "ceremonyId",
  "checkpointHash",
  "controlEntryHash",
  "hostedReceiptHash",
  "signerEndpointId",
  "committedSequence",
  "committedHeadHash",
  "recipientSetHash",
] as const;
const completionFields = [...completionUnsignedFields, "signature"] as const;

function checkpointMap(value: AncV1UnsignedRotationManifestCheckpoint) {
  exact(value, checkpointUnsignedFields, "Unsigned rotation checkpoint");
  return new Map<number, AncV1CanonicalValue>([
    ...commonMap(value, "rotation-manifest-checkpoint"),
    [CHECKPOINT.ceremonyId, bytes(value.ceremonyId, ID_BYTES, "ceremonyId")],
    [CHECKPOINT.baseSequence, nonnegative(value.baseSequence, "baseSequence")],
    [
      CHECKPOINT.baseHeadHash,
      bytes(value.baseHeadHash, HASH_BYTES, "baseHeadHash"),
    ],
    [CHECKPOINT.baseEpoch, positive(value.baseEpoch, "baseEpoch")],
    [CHECKPOINT.targetEpoch, positive(value.targetEpoch, "targetEpoch")],
    [
      CHECKPOINT.manifestObjectId,
      bytes(value.manifestObjectId, ID_BYTES, "manifestObjectId"),
    ],
    [
      CHECKPOINT.revisionId,
      bytes(value.revisionId, REVISION_ID_BYTES, "revisionId"),
    ],
    [CHECKPOINT.generation, positive(value.generation, "generation")],
    [
      CHECKPOINT.ciphertextHash,
      bytes(value.ciphertextHash, HASH_BYTES, "ciphertextHash"),
    ],
    [
      CHECKPOINT.liveObjectCount,
      boundedCount(value.liveObjectCount, "liveObjectCount"),
    ],
    [
      CHECKPOINT.liveRevisionCount,
      boundedCount(value.liveRevisionCount, "liveRevisionCount"),
    ],
    [
      CHECKPOINT.liveRevisionSetHash,
      bytes(value.liveRevisionSetHash, HASH_BYTES, "liveRevisionSetHash"),
    ],
    [
      CHECKPOINT.recipientSetHash,
      bytes(value.recipientSetHash, HASH_BYTES, "recipientSetHash"),
    ],
    [
      CHECKPOINT.controlEntryHash,
      bytes(value.controlEntryHash, HASH_BYTES, "controlEntryHash"),
    ],
    [
      CHECKPOINT.signerEndpointId,
      bytes(value.signerEndpointId, ID_BYTES, "signerEndpointId"),
    ],
    [
      CHECKPOINT.removedEndpointId,
      bytes(value.removedEndpointId, ID_BYTES, "removedEndpointId"),
    ],
  ]);
}

export function encodeAncV1UnsignedRotationManifestCheckpoint(
  value: AncV1UnsignedRotationManifestCheckpoint,
) {
  return encodeAncV1Canonical(checkpointMap(value));
}

export function encodeAncV1RotationManifestCheckpoint(
  value: AncV1RotationManifestCheckpoint,
) {
  exact(value, checkpointFields, "Rotation checkpoint");
  const { signature, ...unsigned } = value;
  const encoded = encodeAncV1Canonical(
    new Map([
      ...checkpointMap(unsigned),
      [CHECKPOINT.signature, bytes(signature, 64, "signature")],
    ]),
  );
  if (encoded.byteLength > ANC_ROTATION_EVIDENCE_SIZE_LIMITS.checkpointBytes)
    fail("Rotation checkpoint exceeds its size limit");
  return encoded;
}

export async function signAncV1RotationManifestCheckpoint(
  value: AncV1UnsignedRotationManifestCheckpoint,
  privateKey: Uint8Array,
): Promise<AncV1RotationManifestCheckpoint> {
  return {
    ...value,
    signature: await sign(
      "rotation-manifest-checkpoint",
      encodeAncV1UnsignedRotationManifestCheckpoint(value),
      privateKey,
    ),
  };
}

export function decodeAncV1RotationManifestCheckpoint(
  encoded: Uint8Array,
  binding: { readonly expectedVaultId: Uint8Array },
): AncV1RotationManifestCheckpoint {
  exact(binding, ["expectedVaultId"], "Rotation checkpoint binding");
  const map = decodeAncV1Envelope(encoded, checkpointKeys, {
    maxBytes: ANC_ROTATION_EVIDENCE_SIZE_LIMITS.checkpointBytes,
  });
  return {
    ...decodeCommon(
      map,
      "rotation-manifest-checkpoint",
      binding.expectedVaultId,
    ),
    type: "rotation-manifest-checkpoint",
    ceremonyId: bytes(
      field(map, CHECKPOINT.ceremonyId, "ceremonyId"),
      16,
      "ceremonyId",
    ),
    baseSequence: nonnegative(
      field(map, CHECKPOINT.baseSequence, "baseSequence"),
      "baseSequence",
    ),
    baseHeadHash: bytes(
      field(map, CHECKPOINT.baseHeadHash, "baseHeadHash"),
      32,
      "baseHeadHash",
    ),
    baseEpoch: positive(
      field(map, CHECKPOINT.baseEpoch, "baseEpoch"),
      "baseEpoch",
    ),
    targetEpoch: positive(
      field(map, CHECKPOINT.targetEpoch, "targetEpoch"),
      "targetEpoch",
    ),
    manifestObjectId: bytes(
      field(map, CHECKPOINT.manifestObjectId, "manifestObjectId"),
      16,
      "manifestObjectId",
    ),
    revisionId: bytes(
      field(map, CHECKPOINT.revisionId, "revisionId"),
      32,
      "revisionId",
    ),
    generation: positive(
      field(map, CHECKPOINT.generation, "generation"),
      "generation",
    ),
    ciphertextHash: bytes(
      field(map, CHECKPOINT.ciphertextHash, "ciphertextHash"),
      32,
      "ciphertextHash",
    ),
    liveObjectCount: boundedCount(
      field(map, CHECKPOINT.liveObjectCount, "liveObjectCount"),
      "liveObjectCount",
    ),
    liveRevisionCount: boundedCount(
      field(map, CHECKPOINT.liveRevisionCount, "liveRevisionCount"),
      "liveRevisionCount",
    ),
    liveRevisionSetHash: bytes(
      field(map, CHECKPOINT.liveRevisionSetHash, "liveRevisionSetHash"),
      32,
      "liveRevisionSetHash",
    ),
    recipientSetHash: bytes(
      field(map, CHECKPOINT.recipientSetHash, "recipientSetHash"),
      32,
      "recipientSetHash",
    ),
    controlEntryHash: bytes(
      field(map, CHECKPOINT.controlEntryHash, "controlEntryHash"),
      32,
      "controlEntryHash",
    ),
    signerEndpointId: bytes(
      field(map, CHECKPOINT.signerEndpointId, "signerEndpointId"),
      16,
      "signerEndpointId",
    ),
    removedEndpointId: bytes(
      field(map, CHECKPOINT.removedEndpointId, "removedEndpointId"),
      16,
      "removedEndpointId",
    ),
    signature: bytes(
      field(map, CHECKPOINT.signature, "signature"),
      64,
      "signature",
    ),
  };
}

export async function verifyAncV1RotationManifestCheckpoint(
  encoded: Uint8Array,
  binding: {
    readonly expectedVaultId: Uint8Array;
    readonly expectedSignerEndpointId: Uint8Array;
    readonly signerSigningPublicKey: Uint8Array;
  },
) {
  exact(
    binding,
    ["expectedVaultId", "expectedSignerEndpointId", "signerSigningPublicKey"],
    "Rotation checkpoint verification binding",
  );
  const decoded = decodeAncV1RotationManifestCheckpoint(encoded, {
    expectedVaultId: binding.expectedVaultId,
  });
  if (
    decoded.baseEpoch === Number.MAX_SAFE_INTEGER ||
    decoded.targetEpoch !== decoded.baseEpoch + 1 ||
    !same(
      decoded.signerEndpointId,
      bytes(binding.expectedSignerEndpointId, 16, "expectedSignerEndpointId"),
    ) ||
    same(decoded.signerEndpointId, decoded.removedEndpointId) ||
    decoded.liveObjectCount > decoded.liveRevisionCount
  )
    fail("Rotation checkpoint must advance exactly one epoch");
  const { signature, ...unsigned } = decoded;
  if (
    !(await verify(
      "rotation-manifest-checkpoint",
      encodeAncV1UnsignedRotationManifestCheckpoint(unsigned),
      signature,
      binding.signerSigningPublicKey,
    ))
  )
    fail("Rotation checkpoint signature verification failed");
  return decoded;
}

export async function hashAncV1RotationManifestCheckpoint(
  encoded: Uint8Array,
  expectedVaultId: Uint8Array,
) {
  decodeAncV1RotationManifestCheckpoint(encoded, { expectedVaultId });
  return hash("rotation-manifest-checkpoint-hash", encoded.slice());
}

export interface AncV1RotationLiveRevision {
  readonly objectId: Uint8Array;
  readonly revision: number;
  readonly priorRevisionId: Uint8Array;
  readonly rotatedRevisionId: Uint8Array;
}

function hex(value: Uint8Array): string {
  let output = "";
  for (const byte of value) output += byte.toString(16).padStart(2, "0");
  return output;
}

export async function hashAncV1RotationLiveRevisionSet(
  revisions: readonly AncV1RotationLiveRevision[],
): Promise<Uint8Array> {
  if (
    !Array.isArray(revisions) ||
    revisions.length > ANC_ROTATION_EVIDENCE_SIZE_LIMITS.liveRevisions
  )
    fail("Rotation live revision set exceeds its limit");
  const normalized = revisions.map((revision) => {
    exact(
      revision,
      ["objectId", "revision", "priorRevisionId", "rotatedRevisionId"],
      "Rotation live revision",
    );
    return {
      objectId: bytes(revision.objectId, ID_BYTES, "objectId"),
      revision: positive(revision.revision, "revision"),
      priorRevisionId: bytes(
        revision.priorRevisionId,
        REVISION_ID_BYTES,
        "priorRevisionId",
      ),
      rotatedRevisionId: bytes(
        revision.rotatedRevisionId,
        REVISION_ID_BYTES,
        "rotatedRevisionId",
      ),
    };
  });
  normalized.sort((left, right) => {
    for (let index = 0; index < ID_BYTES; index += 1) {
      const difference = left.objectId[index]! - right.objectId[index]!;
      if (difference !== 0) return difference;
    }
    return left.revision - right.revision;
  });
  for (let index = 1; index < normalized.length; index += 1) {
    const left = normalized[index - 1]!;
    const right = normalized[index]!;
    if (same(left.objectId, right.objectId) && left.revision === right.revision)
      fail("Rotation live revision coordinates must be unique");
  }
  const encoded = encodeAncV1Canonical(
    normalized.map((revision) => [
      revision.objectId,
      revision.revision,
      revision.priorRevisionId,
      revision.rotatedRevisionId,
    ]),
  );
  return hash("rotation-live-revision-set-hash", encoded);
}

export async function verifyAncV1RotationLiveRevisionSetAgainstCheckpoint(
  revisions: readonly AncV1RotationLiveRevision[],
  checkpoint: AncV1RotationManifestCheckpoint,
): Promise<void> {
  if (revisions.length !== checkpoint.liveRevisionCount)
    fail("Rotation live revision coverage is incomplete");
  const objects = new Set(revisions.map((revision) => hex(revision.objectId)));
  if (objects.size !== checkpoint.liveObjectCount)
    fail("Rotation live object coverage is incomplete");
  if (
    !same(
      await hashAncV1RotationLiveRevisionSet(revisions),
      checkpoint.liveRevisionSetHash,
    )
  )
    fail("Rotation live revision set does not match the checkpoint");
}

export interface AncV1RotationRecipient {
  readonly endpointId: Uint8Array;
  readonly signingPublicKey: Uint8Array;
  readonly keyAgreementPublicKey: Uint8Array;
  readonly eekWrapHash: Uint8Array;
}

export async function hashAncV1RotationRecipientSet(
  recipients: readonly AncV1RotationRecipient[],
): Promise<Uint8Array> {
  if (
    !Array.isArray(recipients) ||
    recipients.length < 1 ||
    recipients.length > ANC_ROTATION_EVIDENCE_SIZE_LIMITS.acknowledgements
  )
    fail("Rotation recipient set is outside its limit");
  const normalized = recipients.map((recipient) => {
    exact(
      recipient,
      [
        "endpointId",
        "signingPublicKey",
        "keyAgreementPublicKey",
        "eekWrapHash",
      ],
      "Rotation recipient",
    );
    return {
      endpointId: bytes(recipient.endpointId, 16, "endpointId"),
      signingPublicKey: bytes(
        recipient.signingPublicKey,
        32,
        "signingPublicKey",
      ),
      keyAgreementPublicKey: bytes(
        recipient.keyAgreementPublicKey,
        32,
        "keyAgreementPublicKey",
      ),
      eekWrapHash: bytes(recipient.eekWrapHash, 32, "eekWrapHash"),
    };
  });
  normalized.sort((left, right) => {
    for (let index = 0; index < ID_BYTES; index += 1) {
      const difference = left.endpointId[index]! - right.endpointId[index]!;
      if (difference !== 0) return difference;
    }
    return 0;
  });
  for (let index = 1; index < normalized.length; index += 1)
    if (same(normalized[index - 1]!.endpointId, normalized[index]!.endpointId))
      fail("Rotation recipients must be unique");
  const encoded = encodeAncV1Canonical(
    normalized.map((recipient) => [
      recipient.endpointId,
      recipient.signingPublicKey,
      recipient.keyAgreementPublicKey,
      recipient.eekWrapHash,
    ]),
  );
  return hash("rotation-recipient-set-hash", encoded);
}

function offerMap(value: AncV1UnsignedRotationRecipientOffer) {
  exact(value, offerUnsignedFields, "Unsigned rotation offer");
  if (value.expiresAt < value.createdAt) fail("Offer expiry precedes creation");
  return new Map<number, AncV1CanonicalValue>([
    ...commonMap(value, "rotation-recipient-offer"),
    [OFFER.ceremonyId, bytes(value.ceremonyId, 16, "ceremonyId")],
    [OFFER.checkpointHash, bytes(value.checkpointHash, 32, "checkpointHash")],
    [OFFER.eekWrapHash, bytes(value.eekWrapHash, 32, "eekWrapHash")],
    [
      OFFER.recipientEndpointId,
      bytes(value.recipientEndpointId, 16, "recipientEndpointId"),
    ],
    [
      OFFER.issuerEndpointId,
      bytes(value.issuerEndpointId, 16, "issuerEndpointId"),
    ],
    [OFFER.targetEpoch, positive(value.targetEpoch, "targetEpoch")],
    [OFFER.expiresAt, positive(value.expiresAt, "expiresAt")],
  ]);
}

export function encodeAncV1UnsignedRotationRecipientOffer(
  value: AncV1UnsignedRotationRecipientOffer,
) {
  return encodeAncV1Canonical(offerMap(value));
}

export function encodeAncV1RotationRecipientOffer(
  value: AncV1RotationRecipientOffer,
) {
  exact(value, offerFields, "Rotation offer");
  const { signature, ...unsigned } = value;
  const encoded = encodeAncV1Canonical(
    new Map([
      ...offerMap(unsigned),
      [OFFER.signature, bytes(signature, 64, "signature")],
    ]),
  );
  if (encoded.byteLength > ANC_ROTATION_EVIDENCE_SIZE_LIMITS.offerBytes)
    fail("Rotation offer exceeds its size limit");
  return encoded;
}

export async function signAncV1RotationRecipientOffer(
  value: AncV1UnsignedRotationRecipientOffer,
  privateKey: Uint8Array,
): Promise<AncV1RotationRecipientOffer> {
  return {
    ...value,
    signature: await sign(
      "rotation-recipient-offer",
      encodeAncV1UnsignedRotationRecipientOffer(value),
      privateKey,
    ),
  };
}

export function decodeAncV1RotationRecipientOffer(
  encoded: Uint8Array,
  binding: { readonly expectedVaultId: Uint8Array },
): AncV1RotationRecipientOffer {
  exact(binding, ["expectedVaultId"], "Rotation offer binding");
  const map = decodeAncV1Envelope(encoded, offerKeys, {
    maxBytes: ANC_ROTATION_EVIDENCE_SIZE_LIMITS.offerBytes,
  });
  const result: AncV1RotationRecipientOffer = {
    ...decodeCommon(map, "rotation-recipient-offer", binding.expectedVaultId),
    type: "rotation-recipient-offer",
    ceremonyId: bytes(
      field(map, OFFER.ceremonyId, "ceremonyId"),
      16,
      "ceremonyId",
    ),
    checkpointHash: bytes(
      field(map, OFFER.checkpointHash, "checkpointHash"),
      32,
      "checkpointHash",
    ),
    eekWrapHash: bytes(
      field(map, OFFER.eekWrapHash, "eekWrapHash"),
      32,
      "eekWrapHash",
    ),
    recipientEndpointId: bytes(
      field(map, OFFER.recipientEndpointId, "recipientEndpointId"),
      16,
      "recipientEndpointId",
    ),
    issuerEndpointId: bytes(
      field(map, OFFER.issuerEndpointId, "issuerEndpointId"),
      16,
      "issuerEndpointId",
    ),
    targetEpoch: positive(
      field(map, OFFER.targetEpoch, "targetEpoch"),
      "targetEpoch",
    ),
    expiresAt: positive(field(map, OFFER.expiresAt, "expiresAt"), "expiresAt"),
    signature: bytes(field(map, OFFER.signature, "signature"), 64, "signature"),
  };
  if (result.expiresAt < result.createdAt)
    fail("Offer expiry precedes creation");
  return result;
}

export async function verifyAncV1RotationRecipientOffer(
  encoded: Uint8Array,
  binding: {
    readonly expectedVaultId: Uint8Array;
    readonly expectedIssuerEndpointId: Uint8Array;
    readonly expectedRecipientEndpointId: Uint8Array;
    readonly issuerSigningPublicKey: Uint8Array;
    readonly now: number;
  },
): Promise<AncV1RotationRecipientOffer> {
  exact(
    binding,
    [
      "expectedVaultId",
      "expectedIssuerEndpointId",
      "expectedRecipientEndpointId",
      "issuerSigningPublicKey",
      "now",
    ],
    "Rotation offer verification binding",
  );
  const offer = decodeAncV1RotationRecipientOffer(encoded, {
    expectedVaultId: binding.expectedVaultId,
  });
  const { signature, ...unsigned } = offer;
  const now = positive(binding.now, "now");
  if (
    now + ANC_ROTATION_EVIDENCE_SIZE_LIMITS.clockSkewSeconds <
      offer.createdAt ||
    now >
      offer.expiresAt + ANC_ROTATION_EVIDENCE_SIZE_LIMITS.clockSkewSeconds ||
    !same(
      offer.issuerEndpointId,
      bytes(binding.expectedIssuerEndpointId, 16, "expectedIssuerEndpointId"),
    ) ||
    !same(
      offer.recipientEndpointId,
      bytes(
        binding.expectedRecipientEndpointId,
        16,
        "expectedRecipientEndpointId",
      ),
    ) ||
    !(await verify(
      "rotation-recipient-offer",
      encodeAncV1UnsignedRotationRecipientOffer(unsigned),
      signature,
      binding.issuerSigningPublicKey,
    ))
  )
    fail("Rotation offer verification failed");
  return offer;
}

export async function hashAncV1RotationRecipientOffer(
  encoded: Uint8Array,
  expectedVaultId: Uint8Array,
): Promise<Uint8Array> {
  decodeAncV1RotationRecipientOffer(encoded, { expectedVaultId });
  return hash("rotation-recipient-offer-hash", encoded.slice());
}

function acknowledgementMap(
  value: AncV1UnsignedRotationRecipientAcknowledgement,
) {
  exact(
    value,
    acknowledgementUnsignedFields,
    "Unsigned rotation acknowledgement",
  );
  return new Map<number, AncV1CanonicalValue>([
    ...commonMap(value, "rotation-recipient-acknowledgement"),
    [ACK.ceremonyId, bytes(value.ceremonyId, 16, "ceremonyId")],
    [ACK.checkpointHash, bytes(value.checkpointHash, 32, "checkpointHash")],
    [ACK.eekWrapHash, bytes(value.eekWrapHash, 32, "eekWrapHash")],
    [ACK.offerHash, bytes(value.offerHash, 32, "offerHash")],
    [
      ACK.recipientEndpointId,
      bytes(value.recipientEndpointId, 16, "recipientEndpointId"),
    ],
    [ACK.targetEpoch, positive(value.targetEpoch, "targetEpoch")],
  ]);
}

export function encodeAncV1UnsignedRotationRecipientAcknowledgement(
  value: AncV1UnsignedRotationRecipientAcknowledgement,
) {
  return encodeAncV1Canonical(acknowledgementMap(value));
}

async function possessionMac(
  value: AncV1UnsignedRotationRecipientAcknowledgement,
  epochKey: Uint8Array,
) {
  await sodium.ready;
  const message = preimage(
    "rotation-recipient-acknowledgement-mac",
    encodeAncV1UnsignedRotationRecipientAcknowledgement(value),
  );
  const epoch = bytes(epochKey, KEY_BYTES, "epochKey");
  const context = new TextEncoder().encode(
    `${ANC_ROTATION_EVIDENCE_SUITE_ID}/possession-key\0`,
  );
  const key = sodium.crypto_generichash(KEY_BYTES, context, epoch);
  try {
    return sodium.crypto_generichash(HASH_BYTES, message, key);
  } finally {
    message.fill(0);
    epoch.fill(0);
    context.fill(0);
    key.fill(0);
  }
}

export function encodeAncV1RotationRecipientAcknowledgement(
  value: AncV1RotationRecipientAcknowledgement,
) {
  exact(value, acknowledgementFields, "Rotation acknowledgement");
  const { possessionMac: mac, signature, ...unsigned } = value;
  const signedMap = new Map([
    ...acknowledgementMap(unsigned),
    [ACK.possessionMac, bytes(mac, 32, "possessionMac")],
  ]);
  const encoded = encodeAncV1Canonical(
    new Map([...signedMap, [ACK.signature, bytes(signature, 64, "signature")]]),
  );
  if (
    encoded.byteLength > ANC_ROTATION_EVIDENCE_SIZE_LIMITS.acknowledgementBytes
  )
    fail("Rotation acknowledgement exceeds its size limit");
  return encoded;
}

export async function signAncV1RotationRecipientAcknowledgement(
  value: AncV1UnsignedRotationRecipientAcknowledgement,
  input: {
    readonly recipientSigningPrivateKey: Uint8Array;
    readonly pendingEpochKey: Uint8Array;
  },
): Promise<AncV1RotationRecipientAcknowledgement> {
  exact(
    input,
    ["recipientSigningPrivateKey", "pendingEpochKey"],
    "Rotation acknowledgement signing input",
  );
  const mac = await possessionMac(value, input.pendingEpochKey);
  const signaturePreimage = encodeAncV1Canonical(
    new Map([...acknowledgementMap(value), [ACK.possessionMac, mac]]),
  );
  return {
    ...value,
    possessionMac: mac,
    signature: await sign(
      "rotation-recipient-acknowledgement",
      signaturePreimage,
      input.recipientSigningPrivateKey,
    ),
  };
}

export function decodeAncV1RotationRecipientAcknowledgement(
  encoded: Uint8Array,
  binding: { readonly expectedVaultId: Uint8Array },
): AncV1RotationRecipientAcknowledgement {
  exact(binding, ["expectedVaultId"], "Rotation acknowledgement binding");
  const map = decodeAncV1Envelope(encoded, acknowledgementKeys, {
    maxBytes: ANC_ROTATION_EVIDENCE_SIZE_LIMITS.acknowledgementBytes,
  });
  return {
    ...decodeCommon(
      map,
      "rotation-recipient-acknowledgement",
      binding.expectedVaultId,
    ),
    type: "rotation-recipient-acknowledgement",
    ceremonyId: bytes(
      field(map, ACK.ceremonyId, "ceremonyId"),
      16,
      "ceremonyId",
    ),
    checkpointHash: bytes(
      field(map, ACK.checkpointHash, "checkpointHash"),
      32,
      "checkpointHash",
    ),
    eekWrapHash: bytes(
      field(map, ACK.eekWrapHash, "eekWrapHash"),
      32,
      "eekWrapHash",
    ),
    offerHash: bytes(field(map, ACK.offerHash, "offerHash"), 32, "offerHash"),
    recipientEndpointId: bytes(
      field(map, ACK.recipientEndpointId, "recipientEndpointId"),
      16,
      "recipientEndpointId",
    ),
    targetEpoch: positive(
      field(map, ACK.targetEpoch, "targetEpoch"),
      "targetEpoch",
    ),
    possessionMac: bytes(
      field(map, ACK.possessionMac, "possessionMac"),
      32,
      "possessionMac",
    ),
    signature: bytes(field(map, ACK.signature, "signature"), 64, "signature"),
  };
}

export async function verifyAncV1RotationRecipientAcknowledgement(
  encoded: Uint8Array,
  binding: {
    readonly expectedVaultId: Uint8Array;
    readonly recipientSigningPublicKey: Uint8Array;
    readonly pendingEpochKey: Uint8Array;
  },
): Promise<AncV1RotationRecipientAcknowledgement> {
  exact(
    binding,
    ["expectedVaultId", "recipientSigningPublicKey", "pendingEpochKey"],
    "Rotation acknowledgement verification binding",
  );
  const acknowledgement = decodeAncV1RotationRecipientAcknowledgement(encoded, {
    expectedVaultId: binding.expectedVaultId,
  });
  const { possessionMac: mac, signature, ...unsigned } = acknowledgement;
  const expectedMac = await possessionMac(unsigned, binding.pendingEpochKey);
  const signaturePreimage = encodeAncV1Canonical(
    new Map([...acknowledgementMap(unsigned), [ACK.possessionMac, mac]]),
  );
  if (
    !same(mac, expectedMac) ||
    !(await verify(
      "rotation-recipient-acknowledgement",
      signaturePreimage,
      signature,
      binding.recipientSigningPublicKey,
    ))
  )
    fail("Rotation acknowledgement verification failed");
  return acknowledgement;
}

function destructionMap(
  value: AncV1UnsignedRotationEpochDestructionAttestation,
) {
  exact(value, destructionUnsignedFields, "Unsigned destruction attestation");
  return new Map<number, AncV1CanonicalValue>([
    ...commonMap(value, "rotation-epoch-destruction-attestation"),
    [DESTRUCTION.ceremonyId, bytes(value.ceremonyId, 16, "ceremonyId")],
    [
      DESTRUCTION.checkpointHash,
      bytes(value.checkpointHash, 32, "checkpointHash"),
    ],
    [
      DESTRUCTION.controlEntryHash,
      bytes(value.controlEntryHash, 32, "controlEntryHash"),
    ],
    [DESTRUCTION.endpointId, bytes(value.endpointId, 16, "endpointId")],
    [
      DESTRUCTION.destroyedEpoch,
      positive(value.destroyedEpoch, "destroyedEpoch"),
    ],
    [
      DESTRUCTION.activatedEpoch,
      positive(value.activatedEpoch, "activatedEpoch"),
    ],
    [
      DESTRUCTION.custodyGeneration,
      positive(value.custodyGeneration, "custodyGeneration"),
    ],
  ]);
}

export function encodeAncV1UnsignedRotationEpochDestructionAttestation(
  value: AncV1UnsignedRotationEpochDestructionAttestation,
) {
  return encodeAncV1Canonical(destructionMap(value));
}

export function encodeAncV1RotationEpochDestructionAttestation(
  value: AncV1RotationEpochDestructionAttestation,
) {
  exact(value, destructionFields, "Rotation destruction attestation");
  const { signature, ...unsigned } = value;
  const encoded = encodeAncV1Canonical(
    new Map([
      ...destructionMap(unsigned),
      [DESTRUCTION.signature, bytes(signature, 64, "signature")],
    ]),
  );
  if (encoded.byteLength > ANC_ROTATION_EVIDENCE_SIZE_LIMITS.destructionBytes)
    fail("Rotation destruction attestation exceeds its size limit");
  return encoded;
}

export async function signAncV1RotationEpochDestructionAttestation(
  value: AncV1UnsignedRotationEpochDestructionAttestation,
  privateKey: Uint8Array,
): Promise<AncV1RotationEpochDestructionAttestation> {
  return {
    ...value,
    signature: await sign(
      "rotation-epoch-destruction-attestation",
      encodeAncV1UnsignedRotationEpochDestructionAttestation(value),
      privateKey,
    ),
  };
}

export function decodeAncV1RotationEpochDestructionAttestation(
  encoded: Uint8Array,
  binding: { readonly expectedVaultId: Uint8Array },
): AncV1RotationEpochDestructionAttestation {
  exact(binding, ["expectedVaultId"], "Destruction attestation binding");
  const map = decodeAncV1Envelope(encoded, destructionKeys, {
    maxBytes: ANC_ROTATION_EVIDENCE_SIZE_LIMITS.destructionBytes,
  });
  return {
    ...decodeCommon(
      map,
      "rotation-epoch-destruction-attestation",
      binding.expectedVaultId,
    ),
    type: "rotation-epoch-destruction-attestation",
    ceremonyId: bytes(
      field(map, DESTRUCTION.ceremonyId, "ceremonyId"),
      16,
      "ceremonyId",
    ),
    checkpointHash: bytes(
      field(map, DESTRUCTION.checkpointHash, "checkpointHash"),
      32,
      "checkpointHash",
    ),
    controlEntryHash: bytes(
      field(map, DESTRUCTION.controlEntryHash, "controlEntryHash"),
      32,
      "controlEntryHash",
    ),
    endpointId: bytes(
      field(map, DESTRUCTION.endpointId, "endpointId"),
      16,
      "endpointId",
    ),
    destroyedEpoch: positive(
      field(map, DESTRUCTION.destroyedEpoch, "destroyedEpoch"),
      "destroyedEpoch",
    ),
    activatedEpoch: positive(
      field(map, DESTRUCTION.activatedEpoch, "activatedEpoch"),
      "activatedEpoch",
    ),
    custodyGeneration: positive(
      field(map, DESTRUCTION.custodyGeneration, "custodyGeneration"),
      "custodyGeneration",
    ),
    signature: bytes(
      field(map, DESTRUCTION.signature, "signature"),
      64,
      "signature",
    ),
  };
}

export async function verifyAncV1RotationEpochDestructionAttestation(
  encoded: Uint8Array,
  binding: {
    readonly expectedVaultId: Uint8Array;
    readonly expectedEndpointId: Uint8Array;
    readonly endpointSigningPublicKey: Uint8Array;
  },
): Promise<AncV1RotationEpochDestructionAttestation> {
  exact(
    binding,
    ["expectedVaultId", "expectedEndpointId", "endpointSigningPublicKey"],
    "Destruction attestation verification binding",
  );
  const decoded = decodeAncV1RotationEpochDestructionAttestation(encoded, {
    expectedVaultId: binding.expectedVaultId,
  });
  const { signature, ...unsigned } = decoded;
  if (
    !same(
      decoded.endpointId,
      bytes(binding.expectedEndpointId, 16, "expectedEndpointId"),
    ) ||
    !(await verify(
      "rotation-epoch-destruction-attestation",
      encodeAncV1UnsignedRotationEpochDestructionAttestation(unsigned),
      signature,
      binding.endpointSigningPublicKey,
    ))
  )
    fail("Rotation destruction attestation verification failed");
  return decoded;
}

function completionMap(value: AncV1UnsignedRotationControlCommitAttestation) {
  exact(value, completionUnsignedFields, "Unsigned control commit attestation");
  return new Map<number, AncV1CanonicalValue>([
    ...commonMap(value, "rotation-control-commit-attestation"),
    [COMPLETION.ceremonyId, bytes(value.ceremonyId, 16, "ceremonyId")],
    [
      COMPLETION.checkpointHash,
      bytes(value.checkpointHash, 32, "checkpointHash"),
    ],
    [
      COMPLETION.controlEntryHash,
      bytes(value.controlEntryHash, 32, "controlEntryHash"),
    ],
    [
      COMPLETION.hostedReceiptHash,
      bytes(value.hostedReceiptHash, 32, "hostedReceiptHash"),
    ],
    [
      COMPLETION.signerEndpointId,
      bytes(value.signerEndpointId, 16, "signerEndpointId"),
    ],
    [
      COMPLETION.committedSequence,
      positive(value.committedSequence, "committedSequence"),
    ],
    [
      COMPLETION.committedHeadHash,
      bytes(value.committedHeadHash, 32, "committedHeadHash"),
    ],
    [
      COMPLETION.recipientSetHash,
      bytes(value.recipientSetHash, 32, "recipientSetHash"),
    ],
  ]);
}

export function encodeAncV1UnsignedRotationControlCommitAttestation(
  value: AncV1UnsignedRotationControlCommitAttestation,
) {
  return encodeAncV1Canonical(completionMap(value));
}

export function encodeAncV1RotationControlCommitAttestation(
  value: AncV1RotationControlCommitAttestation,
) {
  exact(value, completionFields, "Rotation control commit attestation");
  const { signature, ...unsigned } = value;
  const encoded = encodeAncV1Canonical(
    new Map([
      ...completionMap(unsigned),
      [COMPLETION.signature, bytes(signature, 64, "signature")],
    ]),
  );
  if (encoded.byteLength > ANC_ROTATION_EVIDENCE_SIZE_LIMITS.completionBytes)
    fail("Rotation control commit attestation exceeds its size limit");
  return encoded;
}

export async function signAncV1RotationControlCommitAttestation(
  value: AncV1UnsignedRotationControlCommitAttestation,
  privateKey: Uint8Array,
): Promise<AncV1RotationControlCommitAttestation> {
  return {
    ...value,
    signature: await sign(
      "rotation-control-commit-attestation",
      encodeAncV1UnsignedRotationControlCommitAttestation(value),
      privateKey,
    ),
  };
}

export function decodeAncV1RotationControlCommitAttestation(
  encoded: Uint8Array,
  binding: { readonly expectedVaultId: Uint8Array },
): AncV1RotationControlCommitAttestation {
  exact(binding, ["expectedVaultId"], "Control commit attestation binding");
  const map = decodeAncV1Envelope(encoded, completionKeys, {
    maxBytes: ANC_ROTATION_EVIDENCE_SIZE_LIMITS.completionBytes,
  });
  return {
    ...decodeCommon(
      map,
      "rotation-control-commit-attestation",
      binding.expectedVaultId,
    ),
    type: "rotation-control-commit-attestation",
    ceremonyId: bytes(
      field(map, COMPLETION.ceremonyId, "ceremonyId"),
      16,
      "ceremonyId",
    ),
    checkpointHash: bytes(
      field(map, COMPLETION.checkpointHash, "checkpointHash"),
      32,
      "checkpointHash",
    ),
    controlEntryHash: bytes(
      field(map, COMPLETION.controlEntryHash, "controlEntryHash"),
      32,
      "controlEntryHash",
    ),
    hostedReceiptHash: bytes(
      field(map, COMPLETION.hostedReceiptHash, "hostedReceiptHash"),
      32,
      "hostedReceiptHash",
    ),
    signerEndpointId: bytes(
      field(map, COMPLETION.signerEndpointId, "signerEndpointId"),
      16,
      "signerEndpointId",
    ),
    committedSequence: positive(
      field(map, COMPLETION.committedSequence, "committedSequence"),
      "committedSequence",
    ),
    committedHeadHash: bytes(
      field(map, COMPLETION.committedHeadHash, "committedHeadHash"),
      32,
      "committedHeadHash",
    ),
    recipientSetHash: bytes(
      field(map, COMPLETION.recipientSetHash, "recipientSetHash"),
      32,
      "recipientSetHash",
    ),
    signature: bytes(
      field(map, COMPLETION.signature, "signature"),
      64,
      "signature",
    ),
  };
}

export async function hashAncV1RotationHostedReceipt(
  encodedReceipt: Uint8Array,
): Promise<Uint8Array> {
  if (
    !(encodedReceipt instanceof Uint8Array) ||
    encodedReceipt.byteLength < 1 ||
    encodedReceipt.byteLength > 1_024
  )
    fail("Rotation hosted receipt is outside its limit");
  decodeAncV1ControlLogRotationAppendReceipt(encodedReceipt);
  return hash("rotation-hosted-receipt-hash", encodedReceipt.slice());
}

export async function verifyAncV1RotationControlCommitAttestation(
  encoded: Uint8Array,
  binding: {
    readonly expectedVaultId: Uint8Array;
    readonly expectedSignerEndpointId: Uint8Array;
    readonly signerSigningPublicKey: Uint8Array;
    readonly expectedHostedReceiptHash: Uint8Array;
  },
): Promise<AncV1RotationControlCommitAttestation> {
  exact(
    binding,
    [
      "expectedVaultId",
      "expectedSignerEndpointId",
      "signerSigningPublicKey",
      "expectedHostedReceiptHash",
    ],
    "Control commit attestation verification binding",
  );
  const decoded = decodeAncV1RotationControlCommitAttestation(encoded, {
    expectedVaultId: binding.expectedVaultId,
  });
  const { signature, ...unsigned } = decoded;
  if (
    !same(
      decoded.signerEndpointId,
      bytes(binding.expectedSignerEndpointId, 16, "expectedSignerEndpointId"),
    ) ||
    !same(
      decoded.hostedReceiptHash,
      bytes(binding.expectedHostedReceiptHash, 32, "expectedHostedReceiptHash"),
    ) ||
    !(await verify(
      "rotation-control-commit-attestation",
      encodeAncV1UnsignedRotationControlCommitAttestation(unsigned),
      signature,
      binding.signerSigningPublicKey,
    ))
  )
    fail("Rotation control commit attestation verification failed");
  return decoded;
}

/** Component verification only; this does not establish rotation completion. */
export async function verifyAncV1RotationAcknowledgementSet(input: {
  readonly encodedAcknowledgements: readonly Uint8Array[];
  readonly encodedCheckpoint: Uint8Array;
  readonly expectedVaultId: Uint8Array;
  readonly expectedSignerEndpointId: Uint8Array;
  readonly signerSigningPublicKey: Uint8Array;
  readonly expectedRecipients: readonly (AncV1RotationRecipient & {
    readonly encodedOffer: Uint8Array;
  })[];
  readonly pendingEpochKey: Uint8Array;
  readonly now: number;
}): Promise<readonly AncV1RotationRecipientAcknowledgement[]> {
  exact(
    input,
    [
      "encodedAcknowledgements",
      "encodedCheckpoint",
      "expectedVaultId",
      "expectedSignerEndpointId",
      "signerSigningPublicKey",
      "expectedRecipients",
      "pendingEpochKey",
      "now",
    ],
    "Rotation acknowledgement set input",
  );
  if (
    input.expectedRecipients.length < 1 ||
    input.expectedRecipients.length >
      ANC_ROTATION_EVIDENCE_SIZE_LIMITS.acknowledgements ||
    input.encodedAcknowledgements.length !== input.expectedRecipients.length
  )
    fail("Rotation acknowledgement coverage is incomplete");
  const checkpoint = await verifyAncV1RotationManifestCheckpoint(
    input.encodedCheckpoint,
    {
      expectedVaultId: input.expectedVaultId,
      expectedSignerEndpointId: input.expectedSignerEndpointId,
      signerSigningPublicKey: input.signerSigningPublicKey,
    },
  );
  const checkpointHash = await hashAncV1RotationManifestCheckpoint(
    input.encodedCheckpoint,
    input.expectedVaultId,
  );
  const recipientSet = input.expectedRecipients.map((recipient) => {
    exact(
      recipient,
      [
        "endpointId",
        "signingPublicKey",
        "keyAgreementPublicKey",
        "eekWrapHash",
        "encodedOffer",
      ],
      "Rotation recipient evidence",
    );
    return {
      endpointId: recipient.endpointId,
      signingPublicKey: recipient.signingPublicKey,
      keyAgreementPublicKey: recipient.keyAgreementPublicKey,
      eekWrapHash: recipient.eekWrapHash,
    };
  });
  if (
    !same(
      await hashAncV1RotationRecipientSet(recipientSet),
      checkpoint.recipientSetHash,
    ) ||
    recipientSet.some((recipient) =>
      same(recipient.endpointId, checkpoint.removedEndpointId),
    ) ||
    !recipientSet.some(
      (recipient) =>
        same(recipient.endpointId, checkpoint.signerEndpointId) &&
        same(recipient.signingPublicKey, input.signerSigningPublicKey),
    )
  )
    fail("Rotation recipient set does not match the signed checkpoint");
  const recipients = new Map(
    await Promise.all(
      input.expectedRecipients.map(async (recipient) => {
        const offer = await verifyAncV1RotationRecipientOffer(
          recipient.encodedOffer,
          {
            expectedVaultId: input.expectedVaultId,
            expectedIssuerEndpointId: checkpoint.signerEndpointId,
            expectedRecipientEndpointId: recipient.endpointId,
            issuerSigningPublicKey: input.signerSigningPublicKey,
            now: input.now,
          },
        );
        const offerHash = await hashAncV1RotationRecipientOffer(
          recipient.encodedOffer,
          input.expectedVaultId,
        );
        if (
          !same(offer.ceremonyId, checkpoint.ceremonyId) ||
          !same(offer.checkpointHash, checkpointHash) ||
          !same(offer.eekWrapHash, recipient.eekWrapHash) ||
          offer.targetEpoch !== checkpoint.targetEpoch
        )
          fail("Rotation recipient offer does not match the checkpoint");
        return [
          hex(bytes(recipient.endpointId, 16, "recipient endpointId")),
          { ...recipient, offer, offerHash },
        ] as const;
      }),
    ),
  );
  if (recipients.size !== input.expectedRecipients.length)
    fail("Rotation recipients must be unique");
  const seen = new Set<string>();
  const verified: AncV1RotationRecipientAcknowledgement[] = [];
  for (const encoded of input.encodedAcknowledgements) {
    const decoded = decodeAncV1RotationRecipientAcknowledgement(encoded, {
      expectedVaultId: input.expectedVaultId,
    });
    const id = hex(decoded.recipientEndpointId);
    const recipient = recipients.get(id);
    if (
      !recipient ||
      seen.has(id) ||
      !same(decoded.ceremonyId, checkpoint.ceremonyId) ||
      !same(decoded.checkpointHash, checkpointHash) ||
      decoded.targetEpoch !== checkpoint.targetEpoch ||
      !same(decoded.eekWrapHash, recipient.eekWrapHash) ||
      !same(decoded.offerHash, recipient.offerHash) ||
      decoded.createdAt + ANC_ROTATION_EVIDENCE_SIZE_LIMITS.clockSkewSeconds <
        recipient.offer.createdAt ||
      decoded.createdAt >
        recipient.offer.expiresAt +
          ANC_ROTATION_EVIDENCE_SIZE_LIMITS.clockSkewSeconds ||
      decoded.createdAt >
        positive(input.now, "now") +
          ANC_ROTATION_EVIDENCE_SIZE_LIMITS.clockSkewSeconds
    )
      fail("Rotation acknowledgement set is not bound to the ceremony");
    verified.push(
      await verifyAncV1RotationRecipientAcknowledgement(encoded, {
        expectedVaultId: input.expectedVaultId,
        recipientSigningPublicKey: recipient.signingPublicKey,
        pendingEpochKey: input.pendingEpochKey,
      }),
    );
    seen.add(id);
  }
  return Object.freeze(verified);
}

/** Component verification only; this does not establish rotation completion. */
export async function verifyAncV1RotationDestructionSet(input: {
  readonly encodedAttestations: readonly Uint8Array[];
  readonly encodedCheckpoint: Uint8Array;
  readonly expectedVaultId: Uint8Array;
  readonly expectedSignerEndpointId: Uint8Array;
  readonly signerSigningPublicKey: Uint8Array;
  readonly expectedRecipients: readonly AncV1RotationRecipient[];
  readonly now: number;
}): Promise<readonly AncV1RotationEpochDestructionAttestation[]> {
  exact(
    input,
    [
      "encodedAttestations",
      "encodedCheckpoint",
      "expectedVaultId",
      "expectedSignerEndpointId",
      "signerSigningPublicKey",
      "expectedRecipients",
      "now",
    ],
    "Rotation destruction set input",
  );
  if (
    input.expectedRecipients.length < 1 ||
    input.expectedRecipients.length >
      ANC_ROTATION_EVIDENCE_SIZE_LIMITS.acknowledgements ||
    input.encodedAttestations.length !== input.expectedRecipients.length
  )
    fail("Rotation destruction coverage is incomplete");
  const checkpoint = await verifyAncV1RotationManifestCheckpoint(
    input.encodedCheckpoint,
    {
      expectedVaultId: input.expectedVaultId,
      expectedSignerEndpointId: input.expectedSignerEndpointId,
      signerSigningPublicKey: input.signerSigningPublicKey,
    },
  );
  const checkpointHash = await hashAncV1RotationManifestCheckpoint(
    input.encodedCheckpoint,
    input.expectedVaultId,
  );
  if (
    !same(
      await hashAncV1RotationRecipientSet(input.expectedRecipients),
      checkpoint.recipientSetHash,
    ) ||
    input.expectedRecipients.some((recipient) =>
      same(recipient.endpointId, checkpoint.removedEndpointId),
    )
  )
    fail("Rotation destruction roster does not match the checkpoint");
  const recipients = new Map(
    input.expectedRecipients.map((recipient) => [
      hex(recipient.endpointId),
      recipient,
    ]),
  );
  if (recipients.size !== input.expectedRecipients.length)
    fail("Rotation destruction recipients must be unique");
  const seen = new Set<string>();
  const verified: AncV1RotationEpochDestructionAttestation[] = [];
  for (const encoded of input.encodedAttestations) {
    const decoded = decodeAncV1RotationEpochDestructionAttestation(encoded, {
      expectedVaultId: input.expectedVaultId,
    });
    const id = hex(decoded.endpointId);
    const recipient = recipients.get(id);
    if (
      !recipient ||
      seen.has(id) ||
      !same(decoded.ceremonyId, checkpoint.ceremonyId) ||
      !same(decoded.checkpointHash, checkpointHash) ||
      !same(decoded.controlEntryHash, checkpoint.controlEntryHash) ||
      decoded.destroyedEpoch !== checkpoint.baseEpoch ||
      decoded.activatedEpoch !== checkpoint.targetEpoch ||
      decoded.createdAt >
        positive(input.now, "now") +
          ANC_ROTATION_EVIDENCE_SIZE_LIMITS.clockSkewSeconds
    )
      fail("Rotation destruction set is not bound to the ceremony");
    verified.push(
      await verifyAncV1RotationEpochDestructionAttestation(encoded, {
        expectedVaultId: input.expectedVaultId,
        expectedEndpointId: recipient.endpointId,
        endpointSigningPublicKey: recipient.signingPublicKey,
      }),
    );
    seen.add(id);
  }
  return Object.freeze(verified);
}

/**
 * Component verification only. Callers deciding success or publication must
 * use verifyAncV1CompletedRotationEvidence so notBefore comes from verified
 * acknowledgement and destruction evidence rather than caller assertion.
 */
export async function verifyAncV1RotationCommittedCompletion(input: {
  readonly encodedCompletion: Uint8Array;
  readonly encodedCheckpoint: Uint8Array;
  readonly encodedHostedReceipt: Uint8Array;
  readonly expectedHostedEntryId: string;
  readonly expectedHostedVaultId: string;
  readonly expectedRecoveryWrapHash: Uint8Array;
  readonly expectedRecoveryWrapByteLength: number;
  readonly expectedVaultId: Uint8Array;
  readonly expectedSignerEndpointId: Uint8Array;
  readonly signerSigningPublicKey: Uint8Array;
  readonly notBefore: number;
  readonly now: number;
}): Promise<AncV1RotationControlCommitAttestation> {
  exact(
    input,
    [
      "encodedCompletion",
      "encodedCheckpoint",
      "encodedHostedReceipt",
      "expectedHostedEntryId",
      "expectedHostedVaultId",
      "expectedRecoveryWrapHash",
      "expectedRecoveryWrapByteLength",
      "expectedVaultId",
      "expectedSignerEndpointId",
      "signerSigningPublicKey",
      "notBefore",
      "now",
    ],
    "Rotation committed completion input",
  );
  const checkpoint = await verifyAncV1RotationManifestCheckpoint(
    input.encodedCheckpoint,
    {
      expectedVaultId: input.expectedVaultId,
      expectedSignerEndpointId: input.expectedSignerEndpointId,
      signerSigningPublicKey: input.signerSigningPublicKey,
    },
  );
  const checkpointHash = await hashAncV1RotationManifestCheckpoint(
    input.encodedCheckpoint,
    input.expectedVaultId,
  );
  const receipt = decodeAncV1ControlLogRotationAppendReceipt(
    input.encodedHostedReceipt,
  );
  const receiptHash = await hashAncV1RotationHostedReceipt(
    input.encodedHostedReceipt,
  );
  const completion = await verifyAncV1RotationControlCommitAttestation(
    input.encodedCompletion,
    {
      expectedVaultId: input.expectedVaultId,
      expectedSignerEndpointId: input.expectedSignerEndpointId,
      signerSigningPublicKey: input.signerSigningPublicKey,
      expectedHostedReceiptHash: receiptHash,
    },
  );
  const notBefore = positive(input.notBefore, "notBefore");
  const now = positive(input.now, "now");
  if (
    !same(completion.ceremonyId, checkpoint.ceremonyId) ||
    !same(completion.checkpointHash, checkpointHash) ||
    !same(completion.controlEntryHash, checkpoint.controlEntryHash) ||
    !same(completion.committedHeadHash, checkpoint.controlEntryHash) ||
    !same(completion.recipientSetHash, checkpoint.recipientSetHash) ||
    receipt.vaultId !== input.expectedHostedVaultId ||
    receipt.entryId !== input.expectedHostedEntryId ||
    receipt.sequence !== checkpoint.baseSequence + 1 ||
    receipt.headHash !== hex(checkpoint.controlEntryHash) ||
    receipt.recoveryWrapHash !==
      hex(
        bytes(input.expectedRecoveryWrapHash, 32, "expectedRecoveryWrapHash"),
      ) ||
    receipt.recoveryWrapByteLength !==
      positive(
        input.expectedRecoveryWrapByteLength,
        "expectedRecoveryWrapByteLength",
      ) ||
    checkpoint.baseSequence === Number.MAX_SAFE_INTEGER ||
    completion.committedSequence !== checkpoint.baseSequence + 1 ||
    completion.createdAt + ANC_ROTATION_EVIDENCE_SIZE_LIMITS.clockSkewSeconds <
      notBefore ||
    completion.createdAt >
      now + ANC_ROTATION_EVIDENCE_SIZE_LIMITS.clockSkewSeconds
  )
    fail("Rotation completion is not bound to committed ceremony evidence");
  return completion;
}

export interface AncV1CompletedRotationEvidence {
  readonly acknowledgements: readonly AncV1RotationRecipientAcknowledgement[];
  readonly destructions: readonly AncV1RotationEpochDestructionAttestation[];
  readonly completion: AncV1RotationControlCommitAttestation;
}

/**
 * The sole success predicate for a completed attended rotation. The caller must
 * not publish a new live manifest or report endpoint removal until this verifier
 * accepts the complete, canonical evidence bundle.
 */
export async function verifyAncV1CompletedRotationEvidence(input: {
  readonly encodedAcknowledgements: readonly Uint8Array[];
  readonly encodedDestructions: readonly Uint8Array[];
  readonly encodedCompletion: Uint8Array;
  readonly encodedCheckpoint: Uint8Array;
  readonly encodedHostedReceipt: Uint8Array;
  readonly expectedHostedEntryId: string;
  readonly expectedHostedVaultId: string;
  readonly expectedRecoveryWrapHash: Uint8Array;
  readonly expectedRecoveryWrapByteLength: number;
  readonly expectedVaultId: Uint8Array;
  readonly expectedSignerEndpointId: Uint8Array;
  readonly signerSigningPublicKey: Uint8Array;
  readonly expectedRecipients: readonly (AncV1RotationRecipient & {
    readonly encodedOffer: Uint8Array;
  })[];
  readonly pendingEpochKey: Uint8Array;
  readonly now: number;
}): Promise<AncV1CompletedRotationEvidence> {
  exact(
    input,
    [
      "encodedAcknowledgements",
      "encodedDestructions",
      "encodedCompletion",
      "encodedCheckpoint",
      "encodedHostedReceipt",
      "expectedHostedEntryId",
      "expectedHostedVaultId",
      "expectedRecoveryWrapHash",
      "expectedRecoveryWrapByteLength",
      "expectedVaultId",
      "expectedSignerEndpointId",
      "signerSigningPublicKey",
      "expectedRecipients",
      "pendingEpochKey",
      "now",
    ],
    "Completed rotation evidence input",
  );
  if (
    !Array.isArray(input.expectedRecipients) ||
    input.expectedRecipients.length < 1 ||
    !Array.isArray(input.encodedAcknowledgements) ||
    !Array.isArray(input.encodedDestructions) ||
    input.encodedAcknowledgements.length !== input.expectedRecipients.length ||
    input.encodedDestructions.length !== input.expectedRecipients.length
  )
    fail("Completed rotation evidence requires full non-empty coverage");
  const acknowledgements = await verifyAncV1RotationAcknowledgementSet({
    encodedAcknowledgements: input.encodedAcknowledgements,
    encodedCheckpoint: input.encodedCheckpoint,
    expectedVaultId: input.expectedVaultId,
    expectedSignerEndpointId: input.expectedSignerEndpointId,
    signerSigningPublicKey: input.signerSigningPublicKey,
    expectedRecipients: input.expectedRecipients,
    pendingEpochKey: input.pendingEpochKey,
    now: input.now,
  });
  const recipients = input.expectedRecipients.map((recipient) => ({
    endpointId: recipient.endpointId,
    signingPublicKey: recipient.signingPublicKey,
    keyAgreementPublicKey: recipient.keyAgreementPublicKey,
    eekWrapHash: recipient.eekWrapHash,
  }));
  const destructions = await verifyAncV1RotationDestructionSet({
    encodedAttestations: input.encodedDestructions,
    encodedCheckpoint: input.encodedCheckpoint,
    expectedVaultId: input.expectedVaultId,
    expectedSignerEndpointId: input.expectedSignerEndpointId,
    signerSigningPublicKey: input.signerSigningPublicKey,
    expectedRecipients: recipients,
    now: input.now,
  });
  const notBefore = Math.max(
    ...acknowledgements.map((value) => value.createdAt),
    ...destructions.map((value) => value.createdAt),
  );
  const completion = await verifyAncV1RotationCommittedCompletion({
    encodedCompletion: input.encodedCompletion,
    encodedCheckpoint: input.encodedCheckpoint,
    encodedHostedReceipt: input.encodedHostedReceipt,
    expectedHostedEntryId: input.expectedHostedEntryId,
    expectedHostedVaultId: input.expectedHostedVaultId,
    expectedRecoveryWrapHash: input.expectedRecoveryWrapHash,
    expectedRecoveryWrapByteLength: input.expectedRecoveryWrapByteLength,
    expectedVaultId: input.expectedVaultId,
    expectedSignerEndpointId: input.expectedSignerEndpointId,
    signerSigningPublicKey: input.signerSigningPublicKey,
    notBefore,
    now: input.now,
  });
  return Object.freeze({ acknowledgements, destructions, completion });
}
