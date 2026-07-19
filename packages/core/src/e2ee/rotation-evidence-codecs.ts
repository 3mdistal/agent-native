import sodium from "libsodium-wrappers-sumo";

import {
  type AncV1CanonicalValue,
  decodeAncV1Envelope,
  encodeAncV1Canonical,
} from "./canonical.js";
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
  }),
});
export const ANC_ROTATION_EVIDENCE_SIZE_LIMITS = Object.freeze({
  checkpointBytes: 1_024,
  offerBytes: 1_024,
  acknowledgementBytes: 1_024,
  acknowledgements: 64,
});

const CHECKPOINT = ANC_ROTATION_EVIDENCE_FIELDS.checkpoint;
const OFFER = ANC_ROTATION_EVIDENCE_FIELDS.offer;
const ACK = ANC_ROTATION_EVIDENCE_FIELDS.acknowledgement;
const ID_BYTES = 16;
const HASH_BYTES = 32;
const REVISION_ID_BYTES = 32;
const SIGNATURE_BYTES = 64;
const KEY_BYTES = 32;

type RotationType =
  | "rotation-manifest-checkpoint"
  | "rotation-recipient-offer"
  | "rotation-recipient-acknowledgement";
type RotationDomain = RotationType | "rotation-live-revision-set";

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
  readonly recipientEndpointId: Uint8Array;
  readonly targetEpoch: number;
}

export interface AncV1RotationRecipientAcknowledgement extends AncV1UnsignedRotationRecipientAcknowledgement {
  readonly possessionMac: Uint8Array;
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

async function hash(type: RotationDomain, encoded: Uint8Array) {
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
  try {
    return sodium.crypto_sign_detached(
      message,
      bytes(privateKey, 64, "signingPrivateKey"),
    );
  } finally {
    message.fill(0);
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
  "recipientEndpointId",
  "targetEpoch",
] as const;
const acknowledgementFields = [
  ...acknowledgementUnsignedFields,
  "possessionMac",
  "signature",
] as const;

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
      nonnegative(value.liveObjectCount, "liveObjectCount"),
    ],
    [
      CHECKPOINT.liveRevisionCount,
      nonnegative(value.liveRevisionCount, "liveRevisionCount"),
    ],
    [
      CHECKPOINT.liveRevisionSetHash,
      bytes(value.liveRevisionSetHash, HASH_BYTES, "liveRevisionSetHash"),
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
    liveObjectCount: nonnegative(
      field(map, CHECKPOINT.liveObjectCount, "liveObjectCount"),
      "liveObjectCount",
    ),
    liveRevisionCount: nonnegative(
      field(map, CHECKPOINT.liveRevisionCount, "liveRevisionCount"),
      "liveRevisionCount",
    ),
    liveRevisionSetHash: bytes(
      field(map, CHECKPOINT.liveRevisionSetHash, "liveRevisionSetHash"),
      32,
      "liveRevisionSetHash",
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
    readonly signerSigningPublicKey: Uint8Array;
  },
) {
  exact(
    binding,
    ["expectedVaultId", "signerSigningPublicKey"],
    "Rotation checkpoint verification binding",
  );
  const decoded = decodeAncV1RotationManifestCheckpoint(encoded, {
    expectedVaultId: binding.expectedVaultId,
  });
  if (
    decoded.baseEpoch === Number.MAX_SAFE_INTEGER ||
    decoded.targetEpoch !== decoded.baseEpoch + 1
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
  return hash("rotation-manifest-checkpoint", encoded.slice());
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
  if (!Array.isArray(revisions) || revisions.length > 10_000)
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
    const coordinate = hex(left.objectId).localeCompare(hex(right.objectId));
    return coordinate || left.revision - right.revision;
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
  return hash("rotation-live-revision-set", encoded);
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
    readonly issuerSigningPublicKey: Uint8Array;
    readonly now: number;
  },
): Promise<AncV1RotationRecipientOffer> {
  exact(
    binding,
    ["expectedVaultId", "issuerSigningPublicKey", "now"],
    "Rotation offer verification binding",
  );
  const offer = decodeAncV1RotationRecipientOffer(encoded, {
    expectedVaultId: binding.expectedVaultId,
  });
  const { signature, ...unsigned } = offer;
  if (
    positive(binding.now, "now") < offer.createdAt ||
    binding.now > offer.expiresAt ||
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
    "rotation-recipient-acknowledgement",
    encodeAncV1UnsignedRotationRecipientAcknowledgement(value),
  );
  const key = bytes(epochKey, KEY_BYTES, "epochKey");
  try {
    return sodium.crypto_generichash(HASH_BYTES, message, key);
  } finally {
    message.fill(0);
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

export async function verifyAncV1RotationAcknowledgementSet(input: {
  readonly encodedAcknowledgements: readonly Uint8Array[];
  readonly expectedVaultId: Uint8Array;
  readonly expectedCeremonyId: Uint8Array;
  readonly expectedCheckpointHash: Uint8Array;
  readonly expectedTargetEpoch: number;
  readonly expectedRecipients: readonly {
    readonly endpointId: Uint8Array;
    readonly signingPublicKey: Uint8Array;
    readonly eekWrapHash: Uint8Array;
  }[];
  readonly pendingEpochKey: Uint8Array;
}): Promise<readonly AncV1RotationRecipientAcknowledgement[]> {
  exact(
    input,
    [
      "encodedAcknowledgements",
      "expectedVaultId",
      "expectedCeremonyId",
      "expectedCheckpointHash",
      "expectedTargetEpoch",
      "expectedRecipients",
      "pendingEpochKey",
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
  const recipients = new Map(
    input.expectedRecipients.map((recipient) => {
      exact(
        recipient,
        ["endpointId", "signingPublicKey", "eekWrapHash"],
        "Rotation recipient",
      );
      return [
        hex(bytes(recipient.endpointId, 16, "recipient endpointId")),
        recipient,
      ] as const;
    }),
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
      !same(decoded.ceremonyId, input.expectedCeremonyId) ||
      !same(decoded.checkpointHash, input.expectedCheckpointHash) ||
      decoded.targetEpoch !== input.expectedTargetEpoch ||
      !same(decoded.eekWrapHash, recipient.eekWrapHash)
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
