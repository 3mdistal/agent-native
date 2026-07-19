import sodium from "libsodium-wrappers-sumo";

import {
  type AncV1CanonicalValue,
  decodeAncV1Envelope,
  encodeAncV1Canonical,
} from "./canonical.js";

export const ANC_BROKER_REPLACEMENT_APPROVAL_SUITE_ID = "anc/v1" as const;
export const ANC_BROKER_REPLACEMENT_APPROVAL_TYPE =
  "broker_replacement_approval" as const;
export const ANC_BROKER_REPLACEMENT_APPROVAL_FIELDS = Object.freeze({
  suite: 1,
  vaultId: 2,
  type: 3,
  createdAtSeconds: 4,
  envelopeId: 5,
  issuerEndpointId: 620,
  oldBrokerEndpointId: 621,
  candidateBrokerEndpointId: 622,
  candidateSigningPublicKey: 623,
  candidateKeyAgreementPublicKey: 624,
  candidateEnrollmentRef: 625,
  offerHash: 626,
  challengeHash: 627,
  sasDecisionHash: 628,
  baseSequence: 629,
  baseHeadHash: 630,
  baseMembershipHash: 631,
  baseEpoch: 632,
  drainId: 633,
  drainGeneration: 634,
  deadlineAtSeconds: 635,
  signature: 636,
});
export const ANC_BROKER_REPLACEMENT_APPROVAL_LIMITS = Object.freeze({
  encodedBytes: 1_024,
  maximumAgeSeconds: 15 * 60,
  futureClockSkewSeconds: 60,
  maximumDeadlineSeconds: 24 * 60 * 60,
  timestampUnit: "unix-seconds",
});

const FIELDS = ANC_BROKER_REPLACEMENT_APPROVAL_FIELDS;
const ID_BYTES = 16;
const HASH_BYTES = 32;
const KEY_BYTES = 32;
const SIGNATURE_BYTES = 64;
const SIGNING_DOMAIN = new TextEncoder().encode(
  "anc/v1/broker-replacement-approval\0",
);
const FREEZE_DOMAIN = new TextEncoder().encode(
  "anc/v1/broker-replacement-freeze\0",
);
const unsignedFieldNames = [
  "suite",
  "vaultId",
  "type",
  "createdAtSeconds",
  "envelopeId",
  "issuerEndpointId",
  "oldBrokerEndpointId",
  "candidateBrokerEndpointId",
  "candidateSigningPublicKey",
  "candidateKeyAgreementPublicKey",
  "candidateEnrollmentRef",
  "offerHash",
  "challengeHash",
  "sasDecisionHash",
  "baseSequence",
  "baseHeadHash",
  "baseMembershipHash",
  "baseEpoch",
  "drainId",
  "drainGeneration",
  "deadlineAtSeconds",
] as const;
const signedFieldNames = [...unsignedFieldNames, "signature"] as const;
const signedKeys = signedFieldNames.map((name) => FIELDS[name]);

export interface AncV1UnsignedBrokerReplacementApproval {
  readonly suite: typeof ANC_BROKER_REPLACEMENT_APPROVAL_SUITE_ID;
  readonly vaultId: Uint8Array;
  readonly type: typeof ANC_BROKER_REPLACEMENT_APPROVAL_TYPE;
  readonly createdAtSeconds: number;
  readonly envelopeId: Uint8Array;
  readonly issuerEndpointId: Uint8Array;
  readonly oldBrokerEndpointId: Uint8Array;
  readonly candidateBrokerEndpointId: Uint8Array;
  readonly candidateSigningPublicKey: Uint8Array;
  readonly candidateKeyAgreementPublicKey: Uint8Array;
  readonly candidateEnrollmentRef: Uint8Array;
  readonly offerHash: Uint8Array;
  readonly challengeHash: Uint8Array;
  readonly sasDecisionHash: Uint8Array;
  readonly baseSequence: number;
  readonly baseHeadHash: Uint8Array;
  readonly baseMembershipHash: Uint8Array;
  readonly baseEpoch: number;
  readonly drainId: Uint8Array;
  readonly drainGeneration: number;
  readonly deadlineAtSeconds: number;
}

export interface AncV1BrokerReplacementApproval extends AncV1UnsignedBrokerReplacementApproval {
  readonly signature: Uint8Array;
}

export interface AncV1BrokerReplacementApprovalExpectations {
  readonly vaultId: Uint8Array;
  readonly issuerEndpointId: Uint8Array;
  readonly oldBrokerEndpointId: Uint8Array;
  readonly candidateBrokerEndpointId: Uint8Array;
  readonly candidateSigningPublicKey: Uint8Array;
  readonly candidateKeyAgreementPublicKey: Uint8Array;
  readonly candidateEnrollmentRef: Uint8Array;
  readonly offerHash: Uint8Array;
  readonly challengeHash: Uint8Array;
  readonly sasDecisionHash: Uint8Array;
  readonly baseSequence: number;
  readonly baseHeadHash: Uint8Array;
  readonly baseMembershipHash: Uint8Array;
  readonly baseEpoch: number;
  readonly drainId: Uint8Array;
  readonly drainGeneration: number;
  readonly deadlineAtSeconds: number;
  readonly expectedCreatedAtSeconds: number;
  readonly nowSeconds: number;
  readonly issuerSigningPublicKey: Uint8Array;
}

export class AncV1BrokerReplacementApprovalError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "AncV1BrokerReplacementApprovalError";
  }
}

function fail(message: string): never {
  throw new AncV1BrokerReplacementApprovalError(message);
}

function exact(value: object, expected: readonly string[], name: string): void {
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

function text<T extends string>(value: unknown, expected: T, name: string): T {
  if (value !== expected) fail(`${name} must be ${expected}`);
  return expected;
}

function same(left: Uint8Array, right: Uint8Array): boolean {
  if (left.byteLength !== right.byteLength) return false;
  let difference = 0;
  for (let index = 0; index < left.byteLength; index += 1)
    difference |= left[index]! ^ right[index]!;
  return difference === 0;
}

function concat(left: Uint8Array, right: Uint8Array): Uint8Array {
  const output = new Uint8Array(left.byteLength + right.byteLength);
  output.set(left);
  output.set(right, left.byteLength);
  return output;
}

function field(
  map: ReadonlyMap<number, AncV1CanonicalValue>,
  key: number,
  name: string,
): AncV1CanonicalValue {
  if (!map.has(key)) fail(`${name} is required`);
  return map.get(key)!;
}

function validateRelations(
  value: Pick<
    AncV1UnsignedBrokerReplacementApproval,
    | "createdAtSeconds"
    | "deadlineAtSeconds"
    | "envelopeId"
    | "candidateEnrollmentRef"
    | "issuerEndpointId"
    | "oldBrokerEndpointId"
    | "candidateBrokerEndpointId"
  >,
): void {
  if (!same(value.candidateEnrollmentRef, value.envelopeId))
    fail("candidateEnrollmentRef must equal envelopeId");
  if (same(value.oldBrokerEndpointId, value.issuerEndpointId))
    fail("old broker must differ from the issuer");
  if (same(value.candidateBrokerEndpointId, value.oldBrokerEndpointId))
    fail("candidate broker must differ from the old broker");
  if (same(value.candidateBrokerEndpointId, value.issuerEndpointId))
    fail("candidate broker must differ from the issuer");
  if (value.deadlineAtSeconds <= value.createdAtSeconds)
    fail("deadlineAtSeconds must be after createdAtSeconds");
  if (
    value.deadlineAtSeconds - value.createdAtSeconds >
    ANC_BROKER_REPLACEMENT_APPROVAL_LIMITS.maximumDeadlineSeconds
  )
    fail("deadlineAtSeconds exceeds the 24-hour limit");
}

function unsignedMap(
  value: AncV1UnsignedBrokerReplacementApproval,
  validateFields = true,
): Map<number, AncV1CanonicalValue> {
  if (validateFields)
    exact(value, unsignedFieldNames, "broker replacement approval");
  const normalized = {
    suite: text(value.suite, ANC_BROKER_REPLACEMENT_APPROVAL_SUITE_ID, "suite"),
    vaultId: bytes(value.vaultId, ID_BYTES, "vaultId"),
    type: text(value.type, ANC_BROKER_REPLACEMENT_APPROVAL_TYPE, "type"),
    createdAtSeconds: positive(value.createdAtSeconds, "createdAtSeconds"),
    envelopeId: bytes(value.envelopeId, ID_BYTES, "envelopeId"),
    issuerEndpointId: bytes(
      value.issuerEndpointId,
      ID_BYTES,
      "issuerEndpointId",
    ),
    oldBrokerEndpointId: bytes(
      value.oldBrokerEndpointId,
      ID_BYTES,
      "oldBrokerEndpointId",
    ),
    candidateBrokerEndpointId: bytes(
      value.candidateBrokerEndpointId,
      ID_BYTES,
      "candidateBrokerEndpointId",
    ),
    candidateSigningPublicKey: bytes(
      value.candidateSigningPublicKey,
      KEY_BYTES,
      "candidateSigningPublicKey",
    ),
    candidateKeyAgreementPublicKey: bytes(
      value.candidateKeyAgreementPublicKey,
      KEY_BYTES,
      "candidateKeyAgreementPublicKey",
    ),
    candidateEnrollmentRef: bytes(
      value.candidateEnrollmentRef,
      ID_BYTES,
      "candidateEnrollmentRef",
    ),
    offerHash: bytes(value.offerHash, HASH_BYTES, "offerHash"),
    challengeHash: bytes(value.challengeHash, HASH_BYTES, "challengeHash"),
    sasDecisionHash: bytes(
      value.sasDecisionHash,
      HASH_BYTES,
      "sasDecisionHash",
    ),
    baseSequence: positive(value.baseSequence, "baseSequence"),
    baseHeadHash: bytes(value.baseHeadHash, HASH_BYTES, "baseHeadHash"),
    baseMembershipHash: bytes(
      value.baseMembershipHash,
      HASH_BYTES,
      "baseMembershipHash",
    ),
    baseEpoch: positive(value.baseEpoch, "baseEpoch"),
    drainId: bytes(value.drainId, ID_BYTES, "drainId"),
    drainGeneration: positive(value.drainGeneration, "drainGeneration"),
    deadlineAtSeconds: positive(value.deadlineAtSeconds, "deadlineAtSeconds"),
  };
  validateRelations(normalized);
  return new Map<number, AncV1CanonicalValue>([
    [FIELDS.suite, normalized.suite],
    [FIELDS.vaultId, normalized.vaultId],
    [FIELDS.type, normalized.type],
    [FIELDS.createdAtSeconds, normalized.createdAtSeconds],
    [FIELDS.envelopeId, normalized.envelopeId],
    [FIELDS.issuerEndpointId, normalized.issuerEndpointId],
    [FIELDS.oldBrokerEndpointId, normalized.oldBrokerEndpointId],
    [FIELDS.candidateBrokerEndpointId, normalized.candidateBrokerEndpointId],
    [FIELDS.candidateSigningPublicKey, normalized.candidateSigningPublicKey],
    [
      FIELDS.candidateKeyAgreementPublicKey,
      normalized.candidateKeyAgreementPublicKey,
    ],
    [FIELDS.candidateEnrollmentRef, normalized.candidateEnrollmentRef],
    [FIELDS.offerHash, normalized.offerHash],
    [FIELDS.challengeHash, normalized.challengeHash],
    [FIELDS.sasDecisionHash, normalized.sasDecisionHash],
    [FIELDS.baseSequence, normalized.baseSequence],
    [FIELDS.baseHeadHash, normalized.baseHeadHash],
    [FIELDS.baseMembershipHash, normalized.baseMembershipHash],
    [FIELDS.baseEpoch, normalized.baseEpoch],
    [FIELDS.drainId, normalized.drainId],
    [FIELDS.drainGeneration, normalized.drainGeneration],
    [FIELDS.deadlineAtSeconds, normalized.deadlineAtSeconds],
  ]);
}

function decodeUnsigned(
  map: ReadonlyMap<number, AncV1CanonicalValue>,
): AncV1UnsignedBrokerReplacementApproval {
  const value = Object.freeze({
    suite: text(
      field(map, FIELDS.suite, "suite"),
      ANC_BROKER_REPLACEMENT_APPROVAL_SUITE_ID,
      "suite",
    ),
    vaultId: bytes(field(map, FIELDS.vaultId, "vaultId"), ID_BYTES, "vaultId"),
    type: text(
      field(map, FIELDS.type, "type"),
      ANC_BROKER_REPLACEMENT_APPROVAL_TYPE,
      "type",
    ),
    createdAtSeconds: positive(
      field(map, FIELDS.createdAtSeconds, "createdAtSeconds"),
      "createdAtSeconds",
    ),
    envelopeId: bytes(
      field(map, FIELDS.envelopeId, "envelopeId"),
      ID_BYTES,
      "envelopeId",
    ),
    issuerEndpointId: bytes(
      field(map, FIELDS.issuerEndpointId, "issuerEndpointId"),
      ID_BYTES,
      "issuerEndpointId",
    ),
    oldBrokerEndpointId: bytes(
      field(map, FIELDS.oldBrokerEndpointId, "oldBrokerEndpointId"),
      ID_BYTES,
      "oldBrokerEndpointId",
    ),
    candidateBrokerEndpointId: bytes(
      field(map, FIELDS.candidateBrokerEndpointId, "candidateBrokerEndpointId"),
      ID_BYTES,
      "candidateBrokerEndpointId",
    ),
    candidateSigningPublicKey: bytes(
      field(map, FIELDS.candidateSigningPublicKey, "candidateSigningPublicKey"),
      KEY_BYTES,
      "candidateSigningPublicKey",
    ),
    candidateKeyAgreementPublicKey: bytes(
      field(
        map,
        FIELDS.candidateKeyAgreementPublicKey,
        "candidateKeyAgreementPublicKey",
      ),
      KEY_BYTES,
      "candidateKeyAgreementPublicKey",
    ),
    candidateEnrollmentRef: bytes(
      field(map, FIELDS.candidateEnrollmentRef, "candidateEnrollmentRef"),
      ID_BYTES,
      "candidateEnrollmentRef",
    ),
    offerHash: bytes(
      field(map, FIELDS.offerHash, "offerHash"),
      HASH_BYTES,
      "offerHash",
    ),
    challengeHash: bytes(
      field(map, FIELDS.challengeHash, "challengeHash"),
      HASH_BYTES,
      "challengeHash",
    ),
    sasDecisionHash: bytes(
      field(map, FIELDS.sasDecisionHash, "sasDecisionHash"),
      HASH_BYTES,
      "sasDecisionHash",
    ),
    baseSequence: positive(
      field(map, FIELDS.baseSequence, "baseSequence"),
      "baseSequence",
    ),
    baseHeadHash: bytes(
      field(map, FIELDS.baseHeadHash, "baseHeadHash"),
      HASH_BYTES,
      "baseHeadHash",
    ),
    baseMembershipHash: bytes(
      field(map, FIELDS.baseMembershipHash, "baseMembershipHash"),
      HASH_BYTES,
      "baseMembershipHash",
    ),
    baseEpoch: positive(field(map, FIELDS.baseEpoch, "baseEpoch"), "baseEpoch"),
    drainId: bytes(field(map, FIELDS.drainId, "drainId"), ID_BYTES, "drainId"),
    drainGeneration: positive(
      field(map, FIELDS.drainGeneration, "drainGeneration"),
      "drainGeneration",
    ),
    deadlineAtSeconds: positive(
      field(map, FIELDS.deadlineAtSeconds, "deadlineAtSeconds"),
      "deadlineAtSeconds",
    ),
  });
  validateRelations(value);
  return value;
}

function assertBytes(
  actual: Uint8Array,
  expected: Uint8Array,
  length: number,
  name: string,
): void {
  if (!same(actual, bytes(expected, length, `expected ${name}`)))
    fail(`${name} does not match the expected value`);
}

function assertNumber(actual: number, expected: number, name: string): void {
  if (actual !== expected) fail(`${name} does not match the expected value`);
}

export function encodeAncV1UnsignedBrokerReplacementApproval(
  value: AncV1UnsignedBrokerReplacementApproval,
): Uint8Array {
  return encodeAncV1Canonical(unsignedMap(value));
}

export async function signAncV1BrokerReplacementApproval(
  value: AncV1UnsignedBrokerReplacementApproval,
  issuerSigningPrivateKey: Uint8Array,
): Promise<AncV1BrokerReplacementApproval> {
  await sodium.ready;
  const unsigned = encodeAncV1UnsignedBrokerReplacementApproval(value);
  const preimage = concat(SIGNING_DOMAIN, unsigned);
  const privateKey = bytes(
    issuerSigningPrivateKey,
    64,
    "issuerSigningPrivateKey",
  );
  try {
    return Object.freeze({
      ...decodeUnsigned(unsignedMap(value)),
      signature: sodium.crypto_sign_detached(preimage, privateKey),
    });
  } finally {
    privateKey.fill(0);
    preimage.fill(0);
  }
}

export function encodeAncV1BrokerReplacementApproval(
  value: AncV1BrokerReplacementApproval,
): Uint8Array {
  exact(value, signedFieldNames, "signed broker replacement approval");
  const map = unsignedMap(value, false);
  map.set(
    FIELDS.signature,
    bytes(value.signature, SIGNATURE_BYTES, "signature"),
  );
  const encoded = encodeAncV1Canonical(map);
  if (encoded.byteLength > ANC_BROKER_REPLACEMENT_APPROVAL_LIMITS.encodedBytes)
    fail("broker replacement approval exceeds the v1 size limit");
  return encoded;
}

export function decodeAncV1BrokerReplacementApproval(
  encoded: Uint8Array,
): AncV1BrokerReplacementApproval {
  const map = decodeAncV1Envelope(encoded, signedKeys, {
    maxBytes: ANC_BROKER_REPLACEMENT_APPROVAL_LIMITS.encodedBytes,
  });
  if (map.size !== signedKeys.length)
    fail(
      "broker replacement approval must contain exactly its versioned fields",
    );
  return Object.freeze({
    ...decodeUnsigned(map),
    signature: bytes(
      field(map, FIELDS.signature, "signature"),
      SIGNATURE_BYTES,
      "signature",
    ),
  });
}

export async function verifyAncV1BrokerReplacementApproval(
  encoded: Uint8Array,
  expected: AncV1BrokerReplacementApprovalExpectations,
): Promise<AncV1BrokerReplacementApproval> {
  exact(
    expected,
    [
      "vaultId",
      "issuerEndpointId",
      "oldBrokerEndpointId",
      "candidateBrokerEndpointId",
      "candidateSigningPublicKey",
      "candidateKeyAgreementPublicKey",
      "candidateEnrollmentRef",
      "offerHash",
      "challengeHash",
      "sasDecisionHash",
      "baseSequence",
      "baseHeadHash",
      "baseMembershipHash",
      "baseEpoch",
      "drainId",
      "drainGeneration",
      "deadlineAtSeconds",
      "expectedCreatedAtSeconds",
      "nowSeconds",
      "issuerSigningPublicKey",
    ],
    "broker replacement approval expectations",
  );
  const value = decodeAncV1BrokerReplacementApproval(encoded);
  assertBytes(value.vaultId, expected.vaultId, ID_BYTES, "vaultId");
  assertBytes(
    value.issuerEndpointId,
    expected.issuerEndpointId,
    ID_BYTES,
    "issuerEndpointId",
  );
  assertBytes(
    value.oldBrokerEndpointId,
    expected.oldBrokerEndpointId,
    ID_BYTES,
    "oldBrokerEndpointId",
  );
  assertBytes(
    value.candidateBrokerEndpointId,
    expected.candidateBrokerEndpointId,
    ID_BYTES,
    "candidateBrokerEndpointId",
  );
  assertBytes(
    value.candidateSigningPublicKey,
    expected.candidateSigningPublicKey,
    KEY_BYTES,
    "candidateSigningPublicKey",
  );
  assertBytes(
    value.candidateKeyAgreementPublicKey,
    expected.candidateKeyAgreementPublicKey,
    KEY_BYTES,
    "candidateKeyAgreementPublicKey",
  );
  assertBytes(
    value.candidateEnrollmentRef,
    expected.candidateEnrollmentRef,
    ID_BYTES,
    "candidateEnrollmentRef",
  );
  assertBytes(value.offerHash, expected.offerHash, HASH_BYTES, "offerHash");
  assertBytes(
    value.challengeHash,
    expected.challengeHash,
    HASH_BYTES,
    "challengeHash",
  );
  assertBytes(
    value.sasDecisionHash,
    expected.sasDecisionHash,
    HASH_BYTES,
    "sasDecisionHash",
  );
  assertNumber(
    value.baseSequence,
    positive(expected.baseSequence, "expected baseSequence"),
    "baseSequence",
  );
  assertBytes(
    value.baseHeadHash,
    expected.baseHeadHash,
    HASH_BYTES,
    "baseHeadHash",
  );
  assertBytes(
    value.baseMembershipHash,
    expected.baseMembershipHash,
    HASH_BYTES,
    "baseMembershipHash",
  );
  assertNumber(
    value.baseEpoch,
    positive(expected.baseEpoch, "expected baseEpoch"),
    "baseEpoch",
  );
  assertBytes(value.drainId, expected.drainId, ID_BYTES, "drainId");
  assertNumber(
    value.drainGeneration,
    positive(expected.drainGeneration, "expected drainGeneration"),
    "drainGeneration",
  );
  assertNumber(
    value.deadlineAtSeconds,
    positive(expected.deadlineAtSeconds, "expected deadlineAtSeconds"),
    "deadlineAtSeconds",
  );
  const createdAt = positive(
    expected.expectedCreatedAtSeconds,
    "expectedCreatedAtSeconds",
  );
  assertNumber(value.createdAtSeconds, createdAt, "createdAtSeconds");
  const now = positive(expected.nowSeconds, "nowSeconds");
  if (
    createdAt >
    now + ANC_BROKER_REPLACEMENT_APPROVAL_LIMITS.futureClockSkewSeconds
  )
    fail("broker replacement approval is too far in the future");
  if (
    now - createdAt >
    ANC_BROKER_REPLACEMENT_APPROVAL_LIMITS.maximumAgeSeconds
  )
    fail("broker replacement approval is stale");
  if (value.deadlineAtSeconds <= now)
    fail("broker replacement approval deadline has elapsed");
  await sodium.ready;
  const unsigned = encodeAncV1Canonical(unsignedMap(value, false));
  const preimage = concat(SIGNING_DOMAIN, unsigned);
  const valid = sodium.crypto_sign_verify_detached(
    value.signature,
    preimage,
    bytes(expected.issuerSigningPublicKey, KEY_BYTES, "issuerSigningPublicKey"),
  );
  preimage.fill(0);
  if (!valid) fail("broker replacement approval signature is invalid");
  return value;
}

export async function hashAncV1BrokerReplacementFreezeId(
  encodedSignedApproval: Uint8Array,
): Promise<Uint8Array> {
  decodeAncV1BrokerReplacementApproval(encodedSignedApproval);
  await sodium.ready;
  const preimage = concat(FREEZE_DOMAIN, encodedSignedApproval);
  try {
    return sodium
      .crypto_generichash(HASH_BYTES, preimage, null)
      .slice(0, ID_BYTES);
  } finally {
    preimage.fill(0);
  }
}
