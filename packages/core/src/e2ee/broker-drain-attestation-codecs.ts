import sodium from "libsodium-wrappers-sumo";

import {
  type AncV1CanonicalValue,
  decodeAncV1Envelope,
  encodeAncV1Canonical,
} from "./canonical.js";

export const ANC_BROKER_DRAIN_ATTESTATION_SUITE_ID = "anc/v1" as const;
export const ANC_BROKER_DRAIN_ATTESTATION_TYPE =
  "broker_drain_attestation" as const;
export const ANC_BROKER_DRAIN_ATTESTATION_FIELDS = Object.freeze({
  suite: 1,
  vaultId: 2,
  type: 3,
  createdAtSeconds: 4,
  envelopeId: 5,
  issuerEndpointId: 600,
  oldBrokerEndpointId: 601,
  candidateBrokerEndpointId: 602,
  candidateSigningPublicKey: 603,
  candidateKeyAgreementPublicKey: 604,
  candidateEnrollmentRef: 605,
  baseSequence: 606,
  baseHeadHash: 607,
  baseEpoch: 608,
  drainGeneration: 609,
  drainedJobCount: 610,
  drainDigest: 611,
  outstandingJobCount: 612,
  signature: 613,
});
export const ANC_BROKER_DRAIN_ATTESTATION_LIMITS = Object.freeze({
  encodedBytes: 1_024,
  maximumAgeSeconds: 15 * 60,
  futureClockSkewSeconds: 60,
  timestampUnit: "unix-seconds",
});

const FIELDS = ANC_BROKER_DRAIN_ATTESTATION_FIELDS;
const ID_BYTES = 16;
const KEY_BYTES = 32;
const HASH_BYTES = 32;
const SIGNATURE_BYTES = 64;
const SIGNING_DOMAIN = new TextEncoder().encode(
  "anc/v1/broker-drain-attestation\0",
);
const CEREMONY_DOMAIN = new TextEncoder().encode(
  "anc/v1/broker-drain-ceremony\0",
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
  "baseSequence",
  "baseHeadHash",
  "baseEpoch",
  "drainGeneration",
  "drainedJobCount",
  "drainDigest",
  "outstandingJobCount",
] as const;
const signedFieldNames = [...unsignedFieldNames, "signature"] as const;
const signedKeys = signedFieldNames.map((name) => FIELDS[name]);

export interface AncV1UnsignedBrokerDrainAttestation {
  readonly suite: typeof ANC_BROKER_DRAIN_ATTESTATION_SUITE_ID;
  readonly vaultId: Uint8Array;
  readonly type: typeof ANC_BROKER_DRAIN_ATTESTATION_TYPE;
  readonly createdAtSeconds: number;
  readonly envelopeId: Uint8Array;
  readonly issuerEndpointId: Uint8Array;
  readonly oldBrokerEndpointId: Uint8Array;
  readonly candidateBrokerEndpointId: Uint8Array;
  readonly candidateSigningPublicKey: Uint8Array;
  readonly candidateKeyAgreementPublicKey: Uint8Array;
  readonly candidateEnrollmentRef: Uint8Array;
  readonly baseSequence: number;
  readonly baseHeadHash: Uint8Array;
  readonly baseEpoch: number;
  readonly drainGeneration: number;
  readonly drainedJobCount: number;
  readonly drainDigest: Uint8Array;
  readonly outstandingJobCount: number;
}

export interface AncV1BrokerDrainAttestation extends AncV1UnsignedBrokerDrainAttestation {
  readonly signature: Uint8Array;
}

export interface AncV1BrokerDrainAttestationExpectations {
  readonly vaultId: Uint8Array;
  readonly issuerEndpointId: Uint8Array;
  readonly oldBrokerEndpointId: Uint8Array;
  readonly candidateBrokerEndpointId: Uint8Array;
  readonly candidateSigningPublicKey: Uint8Array;
  readonly candidateKeyAgreementPublicKey: Uint8Array;
  readonly candidateEnrollmentRef: Uint8Array;
  readonly baseSequence: number;
  readonly baseHeadHash: Uint8Array;
  readonly baseEpoch: number;
  readonly drainGeneration: number;
  readonly drainedJobCount: number;
  readonly drainDigest: Uint8Array;
  readonly expectedCreatedAtSeconds: number;
  readonly nowSeconds: number;
  readonly issuerSigningPublicKey: Uint8Array;
}

export class AncV1BrokerDrainAttestationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "AncV1BrokerDrainAttestationError";
  }
}

function fail(message: string): never {
  throw new AncV1BrokerDrainAttestationError(message);
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

function nonnegative(value: unknown, name: string): number {
  if (!Number.isSafeInteger(value) || (value as number) < 0)
    fail(`${name} must be a non-negative safe integer`);
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

function unsignedMap(
  value: AncV1UnsignedBrokerDrainAttestation,
  validateFields = true,
): Map<number, AncV1CanonicalValue> {
  if (validateFields)
    exact(value, unsignedFieldNames, "broker drain attestation");
  const outstandingJobCount = nonnegative(
    value.outstandingJobCount,
    "outstandingJobCount",
  );
  if (outstandingJobCount !== 0) fail("outstandingJobCount must be zero");
  return new Map<number, AncV1CanonicalValue>([
    [
      FIELDS.suite,
      text(value.suite, ANC_BROKER_DRAIN_ATTESTATION_SUITE_ID, "suite"),
    ],
    [FIELDS.vaultId, bytes(value.vaultId, ID_BYTES, "vaultId")],
    [FIELDS.type, text(value.type, ANC_BROKER_DRAIN_ATTESTATION_TYPE, "type")],
    [
      FIELDS.createdAtSeconds,
      positive(value.createdAtSeconds, "createdAtSeconds"),
    ],
    [FIELDS.envelopeId, bytes(value.envelopeId, ID_BYTES, "envelopeId")],
    [
      FIELDS.issuerEndpointId,
      bytes(value.issuerEndpointId, ID_BYTES, "issuerEndpointId"),
    ],
    [
      FIELDS.oldBrokerEndpointId,
      bytes(value.oldBrokerEndpointId, ID_BYTES, "oldBrokerEndpointId"),
    ],
    [
      FIELDS.candidateBrokerEndpointId,
      bytes(
        value.candidateBrokerEndpointId,
        ID_BYTES,
        "candidateBrokerEndpointId",
      ),
    ],
    [
      FIELDS.candidateSigningPublicKey,
      bytes(
        value.candidateSigningPublicKey,
        KEY_BYTES,
        "candidateSigningPublicKey",
      ),
    ],
    [
      FIELDS.candidateKeyAgreementPublicKey,
      bytes(
        value.candidateKeyAgreementPublicKey,
        KEY_BYTES,
        "candidateKeyAgreementPublicKey",
      ),
    ],
    [
      FIELDS.candidateEnrollmentRef,
      bytes(value.candidateEnrollmentRef, ID_BYTES, "candidateEnrollmentRef"),
    ],
    [FIELDS.baseSequence, positive(value.baseSequence, "baseSequence")],
    [
      FIELDS.baseHeadHash,
      bytes(value.baseHeadHash, HASH_BYTES, "baseHeadHash"),
    ],
    [FIELDS.baseEpoch, positive(value.baseEpoch, "baseEpoch")],
    [
      FIELDS.drainGeneration,
      positive(value.drainGeneration, "drainGeneration"),
    ],
    [
      FIELDS.drainedJobCount,
      nonnegative(value.drainedJobCount, "drainedJobCount"),
    ],
    [FIELDS.drainDigest, bytes(value.drainDigest, HASH_BYTES, "drainDigest")],
    [FIELDS.outstandingJobCount, outstandingJobCount],
  ]);
}

function decodeUnsignedMap(
  map: ReadonlyMap<number, AncV1CanonicalValue>,
): AncV1UnsignedBrokerDrainAttestation {
  const outstandingJobCount = nonnegative(
    field(map, FIELDS.outstandingJobCount, "outstandingJobCount"),
    "outstandingJobCount",
  );
  if (outstandingJobCount !== 0) fail("outstandingJobCount must be zero");
  return Object.freeze({
    suite: text(
      field(map, FIELDS.suite, "suite"),
      ANC_BROKER_DRAIN_ATTESTATION_SUITE_ID,
      "suite",
    ),
    vaultId: bytes(field(map, FIELDS.vaultId, "vaultId"), ID_BYTES, "vaultId"),
    type: text(
      field(map, FIELDS.type, "type"),
      ANC_BROKER_DRAIN_ATTESTATION_TYPE,
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
    baseSequence: positive(
      field(map, FIELDS.baseSequence, "baseSequence"),
      "baseSequence",
    ),
    baseHeadHash: bytes(
      field(map, FIELDS.baseHeadHash, "baseHeadHash"),
      HASH_BYTES,
      "baseHeadHash",
    ),
    baseEpoch: positive(field(map, FIELDS.baseEpoch, "baseEpoch"), "baseEpoch"),
    drainGeneration: positive(
      field(map, FIELDS.drainGeneration, "drainGeneration"),
      "drainGeneration",
    ),
    drainedJobCount: nonnegative(
      field(map, FIELDS.drainedJobCount, "drainedJobCount"),
      "drainedJobCount",
    ),
    drainDigest: bytes(
      field(map, FIELDS.drainDigest, "drainDigest"),
      HASH_BYTES,
      "drainDigest",
    ),
    outstandingJobCount,
  });
}

function assertExpectedBytes(
  actual: Uint8Array,
  expected: Uint8Array,
  length: number,
  name: string,
): void {
  if (!same(actual, bytes(expected, length, `expected ${name}`)))
    fail(`${name} does not match the expected value`);
}

function assertExpectedNumber(
  actual: number,
  expected: number,
  name: string,
): void {
  if (actual !== expected) fail(`${name} does not match the expected value`);
}

export function encodeAncV1UnsignedBrokerDrainAttestation(
  value: AncV1UnsignedBrokerDrainAttestation,
): Uint8Array {
  return encodeAncV1Canonical(unsignedMap(value));
}

export async function signAncV1BrokerDrainAttestation(
  value: AncV1UnsignedBrokerDrainAttestation,
  issuerSigningPrivateKey: Uint8Array,
): Promise<AncV1BrokerDrainAttestation> {
  await sodium.ready;
  const unsigned = encodeAncV1UnsignedBrokerDrainAttestation(value);
  const preimage = concat(SIGNING_DOMAIN, unsigned);
  const privateKey = bytes(
    issuerSigningPrivateKey,
    64,
    "issuerSigningPrivateKey",
  );
  try {
    const signature = sodium.crypto_sign_detached(preimage, privateKey);
    return Object.freeze({
      ...decodeUnsignedMap(unsignedMap(value)),
      signature,
    });
  } finally {
    privateKey.fill(0);
    preimage.fill(0);
  }
}

export function encodeAncV1BrokerDrainAttestation(
  value: AncV1BrokerDrainAttestation,
): Uint8Array {
  exact(value, signedFieldNames, "signed broker drain attestation");
  const map = unsignedMap(value, false);
  map.set(
    FIELDS.signature,
    bytes(value.signature, SIGNATURE_BYTES, "signature"),
  );
  const encoded = encodeAncV1Canonical(map);
  if (encoded.byteLength > ANC_BROKER_DRAIN_ATTESTATION_LIMITS.encodedBytes)
    fail("broker drain attestation exceeds the v1 size limit");
  return encoded;
}

export function decodeAncV1BrokerDrainAttestation(
  encoded: Uint8Array,
): AncV1BrokerDrainAttestation {
  const map = decodeAncV1Envelope(encoded, signedKeys, {
    maxBytes: ANC_BROKER_DRAIN_ATTESTATION_LIMITS.encodedBytes,
  });
  if (map.size !== signedKeys.length)
    fail("broker drain attestation must contain exactly its versioned fields");
  return Object.freeze({
    ...decodeUnsignedMap(map),
    signature: bytes(
      field(map, FIELDS.signature, "signature"),
      SIGNATURE_BYTES,
      "signature",
    ),
  });
}

export async function verifyAncV1BrokerDrainAttestation(
  encoded: Uint8Array,
  expected: AncV1BrokerDrainAttestationExpectations,
): Promise<AncV1BrokerDrainAttestation> {
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
      "baseSequence",
      "baseHeadHash",
      "baseEpoch",
      "drainGeneration",
      "drainedJobCount",
      "drainDigest",
      "expectedCreatedAtSeconds",
      "nowSeconds",
      "issuerSigningPublicKey",
    ],
    "broker drain attestation expectations",
  );
  const value = decodeAncV1BrokerDrainAttestation(encoded);
  assertExpectedBytes(value.vaultId, expected.vaultId, ID_BYTES, "vaultId");
  assertExpectedBytes(
    value.issuerEndpointId,
    expected.issuerEndpointId,
    ID_BYTES,
    "issuerEndpointId",
  );
  assertExpectedBytes(
    value.oldBrokerEndpointId,
    expected.oldBrokerEndpointId,
    ID_BYTES,
    "oldBrokerEndpointId",
  );
  assertExpectedBytes(
    value.candidateBrokerEndpointId,
    expected.candidateBrokerEndpointId,
    ID_BYTES,
    "candidateBrokerEndpointId",
  );
  assertExpectedBytes(
    value.candidateSigningPublicKey,
    expected.candidateSigningPublicKey,
    KEY_BYTES,
    "candidateSigningPublicKey",
  );
  assertExpectedBytes(
    value.candidateKeyAgreementPublicKey,
    expected.candidateKeyAgreementPublicKey,
    KEY_BYTES,
    "candidateKeyAgreementPublicKey",
  );
  assertExpectedBytes(
    value.candidateEnrollmentRef,
    expected.candidateEnrollmentRef,
    ID_BYTES,
    "candidateEnrollmentRef",
  );
  assertExpectedNumber(
    value.baseSequence,
    positive(expected.baseSequence, "expected baseSequence"),
    "baseSequence",
  );
  assertExpectedBytes(
    value.baseHeadHash,
    expected.baseHeadHash,
    HASH_BYTES,
    "baseHeadHash",
  );
  assertExpectedNumber(
    value.baseEpoch,
    positive(expected.baseEpoch, "expected baseEpoch"),
    "baseEpoch",
  );
  assertExpectedNumber(
    value.drainGeneration,
    positive(expected.drainGeneration, "expected drainGeneration"),
    "drainGeneration",
  );
  assertExpectedNumber(
    value.drainedJobCount,
    nonnegative(expected.drainedJobCount, "expected drainedJobCount"),
    "drainedJobCount",
  );
  assertExpectedBytes(
    value.drainDigest,
    expected.drainDigest,
    HASH_BYTES,
    "drainDigest",
  );
  const expectedCreatedAtSeconds = positive(
    expected.expectedCreatedAtSeconds,
    "expectedCreatedAtSeconds",
  );
  assertExpectedNumber(
    value.createdAtSeconds,
    expectedCreatedAtSeconds,
    "createdAtSeconds",
  );
  const nowSeconds = positive(expected.nowSeconds, "nowSeconds");
  if (
    expectedCreatedAtSeconds >
    nowSeconds + ANC_BROKER_DRAIN_ATTESTATION_LIMITS.futureClockSkewSeconds
  )
    fail("broker drain attestation is too far in the future");
  if (
    nowSeconds - expectedCreatedAtSeconds >
    ANC_BROKER_DRAIN_ATTESTATION_LIMITS.maximumAgeSeconds
  )
    fail("broker drain attestation is stale");
  await sodium.ready;
  const unsigned = encodeAncV1Canonical(unsignedMap(value, false));
  const preimage = concat(SIGNING_DOMAIN, unsigned);
  const valid = sodium.crypto_sign_verify_detached(
    value.signature,
    preimage,
    bytes(expected.issuerSigningPublicKey, KEY_BYTES, "issuerSigningPublicKey"),
  );
  preimage.fill(0);
  if (!valid) fail("broker drain attestation signature is invalid");
  return value;
}

export async function hashAncV1BrokerDrainCeremonyId(
  encodedSignedAttestation: Uint8Array,
): Promise<Uint8Array> {
  decodeAncV1BrokerDrainAttestation(encodedSignedAttestation);
  await sodium.ready;
  return sodium
    .crypto_generichash(
      HASH_BYTES,
      concat(CEREMONY_DOMAIN, encodedSignedAttestation),
      null,
    )
    .slice(0, ID_BYTES);
}
