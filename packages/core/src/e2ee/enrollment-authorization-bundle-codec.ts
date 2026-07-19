const MAGIC = Uint8Array.of(0x41, 0x4e, 0x45, 0x41); // ANEA
const VERSION = 1;
const HEADER_BYTES = 17;

export const ANC_ENROLLMENT_AUTHORIZATION_BUNDLE_LIMITS = Object.freeze({
  enrollmentAuthorizationBytes: 256 * 1024,
  manifestCheckpointBytes: 1_024,
  manifestAuthorizationBytes: 1_024,
  headerBytes: HEADER_BYTES,
  totalBytes: HEADER_BYTES + 256 * 1024 + 1_024 + 1_024,
});

export interface AncV1EnrollmentAuthorizationBundle {
  readonly enrollmentAuthorization: Uint8Array;
  readonly manifestCheckpoint: Uint8Array;
  readonly manifestAuthorization: Uint8Array;
}

export class AncV1EnrollmentAuthorizationBundleError extends Error {
  constructor() {
    super("Invalid enrollment authorization bundle");
    this.name = "AncV1EnrollmentAuthorizationBundleError";
  }
}

function bounded(value: unknown, maximum: number): Uint8Array {
  if (
    !(value instanceof Uint8Array) ||
    value.byteLength < 1 ||
    value.byteLength > maximum
  ) {
    throw new AncV1EnrollmentAuthorizationBundleError();
  }
  return value.slice();
}

function exactInput(value: AncV1EnrollmentAuthorizationBundle): void {
  const actual = Object.keys(value).sort();
  const expected = [
    "enrollmentAuthorization",
    "manifestAuthorization",
    "manifestCheckpoint",
  ].sort();
  if (
    actual.length !== expected.length ||
    actual.some((field, index) => field !== expected[index])
  ) {
    throw new AncV1EnrollmentAuthorizationBundleError();
  }
}

function readLength(view: DataView, offset: number, maximum: number): number {
  const length = view.getUint32(offset, false);
  if (length < 1 || length > maximum) {
    throw new AncV1EnrollmentAuthorizationBundleError();
  }
  return length;
}

/**
 * Opaque hosted framing for the three independently signed enrollment
 * artifacts. This codec deliberately does not interpret any artifact body.
 */
export function encodeAncV1EnrollmentAuthorizationBundle(
  value: AncV1EnrollmentAuthorizationBundle,
): Uint8Array {
  exactInput(value);
  const enrollmentAuthorization = bounded(
    value.enrollmentAuthorization,
    ANC_ENROLLMENT_AUTHORIZATION_BUNDLE_LIMITS.enrollmentAuthorizationBytes,
  );
  const manifestCheckpoint = bounded(
    value.manifestCheckpoint,
    ANC_ENROLLMENT_AUTHORIZATION_BUNDLE_LIMITS.manifestCheckpointBytes,
  );
  const manifestAuthorization = bounded(
    value.manifestAuthorization,
    ANC_ENROLLMENT_AUTHORIZATION_BUNDLE_LIMITS.manifestAuthorizationBytes,
  );
  const output = new Uint8Array(
    HEADER_BYTES +
      enrollmentAuthorization.byteLength +
      manifestCheckpoint.byteLength +
      manifestAuthorization.byteLength,
  );
  output.set(MAGIC, 0);
  output[4] = VERSION;
  const view = new DataView(
    output.buffer,
    output.byteOffset,
    output.byteLength,
  );
  view.setUint32(5, enrollmentAuthorization.byteLength, false);
  view.setUint32(9, manifestCheckpoint.byteLength, false);
  view.setUint32(13, manifestAuthorization.byteLength, false);
  let offset = HEADER_BYTES;
  output.set(enrollmentAuthorization, offset);
  offset += enrollmentAuthorization.byteLength;
  output.set(manifestCheckpoint, offset);
  offset += manifestCheckpoint.byteLength;
  output.set(manifestAuthorization, offset);
  return output;
}

export function decodeAncV1EnrollmentAuthorizationBundle(
  encoded: Uint8Array,
): AncV1EnrollmentAuthorizationBundle {
  if (
    !(encoded instanceof Uint8Array) ||
    encoded.byteLength < HEADER_BYTES + 3 ||
    encoded.byteLength >
      ANC_ENROLLMENT_AUTHORIZATION_BUNDLE_LIMITS.totalBytes ||
    MAGIC.some((byte, index) => encoded[index] !== byte) ||
    encoded[4] !== VERSION
  ) {
    throw new AncV1EnrollmentAuthorizationBundleError();
  }
  const view = new DataView(
    encoded.buffer,
    encoded.byteOffset,
    encoded.byteLength,
  );
  const authorizationLength = readLength(
    view,
    5,
    ANC_ENROLLMENT_AUTHORIZATION_BUNDLE_LIMITS.enrollmentAuthorizationBytes,
  );
  const checkpointLength = readLength(
    view,
    9,
    ANC_ENROLLMENT_AUTHORIZATION_BUNDLE_LIMITS.manifestCheckpointBytes,
  );
  const manifestAuthorizationLength = readLength(
    view,
    13,
    ANC_ENROLLMENT_AUTHORIZATION_BUNDLE_LIMITS.manifestAuthorizationBytes,
  );
  const expectedLength =
    HEADER_BYTES +
    authorizationLength +
    checkpointLength +
    manifestAuthorizationLength;
  if (encoded.byteLength !== expectedLength) {
    throw new AncV1EnrollmentAuthorizationBundleError();
  }
  let offset = HEADER_BYTES;
  const enrollmentAuthorization = encoded.slice(
    offset,
    offset + authorizationLength,
  );
  offset += authorizationLength;
  const manifestCheckpoint = encoded.slice(offset, offset + checkpointLength);
  offset += checkpointLength;
  const manifestAuthorization = encoded.slice(
    offset,
    offset + manifestAuthorizationLength,
  );
  return Object.freeze({
    enrollmentAuthorization,
    manifestCheckpoint,
    manifestAuthorization,
  });
}
