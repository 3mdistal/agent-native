import { describe, expect, it } from "vitest";

import {
  ANC_ENROLLMENT_AUTHORIZATION_BUNDLE_LIMITS as LIMITS,
  AncV1EnrollmentAuthorizationBundleError,
  decodeAncV1EnrollmentAuthorizationBundle,
  encodeAncV1EnrollmentAuthorizationBundle,
} from "./enrollment-authorization-bundle-codec.js";

const value = {
  enrollmentAuthorization: Uint8Array.of(1, 2, 3),
  manifestCheckpoint: Uint8Array.of(4, 5),
  manifestAuthorization: Uint8Array.of(6, 7, 8, 9),
};

describe("anc/v1 enrollment authorization bundle framing", () => {
  it("round trips exact opaque artifacts with deterministic versioned framing", () => {
    const encoded = encodeAncV1EnrollmentAuthorizationBundle(value);
    expect(Buffer.from(encoded).toString("hex")).toBe(
      "414e454101000000030000000200000004010203040506070809",
    );
    expect(decodeAncV1EnrollmentAuthorizationBundle(encoded)).toEqual(value);
    expect(
      encodeAncV1EnrollmentAuthorizationBundle(
        decodeAncV1EnrollmentAuthorizationBundle(encoded),
      ),
    ).toEqual(encoded);
  });

  it("accepts each exact maximum and rejects any oversized member", () => {
    const encoded = encodeAncV1EnrollmentAuthorizationBundle({
      enrollmentAuthorization: new Uint8Array(
        LIMITS.enrollmentAuthorizationBytes,
      ),
      manifestCheckpoint: new Uint8Array(LIMITS.manifestCheckpointBytes),
      manifestAuthorization: new Uint8Array(LIMITS.manifestAuthorizationBytes),
    });
    expect(encoded.byteLength).toBe(LIMITS.totalBytes);
    expect(() =>
      encodeAncV1EnrollmentAuthorizationBundle({
        ...value,
        manifestCheckpoint: new Uint8Array(LIMITS.manifestCheckpointBytes + 1),
      }),
    ).toThrow(AncV1EnrollmentAuthorizationBundleError);
  });

  it.each([
    ["wrong magic", (bytes: Uint8Array) => (bytes[0] = 0)],
    ["wrong version", (bytes: Uint8Array) => (bytes[4] = 2)],
    ["zero member", (bytes: Uint8Array) => bytes.fill(0, 5, 9)],
    ["oversized member", (bytes: Uint8Array) => bytes.fill(0xff, 9, 13)],
    ["declared length mismatch", (bytes: Uint8Array) => (bytes[8]! += 1)],
  ])("rejects %s", (_name, mutate) => {
    const encoded = encodeAncV1EnrollmentAuthorizationBundle(value);
    mutate(encoded);
    expect(() => decodeAncV1EnrollmentAuthorizationBundle(encoded)).toThrow(
      AncV1EnrollmentAuthorizationBundleError,
    );
  });

  it("rejects truncation, trailing bytes, empty members, and extra input fields", () => {
    const encoded = encodeAncV1EnrollmentAuthorizationBundle(value);
    for (const hostile of [
      encoded.slice(0, -1),
      Uint8Array.from([...encoded, 0]),
      encoded.slice(0, 17),
    ]) {
      expect(() => decodeAncV1EnrollmentAuthorizationBundle(hostile)).toThrow(
        AncV1EnrollmentAuthorizationBundleError,
      );
    }
    expect(() =>
      encodeAncV1EnrollmentAuthorizationBundle({
        ...value,
        extra: Uint8Array.of(1),
      } as typeof value),
    ).toThrow(AncV1EnrollmentAuthorizationBundleError);
  });
});
