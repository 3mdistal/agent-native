import sodium from "libsodium-wrappers-sumo";
import { beforeAll, describe, expect, it } from "vitest";

import {
  ANC_BROKER_DRAIN_ATTESTATION_FIELDS,
  type AncV1BrokerDrainAttestationExpectations,
  type AncV1UnsignedBrokerDrainAttestation,
  decodeAncV1BrokerDrainAttestation,
  encodeAncV1BrokerDrainAttestation,
  hashAncV1BrokerDrainCeremonyId,
  signAncV1BrokerDrainAttestation,
  verifyAncV1BrokerDrainAttestation,
} from "./broker-drain-attestation-codecs.js";
import {
  ancV1BytesToHex,
  decodeAncV1Canonical,
  encodeAncV1Canonical,
} from "./canonical.js";

const sequence = (start: number, length: number) =>
  Uint8Array.from({ length }, (_, index) => (start + index) & 0xff);
const changed = (value: Uint8Array) => {
  const output = value.slice();
  output[0] ^= 0xff;
  return output;
};

describe("anc/v1 broker drain attestation", () => {
  let issuer: sodium.KeyPair;
  let encoded: Uint8Array;
  let expectations: AncV1BrokerDrainAttestationExpectations;
  const unsigned: AncV1UnsignedBrokerDrainAttestation = {
    suite: "anc/v1",
    vaultId: sequence(0x00, 16),
    type: "broker_drain_attestation",
    createdAtSeconds: 1_784_452_201,
    envelopeId: sequence(0x10, 16),
    issuerEndpointId: sequence(0x20, 16),
    oldBrokerEndpointId: sequence(0x30, 16),
    candidateBrokerEndpointId: sequence(0x40, 16),
    candidateSigningPublicKey: sequence(0x50, 32),
    candidateKeyAgreementPublicKey: sequence(0x70, 32),
    candidateEnrollmentRef: sequence(0x90, 16),
    baseSequence: 31,
    baseHeadHash: sequence(0xa0, 32),
    baseEpoch: 7,
    drainGeneration: 11,
    drainedJobCount: 23,
    drainDigest: sequence(0xc0, 32),
    outstandingJobCount: 0,
  };

  beforeAll(async () => {
    await sodium.ready;
    issuer = sodium.crypto_sign_seed_keypair(sequence(0xe0, 32));
    encoded = encodeAncV1BrokerDrainAttestation(
      await signAncV1BrokerDrainAttestation(unsigned, issuer.privateKey),
    );
    expectations = {
      vaultId: unsigned.vaultId,
      issuerEndpointId: unsigned.issuerEndpointId,
      oldBrokerEndpointId: unsigned.oldBrokerEndpointId,
      candidateBrokerEndpointId: unsigned.candidateBrokerEndpointId,
      candidateSigningPublicKey: unsigned.candidateSigningPublicKey,
      candidateKeyAgreementPublicKey: unsigned.candidateKeyAgreementPublicKey,
      candidateEnrollmentRef: unsigned.candidateEnrollmentRef,
      baseSequence: unsigned.baseSequence,
      baseHeadHash: unsigned.baseHeadHash,
      baseEpoch: unsigned.baseEpoch,
      drainGeneration: unsigned.drainGeneration,
      drainedJobCount: unsigned.drainedJobCount,
      drainDigest: unsigned.drainDigest,
      expectedCreatedAtSeconds: unsigned.createdAtSeconds,
      nowSeconds: unsigned.createdAtSeconds,
      issuerSigningPublicKey: issuer.publicKey,
    };
  });

  it("freezes the canonical signed artifact and ceremony identifier", async () => {
    expect(ancV1BytesToHex(encoded)).toBe(
      "b30166616e632f76310250000102030405060708090a0b0c0d0e0f03781862726f6b65725f647261696e5f6174746573746174696f6e041a6a5c94690550101112131415161718191a1b1c1d1e1f19025850202122232425262728292a2b2c2d2e2f19025950303132333435363738393a3b3c3d3e3f19025a50404142434445464748494a4b4c4d4e4f19025b5820505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f19025c5820707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f19025d50909192939495969798999a9b9c9d9e9f19025e181f19025f5820a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf190260071902610b190262171902635820c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf1902640019026558405bc0e8e5c0ea88d7e7c27c3ca7b058032df3bcbde664310312083be858b139f91dce9a23fc308a0a9a0a2e986b1f5f0f70729ea7e803302a0af03b84f0c68805",
    );
    expect(ancV1BytesToHex(await hashAncV1BrokerDrainCeremonyId(encoded))).toBe(
      "ad7d174cac3f8e5784c199cd50841d33",
    );
  });

  it("verifies every expected authority, candidate, control, epoch, and drain binding", async () => {
    const verified = await verifyAncV1BrokerDrainAttestation(
      encoded,
      expectations,
    );
    expect(verified.outstandingJobCount).toBe(0);
    expect(verified.baseSequence).toBe(31);
  });

  it.each([
    ["vault", "vaultId"],
    ["issuer identity", "issuerEndpointId"],
    ["old broker identity", "oldBrokerEndpointId"],
    ["candidate identity", "candidateBrokerEndpointId"],
    ["candidate signing key", "candidateSigningPublicKey"],
    ["candidate agreement key", "candidateKeyAgreementPublicKey"],
    ["candidate enrollment", "candidateEnrollmentRef"],
    ["control head", "baseHeadHash"],
    ["drain digest", "drainDigest"],
  ] as const)("rejects a cross-%s substitution", async (_name, field) => {
    await expect(
      verifyAncV1BrokerDrainAttestation(encoded, {
        ...expectations,
        [field]: changed(expectations[field]),
      }),
    ).rejects.toThrow(/expected value/);
  });

  it.each([
    ["sequence", "baseSequence"],
    ["epoch", "baseEpoch"],
    ["drain generation", "drainGeneration"],
    ["drained count", "drainedJobCount"],
  ] as const)("rejects a mismatched %s", async (_name, field) => {
    await expect(
      verifyAncV1BrokerDrainAttestation(encoded, {
        ...expectations,
        [field]: expectations[field] + 1,
      }),
    ).rejects.toThrow(/expected value/);
  });

  it("rejects the wrong issuer signing key and a tampered signature", async () => {
    const otherIssuer = sodium.crypto_sign_seed_keypair(sequence(0x01, 32));
    await expect(
      verifyAncV1BrokerDrainAttestation(encoded, {
        ...expectations,
        issuerSigningPublicKey: otherIssuer.publicKey,
      }),
    ).rejects.toThrow(/signature is invalid/);

    const value = decodeAncV1BrokerDrainAttestation(encoded);
    const tampered = encodeAncV1BrokerDrainAttestation({
      ...value,
      signature: changed(value.signature),
    });
    await expect(
      verifyAncV1BrokerDrainAttestation(tampered, expectations),
    ).rejects.toThrow(/signature is invalid/);
  });

  it("rejects any outstanding work before signature verification", async () => {
    const map = decodeAncV1Canonical(encoded) as Map<number, unknown>;
    map.set(ANC_BROKER_DRAIN_ATTESTATION_FIELDS.outstandingJobCount, 1);
    expect(() =>
      decodeAncV1BrokerDrainAttestation(
        encodeAncV1Canonical(map as Map<number, never>),
      ),
    ).toThrow(/must be zero/);
  });

  it("rejects unknown fields", () => {
    const map = decodeAncV1Canonical(encoded) as Map<number, unknown>;
    map.set(614, 1);
    expect(() =>
      decodeAncV1BrokerDrainAttestation(
        encodeAncV1Canonical(map as Map<number, never>),
      ),
    ).toThrow(/unknown key 614/);
  });

  it("enforces the 15-minute age and 60-second future-skew windows", async () => {
    await expect(
      verifyAncV1BrokerDrainAttestation(encoded, {
        ...expectations,
        nowSeconds: unsigned.createdAtSeconds + 900,
      }),
    ).resolves.toBeDefined();
    await expect(
      verifyAncV1BrokerDrainAttestation(encoded, {
        ...expectations,
        nowSeconds: unsigned.createdAtSeconds + 901,
      }),
    ).rejects.toThrow(/stale/);

    const futureUnsigned = {
      ...unsigned,
      createdAtSeconds: unsigned.createdAtSeconds + 60,
    };
    const futureEncoded = encodeAncV1BrokerDrainAttestation(
      await signAncV1BrokerDrainAttestation(futureUnsigned, issuer.privateKey),
    );
    await expect(
      verifyAncV1BrokerDrainAttestation(futureEncoded, expectations),
    ).rejects.toThrow(/createdAtSeconds/);
    await expect(
      verifyAncV1BrokerDrainAttestation(futureEncoded, {
        ...expectations,
        expectedCreatedAtSeconds: futureUnsigned.createdAtSeconds,
      }),
    ).resolves.toBeDefined();
    const tooFarFuture = encodeAncV1BrokerDrainAttestation(
      await signAncV1BrokerDrainAttestation(
        { ...unsigned, createdAtSeconds: unsigned.createdAtSeconds + 61 },
        issuer.privateKey,
      ),
    );
    await expect(
      verifyAncV1BrokerDrainAttestation(tooFarFuture, {
        ...expectations,
        expectedCreatedAtSeconds: unsigned.createdAtSeconds + 61,
      }),
    ).rejects.toThrow(/future/);
  });
});
