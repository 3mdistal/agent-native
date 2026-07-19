import sodium from "libsodium-wrappers-sumo";
import { beforeAll, describe, expect, it } from "vitest";

import {
  ANC_BROKER_REPLACEMENT_APPROVAL_FIELDS,
  type AncV1BrokerReplacementApprovalExpectations,
  type AncV1UnsignedBrokerReplacementApproval,
  decodeAncV1BrokerReplacementApproval,
  encodeAncV1BrokerReplacementApproval,
  hashAncV1BrokerReplacementFreezeId,
  signAncV1BrokerReplacementApproval,
  verifyAncV1BrokerReplacementApproval,
} from "./broker-replacement-approval-codecs.js";
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

describe("anc/v1 broker replacement approval", () => {
  let issuer: sodium.KeyPair;
  let encoded: Uint8Array;
  let expected: AncV1BrokerReplacementApprovalExpectations;
  const enrollmentRef = sequence(0x10, 16);
  const unsigned: AncV1UnsignedBrokerReplacementApproval = {
    suite: "anc/v1",
    vaultId: sequence(0x00, 16),
    type: "broker_replacement_approval",
    createdAtSeconds: 1_784_452_201,
    envelopeId: enrollmentRef,
    issuerEndpointId: sequence(0x20, 16),
    oldBrokerEndpointId: sequence(0x30, 16),
    candidateBrokerEndpointId: sequence(0x40, 16),
    candidateSigningPublicKey: sequence(0x50, 32),
    candidateKeyAgreementPublicKey: sequence(0x70, 32),
    candidateEnrollmentRef: enrollmentRef,
    offerHash: sequence(0x90, 32),
    challengeHash: sequence(0xb0, 32),
    sasDecisionHash: sequence(0xd0, 32),
    baseSequence: 31,
    baseHeadHash: sequence(0x11, 32),
    baseMembershipHash: sequence(0x31, 32),
    baseEpoch: 7,
    drainId: sequence(0x61, 16),
    drainGeneration: 11,
    deadlineAtSeconds: 1_784_455_801,
  };

  beforeAll(async () => {
    await sodium.ready;
    issuer = sodium.crypto_sign_seed_keypair(sequence(0xe0, 32));
    encoded = encodeAncV1BrokerReplacementApproval(
      await signAncV1BrokerReplacementApproval(unsigned, issuer.privateKey),
    );
    expected = {
      vaultId: unsigned.vaultId,
      issuerEndpointId: unsigned.issuerEndpointId,
      oldBrokerEndpointId: unsigned.oldBrokerEndpointId,
      candidateBrokerEndpointId: unsigned.candidateBrokerEndpointId,
      candidateSigningPublicKey: unsigned.candidateSigningPublicKey,
      candidateKeyAgreementPublicKey: unsigned.candidateKeyAgreementPublicKey,
      candidateEnrollmentRef: unsigned.candidateEnrollmentRef,
      offerHash: unsigned.offerHash,
      challengeHash: unsigned.challengeHash,
      sasDecisionHash: unsigned.sasDecisionHash,
      baseSequence: unsigned.baseSequence,
      baseHeadHash: unsigned.baseHeadHash,
      baseMembershipHash: unsigned.baseMembershipHash,
      baseEpoch: unsigned.baseEpoch,
      drainId: unsigned.drainId,
      drainGeneration: unsigned.drainGeneration,
      deadlineAtSeconds: unsigned.deadlineAtSeconds,
      expectedCreatedAtSeconds: unsigned.createdAtSeconds,
      nowSeconds: unsigned.createdAtSeconds,
      issuerSigningPublicKey: issuer.publicKey,
    };
  });

  it("freezes the canonical signed approval and freeze identifier", async () => {
    expect(ancV1BytesToHex(encoded)).toBe(
      "b60166616e632f76310250000102030405060708090a0b0c0d0e0f03781b62726f6b65725f7265706c6163656d656e745f617070726f76616c041a6a5c94690550101112131415161718191a1b1c1d1e1f19026c50202122232425262728292a2b2c2d2e2f19026d50303132333435363738393a3b3c3d3e3f19026e50404142434445464748494a4b4c4d4e4f19026f5820505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f1902705820707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f19027150101112131415161718191a1b1c1d1e1f1902725820909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf1902735820b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecf1902745820d0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeef190275181f19027658201112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3019027758203132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f5019027807190279506162636465666768696a6b6c6d6e6f7019027a0b19027b1a6a5ca27919027c584000879828e6fbee5989d05e59cd6b998d826bf40c66d2afbe5116240d64110c0e42e1d7a184fce9d75f4d8f9ae18432215c5aed4e857f754fccdc198515344800",
    );
    expect(
      ancV1BytesToHex(await hashAncV1BrokerReplacementFreezeId(encoded)),
    ).toBe("ae073b3a1fe16f05bb2eb869e7970778");
  });

  it("verifies all candidate, enrollment, ceremony, control, epoch, and lane bindings", async () => {
    const value = await verifyAncV1BrokerReplacementApproval(encoded, expected);
    expect(value.candidateEnrollmentRef).toEqual(value.envelopeId);
    expect(value.deadlineAtSeconds).toBe(unsigned.deadlineAtSeconds);
  });

  it.each([
    ["vault", "vaultId"],
    ["issuer", "issuerEndpointId"],
    ["old broker", "oldBrokerEndpointId"],
    ["candidate", "candidateBrokerEndpointId"],
    ["candidate signing key", "candidateSigningPublicKey"],
    ["candidate agreement key", "candidateKeyAgreementPublicKey"],
    ["candidate enrollment", "candidateEnrollmentRef"],
    ["offer", "offerHash"],
    ["challenge", "challengeHash"],
    ["SAS decision", "sasDecisionHash"],
    ["control head", "baseHeadHash"],
    ["membership", "baseMembershipHash"],
    ["drain lane", "drainId"],
  ] as const)("rejects a substituted %s binding", async (_name, field) => {
    await expect(
      verifyAncV1BrokerReplacementApproval(encoded, {
        ...expected,
        [field]: changed(expected[field]),
      }),
    ).rejects.toThrow(/expected value/);
  });

  it.each([
    ["sequence", "baseSequence"],
    ["epoch", "baseEpoch"],
    ["drain generation", "drainGeneration"],
    ["deadline", "deadlineAtSeconds"],
  ] as const)("rejects a substituted %s binding", async (_name, field) => {
    await expect(
      verifyAncV1BrokerReplacementApproval(encoded, {
        ...expected,
        [field]: expected[field] + 1,
      }),
    ).rejects.toThrow(/expected value/);
  });

  it("rejects the wrong issuer key and signature tampering", async () => {
    const other = sodium.crypto_sign_seed_keypair(sequence(0x01, 32));
    await expect(
      verifyAncV1BrokerReplacementApproval(encoded, {
        ...expected,
        issuerSigningPublicKey: other.publicKey,
      }),
    ).rejects.toThrow(/signature is invalid/);
    const value = decodeAncV1BrokerReplacementApproval(encoded);
    const tampered = encodeAncV1BrokerReplacementApproval({
      ...value,
      signature: changed(value.signature),
    });
    await expect(
      verifyAncV1BrokerReplacementApproval(tampered, expected),
    ).rejects.toThrow(/signature is invalid/);
  });

  it("requires the enrollment reference to equal the envelope identifier", async () => {
    await expect(
      signAncV1BrokerReplacementApproval(
        { ...unsigned, candidateEnrollmentRef: changed(enrollmentRef) },
        issuer.privateKey,
      ),
    ).rejects.toThrow(/must equal envelopeId/);
  });

  it("requires a candidate distinct from both old broker and issuer", async () => {
    await expect(
      signAncV1BrokerReplacementApproval(
        { ...unsigned, oldBrokerEndpointId: unsigned.issuerEndpointId },
        issuer.privateKey,
      ),
    ).rejects.toThrow(/old broker must differ from the issuer/);
    await expect(
      signAncV1BrokerReplacementApproval(
        {
          ...unsigned,
          candidateBrokerEndpointId: unsigned.oldBrokerEndpointId,
        },
        issuer.privateKey,
      ),
    ).rejects.toThrow(/old broker/);
    await expect(
      signAncV1BrokerReplacementApproval(
        {
          ...unsigned,
          candidateBrokerEndpointId: unsigned.issuerEndpointId,
        },
        issuer.privateKey,
      ),
    ).rejects.toThrow(/issuer/);
  });

  it("enforces timestamp freshness and exact trusted creation time", async () => {
    await expect(
      verifyAncV1BrokerReplacementApproval(encoded, {
        ...expected,
        expectedCreatedAtSeconds: unsigned.createdAtSeconds + 1,
      }),
    ).rejects.toThrow(/createdAtSeconds/);
    await expect(
      verifyAncV1BrokerReplacementApproval(encoded, {
        ...expected,
        nowSeconds: unsigned.createdAtSeconds + 900,
      }),
    ).resolves.toBeDefined();
    await expect(
      verifyAncV1BrokerReplacementApproval(encoded, {
        ...expected,
        nowSeconds: unsigned.createdAtSeconds + 901,
      }),
    ).rejects.toThrow(/stale/);

    const future = {
      ...unsigned,
      createdAtSeconds: unsigned.createdAtSeconds + 61,
      deadlineAtSeconds: unsigned.deadlineAtSeconds + 61,
    };
    const futureEncoded = encodeAncV1BrokerReplacementApproval(
      await signAncV1BrokerReplacementApproval(future, issuer.privateKey),
    );
    await expect(
      verifyAncV1BrokerReplacementApproval(futureEncoded, {
        ...expected,
        expectedCreatedAtSeconds: future.createdAtSeconds,
        deadlineAtSeconds: future.deadlineAtSeconds,
      }),
    ).rejects.toThrow(/future/);
  });

  it("requires a live deadline no more than 24 hours after creation", async () => {
    const shortDeadline = unsigned.createdAtSeconds + 100;
    const shortEncoded = encodeAncV1BrokerReplacementApproval(
      await signAncV1BrokerReplacementApproval(
        { ...unsigned, deadlineAtSeconds: shortDeadline },
        issuer.privateKey,
      ),
    );
    await expect(
      verifyAncV1BrokerReplacementApproval(shortEncoded, {
        ...expected,
        deadlineAtSeconds: shortDeadline,
        nowSeconds: shortDeadline,
      }),
    ).rejects.toThrow(/deadline has elapsed/);
    await expect(
      signAncV1BrokerReplacementApproval(
        { ...unsigned, deadlineAtSeconds: unsigned.createdAtSeconds },
        issuer.privateKey,
      ),
    ).rejects.toThrow(/must be after/);
    await expect(
      signAncV1BrokerReplacementApproval(
        {
          ...unsigned,
          deadlineAtSeconds: unsigned.createdAtSeconds + 86_401,
        },
        issuer.privateKey,
      ),
    ).rejects.toThrow(/24-hour/);
  });

  it("rejects unknown fields and non-canonical trailing bytes", () => {
    const map = decodeAncV1Canonical(encoded) as Map<number, unknown>;
    map.set(637, 1);
    expect(() =>
      decodeAncV1BrokerReplacementApproval(
        encodeAncV1Canonical(map as Map<number, never>),
      ),
    ).toThrow(/unknown key 637/);
    const trailing = new Uint8Array(encoded.byteLength + 1);
    trailing.set(encoded);
    expect(() => decodeAncV1BrokerReplacementApproval(trailing)).toThrow();
  });

  it("rejects missing required fields", () => {
    const map = decodeAncV1Canonical(encoded) as Map<number, unknown>;
    map.delete(ANC_BROKER_REPLACEMENT_APPROVAL_FIELDS.offerHash);
    expect(() =>
      decodeAncV1BrokerReplacementApproval(
        encodeAncV1Canonical(map as Map<number, never>),
      ),
    ).toThrow(/exactly its versioned fields/);
  });
});
