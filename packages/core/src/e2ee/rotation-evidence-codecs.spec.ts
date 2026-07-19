import { describe, expect, it } from "vitest";

import { ancV1SigningKeypairFromSeed } from "./portable-crypto.js";
import {
  ANC_ROTATION_EVIDENCE_SUITE_ID,
  AncV1RotationEvidenceError,
  decodeAncV1RotationManifestCheckpoint,
  encodeAncV1RotationManifestCheckpoint,
  encodeAncV1RotationRecipientAcknowledgement,
  encodeAncV1RotationRecipientOffer,
  hashAncV1RotationLiveRevisionSet,
  hashAncV1RotationManifestCheckpoint,
  signAncV1RotationManifestCheckpoint,
  signAncV1RotationRecipientAcknowledgement,
  signAncV1RotationRecipientOffer,
  verifyAncV1RotationAcknowledgementSet,
  verifyAncV1RotationManifestCheckpoint,
  verifyAncV1RotationRecipientAcknowledgement,
  verifyAncV1RotationRecipientOffer,
  type AncV1UnsignedRotationManifestCheckpoint,
  type AncV1UnsignedRotationRecipientAcknowledgement,
  type AncV1UnsignedRotationRecipientOffer,
} from "./rotation-evidence-codecs.js";

const fill = (value: number, length = 16) => new Uint8Array(length).fill(value);
const vaultId = fill(1);
const ceremonyId = fill(2);
const issuerId = fill(3);
const removedId = fill(4);
const recipientOneId = fill(5);
const recipientTwoId = fill(6);
const pendingEpochKey = fill(7, 32);
const now = 1_784_451_800;

async function fixture() {
  const issuer = await ancV1SigningKeypairFromSeed(fill(10, 32));
  const recipientOne = await ancV1SigningKeypairFromSeed(fill(11, 32));
  const recipientTwo = await ancV1SigningKeypairFromSeed(fill(12, 32));
  const unsignedCheckpoint: AncV1UnsignedRotationManifestCheckpoint = {
    suite: ANC_ROTATION_EVIDENCE_SUITE_ID,
    vaultId,
    type: "rotation-manifest-checkpoint",
    createdAt: now - 20,
    envelopeId: fill(13),
    ceremonyId,
    baseSequence: 8,
    baseHeadHash: fill(14, 32),
    baseEpoch: 3,
    targetEpoch: 4,
    manifestObjectId: fill(15),
    revisionId: fill(16, 32),
    generation: 9,
    ciphertextHash: fill(17, 32),
    liveObjectCount: 2,
    liveRevisionCount: 2,
    liveRevisionSetHash: fill(18, 32),
    signerEndpointId: issuerId,
    removedEndpointId: removedId,
  };
  const checkpoint = await signAncV1RotationManifestCheckpoint(
    unsignedCheckpoint,
    issuer.privateKey,
  );
  const encodedCheckpoint = encodeAncV1RotationManifestCheckpoint(checkpoint);
  const checkpointHash = await hashAncV1RotationManifestCheckpoint(
    encodedCheckpoint,
    vaultId,
  );
  const makeRecipient = async (input: {
    id: Uint8Array;
    keys: Awaited<ReturnType<typeof ancV1SigningKeypairFromSeed>>;
    marker: number;
  }) => {
    const eekWrapHash = fill(input.marker, 32);
    const unsignedOffer: AncV1UnsignedRotationRecipientOffer = {
      suite: ANC_ROTATION_EVIDENCE_SUITE_ID,
      vaultId,
      type: "rotation-recipient-offer",
      createdAt: now - 10,
      envelopeId: fill(input.marker),
      ceremonyId,
      checkpointHash,
      eekWrapHash,
      recipientEndpointId: input.id,
      issuerEndpointId: issuerId,
      targetEpoch: 4,
      expiresAt: now + 300,
    };
    const encodedOffer = encodeAncV1RotationRecipientOffer(
      await signAncV1RotationRecipientOffer(unsignedOffer, issuer.privateKey),
    );
    const unsignedAck: AncV1UnsignedRotationRecipientAcknowledgement = {
      suite: ANC_ROTATION_EVIDENCE_SUITE_ID,
      vaultId,
      type: "rotation-recipient-acknowledgement",
      createdAt: now,
      envelopeId: fill(input.marker + 20),
      ceremonyId,
      checkpointHash,
      eekWrapHash,
      recipientEndpointId: input.id,
      targetEpoch: 4,
    };
    const encodedAck = encodeAncV1RotationRecipientAcknowledgement(
      await signAncV1RotationRecipientAcknowledgement(unsignedAck, {
        recipientSigningPrivateKey: input.keys.privateKey,
        pendingEpochKey,
      }),
    );
    return { encodedOffer, encodedAck, eekWrapHash, keys: input.keys };
  };
  const one = await makeRecipient({
    id: recipientOneId,
    keys: recipientOne,
    marker: 21,
  });
  const two = await makeRecipient({
    id: recipientTwoId,
    keys: recipientTwo,
    marker: 22,
  });
  return { issuer, encodedCheckpoint, checkpointHash, one, two };
}

describe("anc/rotation/v1 evidence", () => {
  it("binds the new manifest, each EEK wrap, and complete key-possession coverage", async () => {
    const value = await fixture();
    const checkpoint = await verifyAncV1RotationManifestCheckpoint(
      value.encodedCheckpoint,
      {
        expectedVaultId: vaultId,
        signerSigningPublicKey: value.issuer.publicKey,
      },
    );
    expect(checkpoint.targetEpoch).toBe(4);
    expect(
      encodeAncV1RotationManifestCheckpoint(
        decodeAncV1RotationManifestCheckpoint(value.encodedCheckpoint, {
          expectedVaultId: vaultId,
        }),
      ),
    ).toEqual(value.encodedCheckpoint);

    await expect(
      verifyAncV1RotationRecipientOffer(value.one.encodedOffer, {
        expectedVaultId: vaultId,
        issuerSigningPublicKey: value.issuer.publicKey,
        now,
      }),
    ).resolves.toMatchObject({ targetEpoch: 4 });
    await expect(
      verifyAncV1RotationRecipientAcknowledgement(value.one.encodedAck, {
        expectedVaultId: vaultId,
        recipientSigningPublicKey: value.one.keys.publicKey,
        pendingEpochKey,
      }),
    ).resolves.toMatchObject({ targetEpoch: 4 });
    await expect(
      verifyAncV1RotationAcknowledgementSet({
        encodedAcknowledgements: [value.two.encodedAck, value.one.encodedAck],
        expectedVaultId: vaultId,
        expectedCeremonyId: ceremonyId,
        expectedCheckpointHash: value.checkpointHash,
        expectedTargetEpoch: 4,
        expectedRecipients: [
          {
            endpointId: recipientOneId,
            signingPublicKey: value.one.keys.publicKey,
            eekWrapHash: value.one.eekWrapHash,
          },
          {
            endpointId: recipientTwoId,
            signingPublicKey: value.two.keys.publicKey,
            eekWrapHash: value.two.eekWrapHash,
          },
        ],
        pendingEpochKey,
      }),
    ).resolves.toHaveLength(2);
  });

  it("rejects missing, duplicate, substituted, and non-possessing acknowledgements", async () => {
    const value = await fixture();
    const input = {
      expectedVaultId: vaultId,
      expectedCeremonyId: ceremonyId,
      expectedCheckpointHash: value.checkpointHash,
      expectedTargetEpoch: 4,
      expectedRecipients: [
        {
          endpointId: recipientOneId,
          signingPublicKey: value.one.keys.publicKey,
          eekWrapHash: value.one.eekWrapHash,
        },
        {
          endpointId: recipientTwoId,
          signingPublicKey: value.two.keys.publicKey,
          eekWrapHash: value.two.eekWrapHash,
        },
      ],
      pendingEpochKey,
    } as const;
    await expect(
      verifyAncV1RotationAcknowledgementSet({
        ...input,
        encodedAcknowledgements: [value.one.encodedAck],
      }),
    ).rejects.toBeInstanceOf(AncV1RotationEvidenceError);
    await expect(
      verifyAncV1RotationAcknowledgementSet({
        ...input,
        encodedAcknowledgements: [value.one.encodedAck, value.one.encodedAck],
      }),
    ).rejects.toBeInstanceOf(AncV1RotationEvidenceError);
    await expect(
      verifyAncV1RotationAcknowledgementSet({
        ...input,
        expectedCeremonyId: fill(0xee),
        encodedAcknowledgements: [value.one.encodedAck, value.two.encodedAck],
      }),
    ).rejects.toBeInstanceOf(AncV1RotationEvidenceError);
    await expect(
      verifyAncV1RotationRecipientAcknowledgement(value.one.encodedAck, {
        expectedVaultId: vaultId,
        recipientSigningPublicKey: value.one.keys.publicKey,
        pendingEpochKey: fill(0xdd, 32),
      }),
    ).rejects.toBeInstanceOf(AncV1RotationEvidenceError);
  });

  it("rejects future, expired, and tampered recipient offers", async () => {
    const value = await fixture();
    await expect(
      verifyAncV1RotationRecipientOffer(value.one.encodedOffer, {
        expectedVaultId: vaultId,
        issuerSigningPublicKey: value.issuer.publicKey,
        now: now - 11,
      }),
    ).rejects.toBeInstanceOf(AncV1RotationEvidenceError);
    await expect(
      verifyAncV1RotationRecipientOffer(value.one.encodedOffer, {
        expectedVaultId: vaultId,
        issuerSigningPublicKey: value.issuer.publicKey,
        now: now + 301,
      }),
    ).rejects.toBeInstanceOf(AncV1RotationEvidenceError);
    const tampered = value.one.encodedOffer.slice();
    tampered[tampered.byteLength - 1] ^= 1;
    await expect(
      verifyAncV1RotationRecipientOffer(tampered, {
        expectedVaultId: vaultId,
        issuerSigningPublicKey: value.issuer.publicKey,
        now,
      }),
    ).rejects.toBeInstanceOf(Error);
  });

  it("canonicalizes the complete live revision mapping and rejects omissions by coordinate", async () => {
    const first = {
      objectId: fill(0x31),
      revision: 2,
      priorRevisionId: fill(0x32, 32),
      rotatedRevisionId: fill(0x33, 32),
    };
    const second = {
      objectId: fill(0x21),
      revision: 1,
      priorRevisionId: fill(0x22, 32),
      rotatedRevisionId: fill(0x23, 32),
    };
    await expect(
      hashAncV1RotationLiveRevisionSet([first, second]),
    ).resolves.toEqual(await hashAncV1RotationLiveRevisionSet([second, first]));
    await expect(
      hashAncV1RotationLiveRevisionSet([first, first]),
    ).rejects.toBeInstanceOf(AncV1RotationEvidenceError);
  });
});
