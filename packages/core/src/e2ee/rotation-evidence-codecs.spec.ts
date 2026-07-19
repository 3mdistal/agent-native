import { describe, expect, it } from "vitest";

import { ancV1SigningKeypairFromSeed } from "./portable-crypto.js";
import {
  ANC_ROTATION_EVIDENCE_SUITE_ID,
  AncV1RotationEvidenceError,
  decodeAncV1RotationManifestCheckpoint,
  encodeAncV1RotationControlCommitAttestation,
  encodeAncV1RotationEpochDestructionAttestation,
  encodeAncV1RotationManifestCheckpoint,
  encodeAncV1RotationRecipientAcknowledgement,
  encodeAncV1RotationRecipientOffer,
  hashAncV1RotationLiveRevisionSet,
  hashAncV1RotationRecipientOffer,
  hashAncV1RotationRecipientSet,
  hashAncV1RotationManifestCheckpoint,
  hashAncV1RotationHostedReceipt,
  signAncV1RotationControlCommitAttestation,
  signAncV1RotationEpochDestructionAttestation,
  signAncV1RotationManifestCheckpoint,
  signAncV1RotationRecipientAcknowledgement,
  signAncV1RotationRecipientOffer,
  verifyAncV1RotationAcknowledgementSet,
  verifyAncV1RotationControlCommitAttestation,
  verifyAncV1RotationEpochDestructionAttestation,
  verifyAncV1RotationManifestCheckpoint,
  verifyAncV1RotationLiveRevisionSetAgainstCheckpoint,
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
const recipientOneId = issuerId;
const recipientTwoId = fill(6);
const pendingEpochKey = fill(7, 32);
const now = 1_784_451_800;

async function fixture() {
  const issuer = await ancV1SigningKeypairFromSeed(fill(10, 32));
  const recipientOne = issuer;
  const recipientTwo = await ancV1SigningKeypairFromSeed(fill(12, 32));
  const eekWrapHashOne = fill(21, 32);
  const eekWrapHashTwo = fill(22, 32);
  const liveRevisions = [
    {
      objectId: fill(0x31),
      revision: 2,
      priorRevisionId: fill(0x32, 32),
      rotatedRevisionId: fill(0x33, 32),
    },
    {
      objectId: fill(0x21),
      revision: 1,
      priorRevisionId: fill(0x22, 32),
      rotatedRevisionId: fill(0x23, 32),
    },
  ];
  const recipientSet = [
    {
      endpointId: recipientOneId,
      signingPublicKey: recipientOne.publicKey,
      keyAgreementPublicKey: fill(0x41, 32),
      eekWrapHash: eekWrapHashOne,
    },
    {
      endpointId: recipientTwoId,
      signingPublicKey: recipientTwo.publicKey,
      keyAgreementPublicKey: fill(0x42, 32),
      eekWrapHash: eekWrapHashTwo,
    },
  ];
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
    liveRevisionSetHash: await hashAncV1RotationLiveRevisionSet(liveRevisions),
    recipientSetHash: await hashAncV1RotationRecipientSet(recipientSet),
    controlEntryHash: fill(18, 32),
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
    const eekWrapHash =
      input.id === recipientOneId ? eekWrapHashOne : eekWrapHashTwo;
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
    const offerHash = await hashAncV1RotationRecipientOffer(
      encodedOffer,
      vaultId,
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
      offerHash,
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
  return {
    issuer,
    encodedCheckpoint,
    checkpointHash,
    recipientSet,
    liveRevisions,
    one,
    two,
  };
}

describe("anc/rotation/v1 evidence", () => {
  it("binds the new manifest, each EEK wrap, and complete key-possession coverage", async () => {
    const value = await fixture();
    const checkpoint = await verifyAncV1RotationManifestCheckpoint(
      value.encodedCheckpoint,
      {
        expectedVaultId: vaultId,
        expectedSignerEndpointId: issuerId,
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
        expectedIssuerEndpointId: issuerId,
        expectedRecipientEndpointId: recipientOneId,
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
        encodedCheckpoint: value.encodedCheckpoint,
        expectedVaultId: vaultId,
        expectedSignerEndpointId: issuerId,
        signerSigningPublicKey: value.issuer.publicKey,
        expectedRecipients: [
          {
            ...value.recipientSet[0]!,
            encodedOffer: value.one.encodedOffer,
          },
          {
            ...value.recipientSet[1]!,
            encodedOffer: value.two.encodedOffer,
          },
        ],
        pendingEpochKey,
        now,
      }),
    ).resolves.toHaveLength(2);
  });

  it("rejects missing, duplicate, substituted, and non-possessing acknowledgements", async () => {
    const value = await fixture();
    const input = {
      encodedCheckpoint: value.encodedCheckpoint,
      expectedVaultId: vaultId,
      expectedSignerEndpointId: issuerId,
      signerSigningPublicKey: value.issuer.publicKey,
      expectedRecipients: [
        {
          ...value.recipientSet[0]!,
          encodedOffer: value.one.encodedOffer,
        },
        {
          ...value.recipientSet[1]!,
          encodedOffer: value.two.encodedOffer,
        },
      ],
      pendingEpochKey,
      now,
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
        expectedSignerEndpointId: fill(0xee),
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
        expectedIssuerEndpointId: issuerId,
        expectedRecipientEndpointId: recipientOneId,
        issuerSigningPublicKey: value.issuer.publicKey,
        now: now - 71,
      }),
    ).rejects.toBeInstanceOf(AncV1RotationEvidenceError);
    await expect(
      verifyAncV1RotationRecipientOffer(value.one.encodedOffer, {
        expectedVaultId: vaultId,
        expectedIssuerEndpointId: issuerId,
        expectedRecipientEndpointId: recipientOneId,
        issuerSigningPublicKey: value.issuer.publicKey,
        now: now + 361,
      }),
    ).rejects.toBeInstanceOf(AncV1RotationEvidenceError);
    const tampered = value.one.encodedOffer.slice();
    tampered[tampered.byteLength - 1] ^= 1;
    await expect(
      verifyAncV1RotationRecipientOffer(tampered, {
        expectedVaultId: vaultId,
        expectedIssuerEndpointId: issuerId,
        expectedRecipientEndpointId: recipientOneId,
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
    const value = await fixture();
    const checkpoint = decodeAncV1RotationManifestCheckpoint(
      value.encodedCheckpoint,
      { expectedVaultId: vaultId },
    );
    await expect(
      verifyAncV1RotationLiveRevisionSetAgainstCheckpoint(
        value.liveRevisions,
        checkpoint,
      ),
    ).resolves.toBeUndefined();
    await expect(
      verifyAncV1RotationLiveRevisionSetAgainstCheckpoint(
        value.liveRevisions.slice(1),
        checkpoint,
      ),
    ).rejects.toBeInstanceOf(AncV1RotationEvidenceError);
  });

  it("rejects skipped epochs and spoofed or removed signer identities", async () => {
    const value = await fixture();
    const signed = decodeAncV1RotationManifestCheckpoint(
      value.encodedCheckpoint,
      { expectedVaultId: vaultId },
    );
    const { signature: _signature, ...unsigned } = signed;
    const skipped = encodeAncV1RotationManifestCheckpoint(
      await signAncV1RotationManifestCheckpoint(
        { ...unsigned, targetEpoch: unsigned.baseEpoch + 2 },
        value.issuer.privateKey,
      ),
    );
    await expect(
      verifyAncV1RotationManifestCheckpoint(skipped, {
        expectedVaultId: vaultId,
        expectedSignerEndpointId: issuerId,
        signerSigningPublicKey: value.issuer.publicKey,
      }),
    ).rejects.toBeInstanceOf(AncV1RotationEvidenceError);
    const spoofed = encodeAncV1RotationManifestCheckpoint(
      await signAncV1RotationManifestCheckpoint(
        { ...unsigned, signerEndpointId: fill(0xee) },
        value.issuer.privateKey,
      ),
    );
    await expect(
      verifyAncV1RotationManifestCheckpoint(spoofed, {
        expectedVaultId: vaultId,
        expectedSignerEndpointId: issuerId,
        signerSigningPublicKey: value.issuer.publicKey,
      }),
    ).rejects.toBeInstanceOf(AncV1RotationEvidenceError);
    const selfRemoval = encodeAncV1RotationManifestCheckpoint(
      await signAncV1RotationManifestCheckpoint(
        { ...unsigned, removedEndpointId: issuerId },
        value.issuer.privateKey,
      ),
    );
    await expect(
      verifyAncV1RotationManifestCheckpoint(selfRemoval, {
        expectedVaultId: vaultId,
        expectedSignerEndpointId: issuerId,
        signerSigningPublicKey: value.issuer.publicKey,
      }),
    ).rejects.toBeInstanceOf(AncV1RotationEvidenceError);
  });

  it("binds local old-epoch destruction and the final hosted control receipt", async () => {
    const value = await fixture();
    const checkpoint = decodeAncV1RotationManifestCheckpoint(
      value.encodedCheckpoint,
      { expectedVaultId: vaultId },
    );
    const destruction = encodeAncV1RotationEpochDestructionAttestation(
      await signAncV1RotationEpochDestructionAttestation(
        {
          suite: ANC_ROTATION_EVIDENCE_SUITE_ID,
          vaultId,
          type: "rotation-epoch-destruction-attestation",
          createdAt: now,
          envelopeId: fill(0x51),
          ceremonyId,
          checkpointHash: value.checkpointHash,
          controlEntryHash: checkpoint.controlEntryHash,
          endpointId: issuerId,
          destroyedEpoch: 3,
          activatedEpoch: 4,
          custodyGeneration: 8,
        },
        value.issuer.privateKey,
      ),
    );
    await expect(
      verifyAncV1RotationEpochDestructionAttestation(destruction, {
        expectedVaultId: vaultId,
        expectedEndpointId: issuerId,
        endpointSigningPublicKey: value.issuer.publicKey,
      }),
    ).resolves.toMatchObject({ destroyedEpoch: 3, activatedEpoch: 4 });
    await expect(
      verifyAncV1RotationEpochDestructionAttestation(destruction, {
        expectedVaultId: vaultId,
        expectedEndpointId: fill(0xee),
        endpointSigningPublicKey: value.issuer.publicKey,
      }),
    ).rejects.toBeInstanceOf(AncV1RotationEvidenceError);

    const hostedReceiptHash = await hashAncV1RotationHostedReceipt(
      new Uint8Array([0xa1, 0x01, 0x02]),
    );
    const completion = encodeAncV1RotationControlCommitAttestation(
      await signAncV1RotationControlCommitAttestation(
        {
          suite: ANC_ROTATION_EVIDENCE_SUITE_ID,
          vaultId,
          type: "rotation-control-commit-attestation",
          createdAt: now + 1,
          envelopeId: fill(0x61),
          ceremonyId,
          checkpointHash: value.checkpointHash,
          controlEntryHash: checkpoint.controlEntryHash,
          hostedReceiptHash,
          signerEndpointId: issuerId,
          committedSequence: 9,
          committedHeadHash: fill(0x62, 32),
          recipientSetHash: checkpoint.recipientSetHash,
        },
        value.issuer.privateKey,
      ),
    );
    await expect(
      verifyAncV1RotationControlCommitAttestation(completion, {
        expectedVaultId: vaultId,
        expectedSignerEndpointId: issuerId,
        expectedHostedReceiptHash: hostedReceiptHash,
        signerSigningPublicKey: value.issuer.publicKey,
      }),
    ).resolves.toMatchObject({ committedSequence: 9 });
  });
});
