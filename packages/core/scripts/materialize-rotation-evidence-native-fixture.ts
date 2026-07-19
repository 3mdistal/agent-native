import { writeFileSync } from "node:fs";

import { ancV1BytesToHex } from "../src/e2ee/canonical.js";
import { encodeAncV1ControlLogRotationAppendReceipt } from "../src/e2ee/control-log-append.js";
import { ancV1SigningKeypairFromSeed } from "../src/e2ee/portable-crypto.js";
import {
  ANC_ROTATION_EVIDENCE_SUITE_ID,
  encodeAncV1RotationControlCommitAttestation,
  encodeAncV1RotationEpochDestructionAttestation,
  encodeAncV1RotationManifestCheckpoint,
  encodeAncV1RotationRecipientAcknowledgement,
  encodeAncV1RotationRecipientOffer,
  hashAncV1RotationHostedReceipt,
  hashAncV1RotationLiveRevisionSet,
  hashAncV1RotationManifestCheckpoint,
  hashAncV1RotationRecipientOffer,
  hashAncV1RotationRecipientSet,
  signAncV1RotationControlCommitAttestation,
  signAncV1RotationEpochDestructionAttestation,
  signAncV1RotationManifestCheckpoint,
  signAncV1RotationRecipientAcknowledgement,
  signAncV1RotationRecipientOffer,
} from "../src/e2ee/rotation-evidence-codecs.js";

const outputPath = process.argv[2];
if (!outputPath)
  throw new Error(
    "usage: materialize-rotation-evidence-native-fixture.ts OUTPUT",
  );
const fill = (value: number, length = 16) => new Uint8Array(length).fill(value);
const hex = (value: Uint8Array) => ancV1BytesToHex(value);
const now = 1_784_451_800;
const vaultId = fill(1);
const ceremonyId = fill(2);
const issuerId = fill(3);
const removedId = fill(4);
const recipientTwoId = fill(6);
const pendingEpochKey = fill(7, 32);
const issuerSeed = fill(10, 32);
const recipientTwoSeed = fill(12, 32);
const issuer = await ancV1SigningKeypairFromSeed(issuerSeed);
const recipientTwo = await ancV1SigningKeypairFromSeed(recipientTwoSeed);
const recipientSet = [
  {
    endpointId: issuerId,
    signingPublicKey: issuer.publicKey,
    keyAgreementPublicKey: fill(0x41, 32),
    eekWrapHash: fill(21, 32),
  },
  {
    endpointId: recipientTwoId,
    signingPublicKey: recipientTwo.publicKey,
    keyAgreementPublicKey: fill(0x42, 32),
    eekWrapHash: fill(22, 32),
  },
];
const liveRevisionSetHash = await hashAncV1RotationLiveRevisionSet([
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
]);
const checkpoint = await signAncV1RotationManifestCheckpoint(
  {
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
    liveRevisionSetHash,
    recipientSetHash: await hashAncV1RotationRecipientSet(recipientSet),
    controlEntryHash: fill(18, 32),
    signerEndpointId: issuerId,
    removedEndpointId: removedId,
  },
  issuer.privateKey,
);
const encodedCheckpoint = encodeAncV1RotationManifestCheckpoint(checkpoint);
const checkpointHash = await hashAncV1RotationManifestCheckpoint(
  encodedCheckpoint,
  vaultId,
);

async function recipient(index: 1 | 2) {
  const endpointId = index === 1 ? issuerId : recipientTwoId;
  const keys = index === 1 ? issuer : recipientTwo;
  const marker = index === 1 ? 21 : 22;
  const eekWrapHash = recipientSet[index - 1]!.eekWrapHash;
  const offer = await signAncV1RotationRecipientOffer(
    {
      suite: ANC_ROTATION_EVIDENCE_SUITE_ID,
      vaultId,
      type: "rotation-recipient-offer",
      createdAt: now - 10,
      envelopeId: fill(marker),
      ceremonyId,
      checkpointHash,
      eekWrapHash,
      recipientEndpointId: endpointId,
      issuerEndpointId: issuerId,
      targetEpoch: 4,
      expiresAt: now + 300,
    },
    issuer.privateKey,
  );
  const encodedOffer = encodeAncV1RotationRecipientOffer(offer);
  const offerHash = await hashAncV1RotationRecipientOffer(
    encodedOffer,
    vaultId,
  );
  const acknowledgement = await signAncV1RotationRecipientAcknowledgement(
    {
      suite: ANC_ROTATION_EVIDENCE_SUITE_ID,
      vaultId,
      type: "rotation-recipient-acknowledgement",
      createdAt: now,
      envelopeId: fill(marker + 20),
      ceremonyId,
      checkpointHash,
      eekWrapHash,
      offerHash,
      recipientEndpointId: endpointId,
      targetEpoch: 4,
    },
    { recipientSigningPrivateKey: keys.privateKey, pendingEpochKey },
  );
  const destruction = await signAncV1RotationEpochDestructionAttestation(
    {
      suite: ANC_ROTATION_EVIDENCE_SUITE_ID,
      vaultId,
      type: "rotation-epoch-destruction-attestation",
      createdAt: now,
      envelopeId: fill(index === 1 ? 0x51 : 0x52),
      ceremonyId,
      checkpointHash,
      controlEntryHash: checkpoint.controlEntryHash,
      endpointId,
      destroyedEpoch: 3,
      activatedEpoch: 4,
      custodyGeneration: 8,
    },
    keys.privateKey,
  );
  return {
    offer: encodeAncV1RotationRecipientOffer(offer),
    acknowledgement:
      encodeAncV1RotationRecipientAcknowledgement(acknowledgement),
    destruction: encodeAncV1RotationEpochDestructionAttestation(destruction),
  };
}
const one = await recipient(1);
const two = await recipient(2);
const recoveryWrapHash = fill(0x63, 32);
const hostedReceipt = encodeAncV1ControlLogRotationAppendReceipt({
  version: 1,
  suite: "anc/v1",
  type: "control-log-rotation-append-receipt",
  vaultId: "vault-rotation-test",
  entryId: "rotation-entry-0001",
  sequence: 9,
  headHash: hex(checkpoint.controlEntryHash),
  recoveryWrapHash: hex(recoveryWrapHash),
  recoveryWrapByteLength: 128,
});
const completion = await signAncV1RotationControlCommitAttestation(
  {
    suite: ANC_ROTATION_EVIDENCE_SUITE_ID,
    vaultId,
    type: "rotation-control-commit-attestation",
    createdAt: now + 1,
    envelopeId: fill(0x61),
    ceremonyId,
    checkpointHash,
    controlEntryHash: checkpoint.controlEntryHash,
    hostedReceiptHash: await hashAncV1RotationHostedReceipt(hostedReceipt),
    signerEndpointId: issuerId,
    committedSequence: 9,
    committedHeadHash: checkpoint.controlEntryHash,
    recipientSetHash: checkpoint.recipientSetHash,
  },
  issuer.privateKey,
);

writeFileSync(
  outputPath,
  `${JSON.stringify(
    {
      checkpoint: hex(encodedCheckpoint),
      offerOne: hex(one.offer),
      offerTwo: hex(two.offer),
      acknowledgementOne: hex(one.acknowledgement),
      acknowledgementTwo: hex(two.acknowledgement),
      destructionOne: hex(one.destruction),
      destructionTwo: hex(two.destruction),
      hostedReceipt: hex(hostedReceipt),
      completion: hex(encodeAncV1RotationControlCommitAttestation(completion)),
      issuerPublicKey: hex(issuer.publicKey),
      recipientTwoPublicKey: hex(recipientTwo.publicKey),
      checkpointHash: hex(checkpointHash),
      liveRevisionSetHash: hex(liveRevisionSetHash),
      recipientSetHash: hex(checkpoint.recipientSetHash),
    },
    null,
    2,
  )}\n`,
);
issuerSeed.fill(0);
recipientTwoSeed.fill(0);
pendingEpochKey.fill(0);
issuer.privateKey.fill(0);
recipientTwo.privateKey.fill(0);
