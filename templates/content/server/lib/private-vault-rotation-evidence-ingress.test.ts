import {
  ANC_ROTATION_EVIDENCE_SUITE_ID,
  ancV1BytesToHex,
  ancV1Hash,
  ancV1SignDetached,
  ancV1SigningKeypairFromSeed,
  decodeAncV1RotationManifestCheckpoint,
  encodeAncV1EekWrapEnvelope,
  encodeAncV1ControlLogRotationAppendReceipt,
  encodeAncV1RotationEpochDestructionAttestation,
  encodeAncV1RotationManifestCheckpoint,
  encodeAncV1RotationRecipientAcknowledgement,
  encodeAncV1RotationRecipientOffer,
  encodeAncV1RotationControlCommitAttestation,
  encodeAncV1UnsignedEekWrapPreimage,
  hashAncV1RotationLiveRevisionSet,
  hashAncV1RotationManifestCheckpoint,
  hashAncV1RotationRecipientSet,
  hashAncV1RotationRecipientOffer,
  hashAncV1RotationHostedReceipt,
  signAncV1RotationEpochDestructionAttestation,
  signAncV1RotationManifestCheckpoint,
  signAncV1RotationRecipientOffer,
  signAncV1RotationControlCommitAttestation,
  signAncV1RotationRecipientAcknowledgement,
  type ControlLogState,
} from "@agent-native/core/e2ee";
import { describe, expect, it, vi } from "vitest";

import { createPrivateVaultRotationEvidenceIngress } from "./private-vault-rotation-evidence-ingress.js";

const fill = (value: number, length = 16) => new Uint8Array(length).fill(value);
const vault = fill(1);
const issuerId = fill(2);
const removedId = fill(3);
const ceremonyId = fill(4);
const now = 1_784_520_000;

async function fixture() {
  const issuer = await ancV1SigningKeypairFromSeed(fill(5, 32));
  const removed = await ancV1SigningKeypairFromSeed(fill(6, 32));
  const unsignedWrap = {
    suite: "anc/v1" as const,
    vaultId: vault,
    type: "eek-wrap" as const,
    createdAt: now - 10,
    envelopeId: fill(7),
    epoch: 2,
    recipientEndpointId: issuerId,
    issuerEndpointId: issuerId,
    nonce: fill(8, 24),
    ciphertext: fill(9, 64),
  };
  const encodedWrap = encodeAncV1EekWrapEnvelope({
    ...unsignedWrap,
    signature: await ancV1SignDetached(
      "eek-wrap",
      encodeAncV1UnsignedEekWrapPreimage(unsignedWrap),
      issuer.privateKey,
    ),
  });
  const wrapHash = await ancV1Hash("eek-wrap", encodedWrap);
  const recipientSetHash = await hashAncV1RotationRecipientSet([
    {
      endpointId: issuerId,
      signingPublicKey: issuer.publicKey,
      keyAgreementPublicKey: fill(10, 32),
      eekWrapHash: wrapHash,
    },
  ]);
  const checkpoint = encodeAncV1RotationManifestCheckpoint(
    await signAncV1RotationManifestCheckpoint(
      {
        suite: ANC_ROTATION_EVIDENCE_SUITE_ID,
        vaultId: vault,
        type: "rotation-manifest-checkpoint",
        createdAt: now - 20,
        envelopeId: fill(11),
        ceremonyId,
        baseSequence: 4,
        baseHeadHash: fill(12, 32),
        baseEpoch: 1,
        targetEpoch: 2,
        manifestObjectId: fill(13),
        revisionId: fill(14, 32),
        generation: 2,
        ciphertextHash: fill(15, 32),
        liveObjectCount: 1,
        liveRevisionCount: 1,
        liveRevisionSetHash: await hashAncV1RotationLiveRevisionSet([
          {
            objectId: fill(16),
            revision: 1,
            priorRevisionId: fill(17, 32),
            rotatedRevisionId: fill(18, 32),
          },
        ]),
        recipientSetHash,
        controlEntryHash: fill(19, 32),
        signerEndpointId: issuerId,
        removedEndpointId: removedId,
      },
      issuer.privateKey,
    ),
  );
  const checkpointHash = await hashAncV1RotationManifestCheckpoint(
    checkpoint,
    vault,
  );
  const offer = encodeAncV1RotationRecipientOffer(
    await signAncV1RotationRecipientOffer(
      {
        suite: ANC_ROTATION_EVIDENCE_SUITE_ID,
        vaultId: vault,
        type: "rotation-recipient-offer",
        createdAt: now - 5,
        envelopeId: fill(20),
        ceremonyId,
        checkpointHash,
        eekWrapHash: wrapHash,
        recipientEndpointId: issuerId,
        issuerEndpointId: issuerId,
        targetEpoch: 2,
        expiresAt: now + 300,
      },
      issuer.privateKey,
    ),
  );
  const state: ControlLogState = {
    vaultId: ancV1BytesToHex(vault),
    sequence: 4,
    headHash: ancV1BytesToHex(fill(12, 32)),
    membershipHash: ancV1BytesToHex(fill(21, 32)),
    signedAt: new Date((now - 30) * 1_000).toISOString(),
    activeMembers: [
      {
        endpointId: ancV1BytesToHex(issuerId),
        role: "endpoint",
        unattended: false,
        signingPublicKey: ancV1BytesToHex(issuer.publicKey),
        keyAgreementPublicKey: ancV1BytesToHex(fill(10, 32)),
        enrollmentRef: ancV1BytesToHex(fill(22)),
      },
      {
        endpointId: ancV1BytesToHex(removedId),
        role: "endpoint",
        unattended: false,
        signingPublicKey: ancV1BytesToHex(removed.publicKey),
        keyAgreementPublicKey: ancV1BytesToHex(fill(23, 32)),
        enrollmentRef: ancV1BytesToHex(fill(24)),
      },
    ],
    removedEndpointIds: [],
    epoch: 1,
    recoveryGeneration: 1,
    recoveryId: ancV1BytesToHex(fill(25)),
    recoverySigningPublicKey: ancV1BytesToHex(fill(26, 32)),
    recoveryKeyAgreementPublicKey: ancV1BytesToHex(fill(27, 32)),
    recoveryWrapHash: ancV1BytesToHex(fill(28, 32)),
    freshnessMode: "endpoint_witnessed",
  };
  return { issuer, checkpoint, offer, encodedWrap, state };
}

describe("Private Vault verified rotation evidence ingress", () => {
  it("binds the checkpoint and final offer set to the authenticated control state", async () => {
    const value = await fixture();
    const scope = {
      ownerEmail: "alice@example.test",
      accountId: "account:alice",
      orgId: "org:alice",
      workspaceId: "workspace:alice",
      vaultId: value.state.vaultId,
    };
    const principal = {
      ownerEmail: scope.ownerEmail,
      orgId: scope.orgId,
      vaultId: scope.vaultId,
      endpointId: ancV1BytesToHex(issuerId),
    };
    let status: any;
    const store = {
      establish: vi.fn(async (_scope, input) => {
        status = {
          ceremonyId: input.ceremonyId,
          phase: "collecting_offers",
          expectedRecipientCount: 1,
          checkpoint: input.checkpoint,
          recipients: [],
          hostedReceipt: null,
          completionAttestation: null,
          terminalAt: null,
          purgeEligibleAt: null,
        };
        return status;
      }),
      read: vi.fn(async () => status),
      putRecipientOffer: vi.fn(async (_scope, input) => ({
        ...status,
        phase: "awaiting_acknowledgements",
        recipients: [
          {
            recipientEndpointId: input.recipientEndpointId,
            offer: input.offer,
            eekWrap: input.eekWrap,
            acknowledgement: null,
            destructionAttestation: null,
          },
        ],
      })),
    };
    const ingress = createPrivateVaultRotationEvidenceIngress({
      loadState: async () => value.state,
      resolveScope: async () => scope,
      store: store as never,
      now: () => now,
    });
    await expect(
      ingress.appendCheckpoint(principal, value.checkpoint),
    ).resolves.toMatchObject({ phase: "collecting_offers" });
    await expect(
      ingress.appendOffer(principal, value.offer, value.encodedWrap),
    ).resolves.toMatchObject({ phase: "awaiting_acknowledgements" });
    expect(store.establish).toHaveBeenCalledWith(
      scope,
      expect.objectContaining({ expectedRecipientCount: 1 }),
    );
  });

  it("rejects an EEK-wrap substitution before persistence", async () => {
    const value = await fixture();
    const scope = {
      ownerEmail: "alice@example.test",
      accountId: "account:alice",
      orgId: "org:alice",
      workspaceId: "workspace:alice",
      vaultId: value.state.vaultId,
    };
    const status = {
      ceremonyId: ancV1BytesToHex(ceremonyId),
      phase: "collecting_offers" as const,
      expectedRecipientCount: 1,
      checkpoint: value.checkpoint,
      recipients: [],
      hostedReceipt: null,
      completionAttestation: null,
      terminalAt: null,
      purgeEligibleAt: null,
    };
    const putRecipientOffer = vi.fn();
    const ingress = createPrivateVaultRotationEvidenceIngress({
      loadState: async () => value.state,
      resolveScope: async () => scope,
      store: { read: async () => status, putRecipientOffer } as never,
      now: () => now,
    });
    const changed = value.encodedWrap.slice();
    changed[changed.length - 1] ^= 1;
    await expect(
      ingress.appendOffer(
        {
          ownerEmail: scope.ownerEmail,
          orgId: scope.orgId,
          vaultId: scope.vaultId,
          endpointId: ancV1BytesToHex(issuerId),
        },
        value.offer,
        changed,
      ),
    ).rejects.toBeDefined();
    expect(putRecipientOffer).not.toHaveBeenCalled();
  });

  it("serves only the active survivor and stores ACK before fully verified destruction", async () => {
    const value = await fixture();
    const scope = {
      ownerEmail: "alice@example.test",
      accountId: "account:alice",
      orgId: "org:alice",
      workspaceId: "workspace:alice",
      vaultId: value.state.vaultId,
    };
    const recipientId = ancV1BytesToHex(issuerId);
    const principal = {
      ownerEmail: scope.ownerEmail,
      orgId: scope.orgId,
      vaultId: scope.vaultId,
      endpointId: recipientId,
    };
    const checkpointHash = await hashAncV1RotationManifestCheckpoint(
      value.checkpoint,
      vault,
    );
    const offerHash = await hashAncV1RotationRecipientOffer(value.offer, vault);
    const acknowledgement = encodeAncV1RotationRecipientAcknowledgement(
      await signAncV1RotationRecipientAcknowledgement(
        {
          suite: ANC_ROTATION_EVIDENCE_SUITE_ID,
          vaultId: vault,
          type: "rotation-recipient-acknowledgement",
          createdAt: now,
          envelopeId: fill(29),
          ceremonyId,
          checkpointHash,
          eekWrapHash: await ancV1Hash("eek-wrap", value.encodedWrap),
          offerHash,
          recipientEndpointId: issuerId,
          targetEpoch: 2,
        },
        {
          recipientSigningPrivateKey: value.issuer.privateKey,
          pendingEpochKey: fill(30, 32),
        },
      ),
    );
    const destruction = encodeAncV1RotationEpochDestructionAttestation(
      await signAncV1RotationEpochDestructionAttestation(
        {
          suite: ANC_ROTATION_EVIDENCE_SUITE_ID,
          vaultId: vault,
          type: "rotation-epoch-destruction-attestation",
          createdAt: now,
          envelopeId: fill(31),
          ceremonyId,
          checkpointHash,
          controlEntryHash: fill(19, 32),
          endpointId: issuerId,
          destroyedEpoch: 1,
          activatedEpoch: 2,
          // Custody and manifest generations are independent monotonic clocks.
          custodyGeneration: 7,
        },
        value.issuer.privateKey,
      ),
    );
    let status: any = {
      ceremonyId: ancV1BytesToHex(ceremonyId),
      phase: "awaiting_acknowledgements",
      expectedRecipientCount: 1,
      checkpoint: value.checkpoint,
      recipients: [
        {
          recipientEndpointId: recipientId,
          offer: value.offer,
          eekWrap: value.encodedWrap,
          acknowledgement: null,
          destructionAttestation: null,
        },
      ],
      hostedReceipt: null,
      completionAttestation: null,
      terminalAt: null,
      purgeEligibleAt: null,
    };
    const store = {
      read: vi.fn(async () => status),
      putRecipientAcknowledgement: vi.fn(async (_scope, input) => {
        status = {
          ...status,
          phase: "awaiting_destructions",
          recipients: [
            { ...status.recipients[0], acknowledgement: input.acknowledgement },
          ],
        };
        return status;
      }),
      putDestructionAttestation: vi.fn(async (_scope, input) => {
        status = {
          ...status,
          phase: "awaiting_hosted_receipt",
          recipients: [
            {
              ...status.recipients[0],
              destructionAttestation: input.destructionAttestation,
            },
          ],
        };
        return status;
      }),
    };
    const ingress = createPrivateVaultRotationEvidenceIngress({
      loadState: async () => value.state,
      resolveScope: async () => scope,
      store: store as never,
      now: () => now,
    });
    await expect(
      ingress.fetchRecipientEvidence(
        principal,
        ancV1BytesToHex(ceremonyId),
        recipientId,
      ),
    ).resolves.toMatchObject({ recipientEndpointId: recipientId });
    await expect(
      ingress.appendAcknowledgement(
        principal,
        ancV1BytesToHex(ceremonyId),
        recipientId,
        acknowledgement,
      ),
    ).resolves.toMatchObject({ phase: "awaiting_destructions" });
    expect(store.putRecipientAcknowledgement).toHaveBeenCalledWith(
      scope,
      expect.objectContaining({ acknowledgement }),
    );
    const forgedDestruction = destruction.slice();
    forgedDestruction[forgedDestruction.length - 1] ^= 1;
    await expect(
      ingress.appendDestruction(
        principal,
        ancV1BytesToHex(ceremonyId),
        recipientId,
        forgedDestruction,
      ),
    ).rejects.toBeDefined();
    expect(store.putDestructionAttestation).not.toHaveBeenCalled();
    await expect(
      ingress.appendDestruction(
        principal,
        ancV1BytesToHex(ceremonyId),
        recipientId,
        destruction,
      ),
    ).resolves.toMatchObject({ phase: "awaiting_hosted_receipt" });

    await expect(
      ingress.readForInitiator(principal, ancV1BytesToHex(ceremonyId)),
    ).resolves.toMatchObject({
      recipients: [
        expect.objectContaining({
          acknowledgement,
          destructionAttestation: destruction,
        }),
      ],
    });
    await expect(
      ingress.fetchRecipientEvidence(
        { ...principal, endpointId: ancV1BytesToHex(removedId) },
        ancV1BytesToHex(ceremonyId),
        ancV1BytesToHex(removedId),
      ),
    ).rejects.toBeDefined();
  });

  it("binds hosted receipt and completion to the post-commit head and stored evidence clock", async () => {
    const value = await fixture();
    const scope = {
      ownerEmail: "alice@example.test",
      accountId: "account:alice",
      orgId: "org:alice",
      workspaceId: "workspace:alice",
      vaultId: value.state.vaultId,
    };
    const recipientId = ancV1BytesToHex(issuerId);
    const principal = {
      ownerEmail: scope.ownerEmail,
      orgId: scope.orgId,
      vaultId: scope.vaultId,
      endpointId: recipientId,
    };
    const checkpointHash = await hashAncV1RotationManifestCheckpoint(
      value.checkpoint,
      vault,
    );
    const acknowledgement = encodeAncV1RotationRecipientAcknowledgement(
      await signAncV1RotationRecipientAcknowledgement(
        {
          suite: ANC_ROTATION_EVIDENCE_SUITE_ID,
          vaultId: vault,
          type: "rotation-recipient-acknowledgement",
          createdAt: now,
          envelopeId: fill(32),
          ceremonyId,
          checkpointHash,
          eekWrapHash: await ancV1Hash("eek-wrap", value.encodedWrap),
          offerHash: await hashAncV1RotationRecipientOffer(value.offer, vault),
          recipientEndpointId: issuerId,
          targetEpoch: 2,
        },
        {
          recipientSigningPrivateKey: value.issuer.privateKey,
          pendingEpochKey: fill(33, 32),
        },
      ),
    );
    const destruction = encodeAncV1RotationEpochDestructionAttestation(
      await signAncV1RotationEpochDestructionAttestation(
        {
          suite: ANC_ROTATION_EVIDENCE_SUITE_ID,
          vaultId: vault,
          type: "rotation-epoch-destruction-attestation",
          createdAt: now,
          envelopeId: fill(34),
          ceremonyId,
          checkpointHash,
          controlEntryHash: fill(19, 32),
          endpointId: issuerId,
          destroyedEpoch: 1,
          activatedEpoch: 2,
          custodyGeneration: 2,
        },
        value.issuer.privateKey,
      ),
    );
    const wrapHash = "ab".repeat(32);
    const receiptValue = {
      version: 1 as const,
      suite: "anc/v1" as const,
      type: "control-log-rotation-append-receipt" as const,
      vaultId: scope.vaultId,
      entryId: "entry:rotation:test",
      sequence: 5,
      headHash: ancV1BytesToHex(fill(19, 32)),
      recoveryWrapHash: wrapHash,
      recoveryWrapByteLength: 128,
    };
    const receipt = encodeAncV1ControlLogRotationAppendReceipt(receiptValue);
    const makeCompletion = async (createdAt: number) =>
      encodeAncV1RotationControlCommitAttestation(
        await signAncV1RotationControlCommitAttestation(
          {
            suite: ANC_ROTATION_EVIDENCE_SUITE_ID,
            vaultId: vault,
            type: "rotation-control-commit-attestation",
            createdAt,
            envelopeId: fill(35),
            ceremonyId,
            checkpointHash,
            controlEntryHash: fill(19, 32),
            hostedReceiptHash: await hashAncV1RotationHostedReceipt(receipt),
            signerEndpointId: issuerId,
            committedSequence: 5,
            committedHeadHash: fill(19, 32),
            recipientSetHash: decodeAncV1RotationManifestCheckpoint(
              value.checkpoint,
              { expectedVaultId: vault },
            ).recipientSetHash,
          },
          value.issuer.privateKey,
        ),
      );
    const completion = await makeCompletion(now + 1);
    let status: any = {
      ceremonyId: ancV1BytesToHex(ceremonyId),
      phase: "awaiting_hosted_receipt",
      expectedRecipientCount: 1,
      checkpoint: value.checkpoint,
      recipients: [
        {
          recipientEndpointId: recipientId,
          offer: value.offer,
          eekWrap: value.encodedWrap,
          acknowledgement,
          destructionAttestation: destruction,
        },
      ],
      hostedReceipt: null,
      completionAttestation: null,
      terminalAt: null,
      purgeEligibleAt: null,
    };
    const store = {
      read: vi.fn(async () => status),
      putHostedReceipt: vi.fn(async (_scope, input) => {
        status = {
          ...status,
          phase: "awaiting_completion",
          hostedReceipt: input.hostedReceipt,
        };
        return status;
      }),
      putCompletionAttestation: vi.fn(async (_scope, input) => {
        status = {
          ...status,
          phase: "completed",
          completionAttestation: input.completionAttestation,
        };
        return status;
      }),
    };
    const committedState = {
      ...value.state,
      sequence: 5,
      headHash: ancV1BytesToHex(fill(19, 32)),
      epoch: 2,
      activeMembers: [value.state.activeMembers[0]!],
      removedEndpointIds: [ancV1BytesToHex(removedId)],
      recoveryWrapHash: wrapHash,
    };
    const ingress = createPrivateVaultRotationEvidenceIngress({
      loadState: async () => committedState,
      resolveScope: async () => scope,
      store: store as never,
      loadCommittedWrapBinding: async () => ({
        controlEntryId: "entry:rotation:test",
        recoveryWrapHash: wrapHash,
        recoveryWrapByteLength: 128,
      }),
      now: () => now + 1,
    });
    for (const changed of [
      { sequence: 4 },
      { headHash: "cd".repeat(32) },
      { recoveryWrapHash: "ef".repeat(32) },
      { recoveryWrapByteLength: 127 },
    ]) {
      await expect(
        ingress.appendHostedReceipt(
          principal,
          ancV1BytesToHex(ceremonyId),
          encodeAncV1ControlLogRotationAppendReceipt({
            ...receiptValue,
            ...changed,
          }),
        ),
      ).rejects.toBeDefined();
    }
    await expect(
      ingress.appendHostedReceipt(
        { ...principal, endpointId: ancV1BytesToHex(removedId) },
        ancV1BytesToHex(ceremonyId),
        receipt,
      ),
    ).rejects.toBeDefined();
    await expect(
      ingress.appendHostedReceipt(
        principal,
        ancV1BytesToHex(ceremonyId),
        receipt,
      ),
    ).resolves.toMatchObject({ phase: "awaiting_completion" });
    await expect(
      ingress.appendCompletionAttestation(
        principal,
        ancV1BytesToHex(ceremonyId),
        await makeCompletion(now - 120),
      ),
    ).rejects.toBeDefined();
    const forgedCompletion = completion.slice();
    forgedCompletion[forgedCompletion.length - 1] ^= 1;
    await expect(
      ingress.appendCompletionAttestation(
        principal,
        ancV1BytesToHex(ceremonyId),
        forgedCompletion,
      ),
    ).rejects.toBeDefined();
    await expect(
      ingress.appendCompletionAttestation(
        principal,
        ancV1BytesToHex(ceremonyId),
        completion,
      ),
    ).resolves.toMatchObject({ phase: "completed" });
    await expect(
      ingress.appendCompletionAttestation(
        principal,
        ancV1BytesToHex(ceremonyId),
        completion,
      ),
    ).resolves.toMatchObject({ phase: "completed" });
    expect(store.putCompletionAttestation).toHaveBeenCalledTimes(1);
    await expect(
      ingress.readForInitiator(principal, ancV1BytesToHex(ceremonyId)),
    ).resolves.toMatchObject({
      phase: "completed",
      hostedReceipt: receipt,
      completionAttestation: completion,
    });

    await expect(
      createPrivateVaultRotationEvidenceIngress({
        loadState: async () => ({ ...committedState, sequence: 4 }),
        resolveScope: async () => scope,
        store: store as never,
        loadCommittedWrapBinding: async () => ({
          controlEntryId: "entry:rotation:test",
          recoveryWrapHash: wrapHash,
          recoveryWrapByteLength: 128,
        }),
        now: () => now + 1,
      }).appendHostedReceipt(principal, ancV1BytesToHex(ceremonyId), receipt),
    ).rejects.toBeDefined();
  });
});
