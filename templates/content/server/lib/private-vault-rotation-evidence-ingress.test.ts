import {
  ANC_ROTATION_EVIDENCE_SUITE_ID,
  ancV1BytesToHex,
  ancV1Hash,
  ancV1SignDetached,
  ancV1SigningKeypairFromSeed,
  encodeAncV1EekWrapEnvelope,
  encodeAncV1RotationManifestCheckpoint,
  encodeAncV1RotationRecipientOffer,
  encodeAncV1UnsignedEekWrapPreimage,
  hashAncV1RotationLiveRevisionSet,
  hashAncV1RotationManifestCheckpoint,
  hashAncV1RotationRecipientSet,
  signAncV1RotationManifestCheckpoint,
  signAncV1RotationRecipientOffer,
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
});
