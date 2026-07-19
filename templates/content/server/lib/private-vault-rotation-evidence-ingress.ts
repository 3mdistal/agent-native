import {
  ancV1BytesToHex,
  ancV1Hash,
  ancV1HexToBytes,
  decodeAncV1RotationManifestCheckpoint,
  decodeAncV1RotationRecipientOffer,
  hashAncV1RotationManifestCheckpoint,
  hashAncV1RotationRecipientSet,
  verifyAncV1EekWrapEnvelope,
  verifyAncV1RotationManifestCheckpoint,
  verifyAncV1RotationRecipientOffer,
  type ControlLogState,
} from "@agent-native/core/e2ee";

import type { PrivateVaultMigrationEvidencePrincipal } from "./private-vault-migration-evidence.js";
import {
  PrivateVaultRotationEvidenceError,
  type PrivateVaultRotationEvidenceScope,
  type PrivateVaultRotationEvidenceStatus,
  createPrivateVaultRotationEvidenceStore,
} from "./private-vault-rotation-evidence.js";

function same(left: Uint8Array, right: Uint8Array): boolean {
  return (
    left.byteLength === right.byteLength &&
    left.every((value, index) => value === right[index])
  );
}

function fail(): never {
  throw new PrivateVaultRotationEvidenceError("conflict");
}

export interface PrivateVaultRotationEvidencePrincipal extends PrivateVaultMigrationEvidencePrincipal {}

export interface PrivateVaultRotationEvidenceIngressDependencies {
  readonly loadState: (
    principal: PrivateVaultRotationEvidencePrincipal,
  ) => Promise<ControlLogState | null>;
  readonly resolveScope: (
    principal: PrivateVaultRotationEvidencePrincipal,
  ) => Promise<PrivateVaultRotationEvidenceScope | null>;
  readonly store: ReturnType<typeof createPrivateVaultRotationEvidenceStore>;
  readonly now?: () => number;
}

export function createPrivateVaultRotationEvidenceIngress(
  dependencies: PrivateVaultRotationEvidenceIngressDependencies,
) {
  const now = dependencies.now ?? (() => Math.floor(Date.now() / 1_000));

  async function context(principal: PrivateVaultRotationEvidencePrincipal) {
    const [state, scope] = await Promise.all([
      dependencies.loadState(principal),
      dependencies.resolveScope(principal),
    ]);
    if (
      !state ||
      !scope ||
      state.vaultId !== principal.vaultId ||
      scope.vaultId !== principal.vaultId ||
      scope.ownerEmail !== principal.ownerEmail ||
      scope.orgId !== principal.orgId
    )
      fail();
    return { state, scope };
  }

  return {
    async appendCheckpoint(
      principal: PrivateVaultRotationEvidencePrincipal,
      encodedCheckpoint: Uint8Array,
    ): Promise<PrivateVaultRotationEvidenceStatus> {
      const { state, scope } = await context(principal);
      const signer = state.activeMembers.find(
        (member) => member.endpointId === principal.endpointId,
      );
      if (!signer || signer.role !== "endpoint" || signer.unattended) fail();
      const vaultId = ancV1HexToBytes(state.vaultId);
      const checkpoint = await verifyAncV1RotationManifestCheckpoint(
        encodedCheckpoint,
        {
          expectedVaultId: vaultId,
          expectedSignerEndpointId: ancV1HexToBytes(principal.endpointId),
          signerSigningPublicKey: ancV1HexToBytes(signer.signingPublicKey),
        },
      );
      const removedId = ancV1BytesToHex(checkpoint.removedEndpointId);
      const removed = state.activeMembers.find(
        (member) => member.endpointId === removedId,
      );
      const survivors = state.activeMembers.filter(
        (member) => member.endpointId !== removedId,
      );
      if (
        checkpoint.baseSequence !== state.sequence ||
        !same(checkpoint.baseHeadHash, ancV1HexToBytes(state.headHash)) ||
        checkpoint.baseEpoch !== state.epoch ||
        removed?.role !== "endpoint" ||
        removed.unattended ||
        survivors.length < 1 ||
        survivors.length > 64
      )
        fail();
      return dependencies.store.establish(scope, {
        ceremonyId: ancV1BytesToHex(checkpoint.ceremonyId),
        expectedRecipientCount: survivors.length,
        checkpoint: encodedCheckpoint,
      });
    },

    async appendOffer(
      principal: PrivateVaultRotationEvidencePrincipal,
      encodedOffer: Uint8Array,
      encodedEekWrap: Uint8Array,
    ): Promise<PrivateVaultRotationEvidenceStatus> {
      const { state, scope } = await context(principal);
      const vaultId = ancV1HexToBytes(state.vaultId);
      const offerPreview = decodeAncV1RotationRecipientOffer(encodedOffer, {
        expectedVaultId: vaultId,
      });
      const ceremonyId = ancV1BytesToHex(offerPreview.ceremonyId);
      const status = await dependencies.store.read(scope, ceremonyId);
      const checkpoint = decodeAncV1RotationManifestCheckpoint(
        status.checkpoint,
        { expectedVaultId: vaultId },
      );
      const issuerId = ancV1BytesToHex(checkpoint.signerEndpointId);
      const removedId = ancV1BytesToHex(checkpoint.removedEndpointId);
      const recipientId = ancV1BytesToHex(offerPreview.recipientEndpointId);
      const issuer = state.activeMembers.find(
        (member) => member.endpointId === issuerId,
      );
      const recipient = state.activeMembers.find(
        (member) => member.endpointId === recipientId,
      );
      if (
        principal.endpointId !== issuerId ||
        !issuer ||
        issuer.role !== "endpoint" ||
        issuer.unattended ||
        !recipient ||
        recipient.endpointId === removedId ||
        checkpoint.baseSequence !== state.sequence ||
        !same(checkpoint.baseHeadHash, ancV1HexToBytes(state.headHash))
      )
        fail();
      const checkpointHash = await hashAncV1RotationManifestCheckpoint(
        status.checkpoint,
        vaultId,
      );
      const offer = await verifyAncV1RotationRecipientOffer(encodedOffer, {
        expectedVaultId: vaultId,
        expectedIssuerEndpointId: checkpoint.signerEndpointId,
        expectedRecipientEndpointId: offerPreview.recipientEndpointId,
        issuerSigningPublicKey: ancV1HexToBytes(issuer.signingPublicKey),
        now: now(),
      });
      if (
        !same(offer.checkpointHash, checkpointHash) ||
        offer.targetEpoch !== checkpoint.targetEpoch
      )
        fail();
      await verifyAncV1EekWrapEnvelope(encodedEekWrap, {
        expectedVaultId: vaultId,
        expectedRecipientEndpointId: offer.recipientEndpointId,
        expectedIssuerEndpointId: offer.issuerEndpointId,
        expectedEpoch: offer.targetEpoch,
        expectedIssuerSigningPublicKey: ancV1HexToBytes(
          issuer.signingPublicKey,
        ),
      });
      const wrapHash = await ancV1Hash("eek-wrap", encodedEekWrap);
      if (!same(wrapHash, offer.eekWrapHash)) fail();
      const stored = await dependencies.store.putRecipientOffer(scope, {
        ceremonyId,
        recipientEndpointId: recipientId,
        offer: encodedOffer,
        eekWrap: encodedEekWrap,
      });
      if (stored.phase === "awaiting_acknowledgements") {
        const expectedRecipients = state.activeMembers
          .filter((member) => member.endpointId !== removedId)
          .map((member) => {
            const evidence = stored.recipients.find(
              (value) => value.recipientEndpointId === member.endpointId,
            );
            if (!evidence) return fail();
            const storedOffer = decodeAncV1RotationRecipientOffer(
              evidence.offer,
              { expectedVaultId: vaultId },
            );
            return {
              endpointId: ancV1HexToBytes(member.endpointId),
              signingPublicKey: ancV1HexToBytes(member.signingPublicKey),
              keyAgreementPublicKey: ancV1HexToBytes(
                member.keyAgreementPublicKey,
              ),
              eekWrapHash: storedOffer.eekWrapHash,
            };
          });
        if (
          !same(
            await hashAncV1RotationRecipientSet(expectedRecipients),
            checkpoint.recipientSetHash,
          )
        )
          fail();
      }
      return stored;
    },
  };
}
