import { createHash } from "node:crypto";

import {
  ANC_ROTATION_EVIDENCE_SIZE_LIMITS,
  ancV1BytesToHex,
  ancV1Hash,
  ancV1HexToBytes,
  assertFreshControlLogHead,
  decodeAncV1RotationEpochDestructionAttestation,
  decodeAncV1ControlLogRotationAppendReceipt,
  decodeAncV1RotationManifestCheckpoint,
  decodeAncV1RotationRecipientAcknowledgement,
  decodeAncV1RotationRecipientOffer,
  encodeAncV1RotationRecipientAcknowledgement,
  encodeAncV1ControlLogRotationAppendReceipt,
  hashAncV1RotationManifestCheckpoint,
  hashAncV1RotationRecipientOffer,
  hashAncV1RotationRecipientSet,
  verifyAncV1EekWrapEnvelope,
  verifyAncV1RotationEpochDestructionAttestation,
  verifyAncV1RotationCommittedCompletion,
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
  readonly freezeRotation?: (input: {
    principal: PrivateVaultRotationEvidencePrincipal;
    ceremonyId: string;
    baseEpoch: number;
    targetEpoch: number;
    manifestObjectId: string;
    manifestRevisionId: string;
    manifestGeneration: number;
  }) => Promise<unknown>;
  readonly verifyControlBundle?: (input: {
    body: Uint8Array;
    proof: unknown;
    path: string;
  }) => Promise<{
    principal: PrivateVaultRotationEvidencePrincipal;
    scope: PrivateVaultRotationEvidenceScope;
    entryHash: string;
    signedEntry: Uint8Array;
    recoveryWrap: Uint8Array;
    sequence: number;
    targetEpoch: number;
    removedEndpointIds: readonly string[];
    signerEndpointId: string;
  }>;
  readonly loadCommittedWrapBinding?: (
    scope: PrivateVaultRotationEvidenceScope,
    recoveryWrapHash: string,
  ) => Promise<{
    controlEntryId: string;
    recoveryWrapHash: string;
    recoveryWrapByteLength: number;
  } | null>;
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
    try {
      return {
        state: assertFreshControlLogHead(state, new Date(now() * 1_000)),
        scope,
      };
    } catch {
      return fail();
    }
  }

  async function ceremonyContext(
    principal: PrivateVaultRotationEvidencePrincipal,
    ceremonyId: string,
  ) {
    const { state, scope } = await context(principal);
    const vaultId = ancV1HexToBytes(state.vaultId);
    const status = await dependencies.store.read(scope, ceremonyId);
    const checkpointPreview = decodeAncV1RotationManifestCheckpoint(
      status.checkpoint,
      { expectedVaultId: vaultId },
    );
    const signerId = ancV1BytesToHex(checkpointPreview.signerEndpointId);
    const signer = state.activeMembers.find(
      (member) => member.endpointId === signerId,
    );
    if (!signer || signer.role !== "endpoint" || signer.unattended) fail();
    const checkpoint = await verifyAncV1RotationManifestCheckpoint(
      status.checkpoint,
      {
        expectedVaultId: vaultId,
        expectedSignerEndpointId: checkpointPreview.signerEndpointId,
        signerSigningPublicKey: ancV1HexToBytes(signer.signingPublicKey),
      },
    );
    if (
      ancV1BytesToHex(checkpoint.ceremonyId) !== ceremonyId ||
      checkpoint.baseSequence !== state.sequence ||
      !same(checkpoint.baseHeadHash, ancV1HexToBytes(state.headHash)) ||
      checkpoint.baseEpoch !== state.epoch
    )
      fail();
    return { state, scope, status, vaultId, checkpoint, signer, signerId };
  }

  async function postCommitContext(
    principal: PrivateVaultRotationEvidencePrincipal,
    ceremonyId: string,
  ) {
    const { state, scope } = await context(principal);
    const vaultId = ancV1HexToBytes(state.vaultId);
    const status = await dependencies.store.read(scope, ceremonyId);
    const checkpointPreview = decodeAncV1RotationManifestCheckpoint(
      status.checkpoint,
      { expectedVaultId: vaultId },
    );
    const signerId = ancV1BytesToHex(checkpointPreview.signerEndpointId);
    const signer = state.activeMembers.find(
      (member) => member.endpointId === signerId,
    );
    if (!signer || signer.role !== "endpoint" || signer.unattended) fail();
    const checkpoint = await verifyAncV1RotationManifestCheckpoint(
      status.checkpoint,
      {
        expectedVaultId: vaultId,
        expectedSignerEndpointId: checkpointPreview.signerEndpointId,
        signerSigningPublicKey: ancV1HexToBytes(signer.signingPublicKey),
      },
    );
    if (
      ancV1BytesToHex(checkpoint.ceremonyId) !== ceremonyId ||
      checkpoint.baseSequence === Number.MAX_SAFE_INTEGER ||
      state.sequence !== checkpoint.baseSequence + 1 ||
      state.headHash !== ancV1BytesToHex(checkpoint.controlEntryHash) ||
      state.epoch !== checkpoint.targetEpoch ||
      status.expectedRecipientCount !== state.activeMembers.length ||
      status.recipients.length !== state.activeMembers.length
    )
      fail();
    const checkpointHash = await hashAncV1RotationManifestCheckpoint(
      status.checkpoint,
      vaultId,
    );
    const roster = state.activeMembers.map((member) => {
      const evidence = status.recipients.find(
        (recipient) => recipient.recipientEndpointId === member.endpointId,
      );
      if (!evidence) return fail();
      const offer = decodeAncV1RotationRecipientOffer(evidence.offer, {
        expectedVaultId: vaultId,
      });
      if (
        ancV1BytesToHex(offer.recipientEndpointId) !== member.endpointId ||
        !same(offer.ceremonyId, checkpoint.ceremonyId) ||
        !same(offer.checkpointHash, checkpointHash) ||
        offer.targetEpoch !== checkpoint.targetEpoch
      )
        return fail();
      return {
        endpointId: ancV1HexToBytes(member.endpointId),
        signingPublicKey: ancV1HexToBytes(member.signingPublicKey),
        keyAgreementPublicKey: ancV1HexToBytes(member.keyAgreementPublicKey),
        eekWrapHash: offer.eekWrapHash,
      };
    });
    if (
      !same(
        await hashAncV1RotationRecipientSet(roster),
        checkpoint.recipientSetHash,
      )
    )
      fail();
    const binding = dependencies.loadCommittedWrapBinding
      ? await dependencies.loadCommittedWrapBinding(
          scope,
          state.recoveryWrapHash,
        )
      : null;
    if (
      !binding ||
      binding.recoveryWrapHash !== state.recoveryWrapHash ||
      !Number.isSafeInteger(binding.recoveryWrapByteLength) ||
      binding.recoveryWrapByteLength < 1
    )
      fail();
    return {
      state,
      scope,
      status,
      vaultId,
      checkpoint,
      signer,
      signerId,
      binding,
    };
  }

  function activeRecipient(
    state: ControlLogState,
    recipientEndpointId: string,
    removedEndpointId: Uint8Array,
  ) {
    const recipient = state.activeMembers.find(
      (member) => member.endpointId === recipientEndpointId,
    );
    if (
      !recipient ||
      recipient.endpointId === ancV1BytesToHex(removedEndpointId) ||
      !(
        (recipient.role === "endpoint" && !recipient.unattended) ||
        (recipient.role === "broker" && recipient.unattended)
      )
    )
      return fail();
    return recipient;
  }

  return {
    async appendControlBundle(
      proof: unknown,
      path: string,
      ceremonyId: string,
      encodedBundle: Uint8Array,
    ) {
      if (!dependencies.verifyControlBundle) fail();
      const verified = await dependencies.verifyControlBundle!({
        body: encodedBundle,
        proof,
        path,
      });
      const value = await ceremonyContext(verified.principal, ceremonyId);
      const removedId = ancV1BytesToHex(value.checkpoint.removedEndpointId);
      if (
        verified.scope.ownerEmail !== value.scope.ownerEmail ||
        verified.scope.accountId !== value.scope.accountId ||
        verified.scope.orgId !== value.scope.orgId ||
        verified.scope.workspaceId !== value.scope.workspaceId ||
        verified.scope.vaultId !== value.scope.vaultId ||
        verified.principal.endpointId !== value.signerId ||
        verified.signerEndpointId !== value.signerId ||
        verified.entryHash !==
          ancV1BytesToHex(value.checkpoint.controlEntryHash) ||
        verified.sequence !== value.checkpoint.baseSequence + 1 ||
        verified.targetEpoch !== value.checkpoint.targetEpoch ||
        verified.removedEndpointIds.length !== 1 ||
        verified.removedEndpointIds[0] !== removedId ||
        value.status.phase !== "awaiting_acknowledgements" ||
        value.status.recipients.some(
          (recipient) => recipient.acknowledgement !== null,
        )
      )
        fail();
      return dependencies.store.putControlBundle(value.scope, {
        ceremonyId,
        signedEntry: verified.signedEntry,
        recoveryWrap: verified.recoveryWrap,
        bundleSha256: createHash("sha256").update(encodedBundle).digest("hex"),
      });
    },

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
      const ceremonyId = ancV1BytesToHex(checkpoint.ceremonyId);
      await dependencies.freezeRotation?.({
        principal,
        ceremonyId,
        baseEpoch: checkpoint.baseEpoch,
        targetEpoch: checkpoint.targetEpoch,
        manifestObjectId: ancV1BytesToHex(checkpoint.manifestObjectId),
        manifestRevisionId: ancV1BytesToHex(checkpoint.revisionId),
        manifestGeneration: checkpoint.generation,
      });
      return dependencies.store.establish(scope, {
        ceremonyId,
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

    async fetchRecipientEvidence(
      principal: PrivateVaultRotationEvidencePrincipal,
      ceremonyId: string,
      recipientEndpointId: string,
    ) {
      const value = await ceremonyContext(principal, ceremonyId);
      if (principal.endpointId !== recipientEndpointId) fail();
      activeRecipient(
        value.state,
        recipientEndpointId,
        value.checkpoint.removedEndpointId,
      );
      const evidence = value.status.recipients.find(
        (recipient) => recipient.recipientEndpointId === recipientEndpointId,
      );
      if (!evidence?.offer || !evidence.eekWrap) fail();
      const controlBundle = await dependencies.store.readControlBundle(
        value.scope,
        ceremonyId,
      );
      const offer = await verifyAncV1RotationRecipientOffer(evidence.offer, {
        expectedVaultId: value.vaultId,
        expectedIssuerEndpointId: value.checkpoint.signerEndpointId,
        expectedRecipientEndpointId: ancV1HexToBytes(recipientEndpointId),
        issuerSigningPublicKey: ancV1HexToBytes(value.signer.signingPublicKey),
        now: now(),
      });
      await verifyAncV1EekWrapEnvelope(evidence.eekWrap, {
        expectedVaultId: value.vaultId,
        expectedRecipientEndpointId: offer.recipientEndpointId,
        expectedIssuerEndpointId: offer.issuerEndpointId,
        expectedEpoch: offer.targetEpoch,
        expectedIssuerSigningPublicKey: ancV1HexToBytes(
          value.signer.signingPublicKey,
        ),
      });
      if (
        !same(offer.ceremonyId, value.checkpoint.ceremonyId) ||
        !same(
          offer.checkpointHash,
          await hashAncV1RotationManifestCheckpoint(
            value.status.checkpoint,
            value.vaultId,
          ),
        ) ||
        !same(
          offer.eekWrapHash,
          await ancV1Hash("eek-wrap", evidence.eekWrap),
        ) ||
        offer.targetEpoch !== value.checkpoint.targetEpoch
      )
        fail();
      return {
        ceremonyId,
        recipientEndpointId,
        checkpoint: value.status.checkpoint.slice(),
        offer: evidence.offer.slice(),
        eekWrap: evidence.eekWrap.slice(),
        signedEntry: controlBundle.signedEntry,
        recoveryWrap: controlBundle.recoveryWrap,
      };
    },

    async appendAcknowledgement(
      principal: PrivateVaultRotationEvidencePrincipal,
      ceremonyId: string,
      recipientEndpointId: string,
      encodedAcknowledgement: Uint8Array,
    ) {
      const value = await ceremonyContext(principal, ceremonyId);
      if (principal.endpointId !== recipientEndpointId) fail();
      activeRecipient(
        value.state,
        recipientEndpointId,
        value.checkpoint.removedEndpointId,
      );
      const evidence = value.status.recipients.find(
        (recipient) => recipient.recipientEndpointId === recipientEndpointId,
      );
      if (!evidence) fail();
      const offer = await verifyAncV1RotationRecipientOffer(evidence.offer, {
        expectedVaultId: value.vaultId,
        expectedIssuerEndpointId: value.checkpoint.signerEndpointId,
        expectedRecipientEndpointId: ancV1HexToBytes(recipientEndpointId),
        issuerSigningPublicKey: ancV1HexToBytes(value.signer.signingPublicKey),
        now: now(),
      });
      const acknowledgement = decodeAncV1RotationRecipientAcknowledgement(
        encodedAcknowledgement,
        { expectedVaultId: value.vaultId },
      );
      if (
        !same(
          encodeAncV1RotationRecipientAcknowledgement(acknowledgement),
          encodedAcknowledgement,
        ) ||
        !same(acknowledgement.ceremonyId, value.checkpoint.ceremonyId) ||
        !same(
          acknowledgement.checkpointHash,
          await hashAncV1RotationManifestCheckpoint(
            value.status.checkpoint,
            value.vaultId,
          ),
        ) ||
        !same(
          acknowledgement.eekWrapHash,
          await ancV1Hash("eek-wrap", evidence.eekWrap),
        ) ||
        !same(
          acknowledgement.offerHash,
          await hashAncV1RotationRecipientOffer(evidence.offer, value.vaultId),
        ) ||
        ancV1BytesToHex(acknowledgement.recipientEndpointId) !==
          recipientEndpointId ||
        acknowledgement.targetEpoch !== value.checkpoint.targetEpoch ||
        acknowledgement.createdAt +
          ANC_ROTATION_EVIDENCE_SIZE_LIMITS.clockSkewSeconds <
          offer.createdAt ||
        acknowledgement.createdAt >
          offer.expiresAt +
            ANC_ROTATION_EVIDENCE_SIZE_LIMITS.clockSkewSeconds ||
        acknowledgement.createdAt >
          now() + ANC_ROTATION_EVIDENCE_SIZE_LIMITS.clockSkewSeconds
      )
        fail();
      // Hosted code cannot verify the possession MAC without the pending epoch
      // key, and Core intentionally couples its ACK component verifier to that
      // check. The signed request proof authenticates these exact bytes; the
      // initiator later verifies the full acknowledgement set with that key
      // before any completion publication.
      return dependencies.store.putRecipientAcknowledgement(value.scope, {
        ceremonyId,
        recipientEndpointId,
        acknowledgement: encodedAcknowledgement,
      });
    },

    async appendDestruction(
      principal: PrivateVaultRotationEvidencePrincipal,
      ceremonyId: string,
      recipientEndpointId: string,
      encodedDestruction: Uint8Array,
    ) {
      const value = await ceremonyContext(principal, ceremonyId);
      if (principal.endpointId !== recipientEndpointId) fail();
      const recipient = activeRecipient(
        value.state,
        recipientEndpointId,
        value.checkpoint.removedEndpointId,
      );
      const evidence = value.status.recipients.find(
        (candidate) => candidate.recipientEndpointId === recipientEndpointId,
      );
      if (!evidence?.acknowledgement) fail();
      const destruction = await verifyAncV1RotationEpochDestructionAttestation(
        encodedDestruction,
        {
          expectedVaultId: value.vaultId,
          expectedEndpointId: ancV1HexToBytes(recipientEndpointId),
          endpointSigningPublicKey: ancV1HexToBytes(recipient.signingPublicKey),
        },
      );
      if (
        ancV1BytesToHex(destruction.ceremonyId) !== ceremonyId ||
        !same(
          destruction.checkpointHash,
          await hashAncV1RotationManifestCheckpoint(
            value.status.checkpoint,
            value.vaultId,
          ),
        ) ||
        !same(
          destruction.controlEntryHash,
          value.checkpoint.controlEntryHash,
        ) ||
        destruction.destroyedEpoch !== value.checkpoint.baseEpoch ||
        destruction.activatedEpoch !== value.checkpoint.targetEpoch ||
        destruction.createdAt >
          now() + ANC_ROTATION_EVIDENCE_SIZE_LIMITS.clockSkewSeconds
      )
        fail();
      return dependencies.store.putDestructionAttestation(value.scope, {
        ceremonyId,
        recipientEndpointId,
        destructionAttestation: encodedDestruction,
      });
    },

    async readForInitiator(
      principal: PrivateVaultRotationEvidencePrincipal,
      ceremonyId: string,
    ) {
      try {
        const value = await ceremonyContext(principal, ceremonyId);
        if (principal.endpointId !== value.signerId) fail();
        return value.status;
      } catch {
        const value = await postCommitContext(principal, ceremonyId);
        if (principal.endpointId !== value.signerId) fail();
        return value.status;
      }
    },

    async appendHostedReceipt(
      principal: PrivateVaultRotationEvidencePrincipal,
      ceremonyId: string,
      encodedReceipt: Uint8Array,
    ) {
      const value = await postCommitContext(principal, ceremonyId);
      if (principal.endpointId !== value.signerId) fail();
      if (value.status.hostedReceipt) {
        if (same(value.status.hostedReceipt, encodedReceipt))
          return value.status;
        fail();
      }
      if (
        value.status.phase !== "awaiting_hosted_receipt" ||
        value.status.recipients.some(
          (recipient) =>
            !recipient.acknowledgement || !recipient.destructionAttestation,
        )
      )
        fail();
      const receipt =
        decodeAncV1ControlLogRotationAppendReceipt(encodedReceipt);
      if (
        !same(
          encodeAncV1ControlLogRotationAppendReceipt(receipt),
          encodedReceipt,
        ) ||
        receipt.vaultId !== value.scope.vaultId ||
        receipt.entryId !== value.binding.controlEntryId ||
        receipt.sequence !== value.checkpoint.baseSequence + 1 ||
        receipt.headHash !==
          ancV1BytesToHex(value.checkpoint.controlEntryHash) ||
        receipt.recoveryWrapHash !== value.binding.recoveryWrapHash ||
        receipt.recoveryWrapHash !== value.state.recoveryWrapHash ||
        receipt.recoveryWrapByteLength !== value.binding.recoveryWrapByteLength
      )
        fail();
      return dependencies.store.putHostedReceipt(value.scope, {
        ceremonyId,
        hostedReceipt: encodedReceipt,
      });
    },

    async appendCompletionAttestation(
      principal: PrivateVaultRotationEvidencePrincipal,
      ceremonyId: string,
      encodedCompletion: Uint8Array,
    ) {
      const value = await postCommitContext(principal, ceremonyId);
      if (principal.endpointId !== value.signerId) fail();
      if (value.status.completionAttestation) {
        if (same(value.status.completionAttestation, encodedCompletion))
          return value.status;
        fail();
      }
      if (
        value.status.phase !== "awaiting_completion" ||
        !value.status.hostedReceipt ||
        value.status.recipients.some(
          (recipient) =>
            !recipient.acknowledgement || !recipient.destructionAttestation,
        )
      )
        fail();
      const evidenceCreatedAt = value.status.recipients.flatMap((recipient) => [
        decodeAncV1RotationRecipientAcknowledgement(
          recipient.acknowledgement!,
          { expectedVaultId: value.vaultId },
        ).createdAt,
        decodeAncV1RotationEpochDestructionAttestation(
          recipient.destructionAttestation!,
          { expectedVaultId: value.vaultId },
        ).createdAt,
      ]);
      if (evidenceCreatedAt.length !== value.status.expectedRecipientCount * 2)
        fail();
      await verifyAncV1RotationCommittedCompletion({
        encodedCompletion,
        encodedCheckpoint: value.status.checkpoint,
        encodedHostedReceipt: value.status.hostedReceipt,
        expectedHostedEntryId: value.binding.controlEntryId,
        expectedHostedVaultId: value.scope.vaultId,
        expectedRecoveryWrapHash: ancV1HexToBytes(
          value.binding.recoveryWrapHash,
        ),
        expectedRecoveryWrapByteLength: value.binding.recoveryWrapByteLength,
        expectedVaultId: value.vaultId,
        expectedSignerEndpointId: value.checkpoint.signerEndpointId,
        signerSigningPublicKey: ancV1HexToBytes(value.signer.signingPublicKey),
        notBefore: Math.max(...evidenceCreatedAt),
        now: now(),
      });
      return dependencies.store.putCompletionAttestation(value.scope, {
        ceremonyId,
        completionAttestation: encodedCompletion,
      });
    },
  };
}
