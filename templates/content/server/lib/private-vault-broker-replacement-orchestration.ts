import { createHash } from "node:crypto";

import {
  ANC_V1_CONTROL_LOG_APPEND_REQUEST_MAX_BYTES,
  ANC_BROKER_REPLACEMENT_APPROVAL_LIMITS,
  ancV1BytesToHex,
  ancV1Hash,
  ancV1HexToBytes,
  ancV1LifecycleIdToHex,
  assertFreshControlLogHead,
  decodeAncV1Canonical,
  decodeAncV1BrokerReplacementApproval,
  decodeAncV1ControlLogRotationAppendReceipt,
  decodeAncV1ControlLogRotationAppendRequest,
  decodeAncV1EndpointEnrollmentOffer,
  decodeSignedControlLogEntry,
  E2EE_ENVELOPE_FIELDS,
  encodeAncV1EndpointEnrollmentOffer,
  hashAncV1EndpointEnrollmentOffer,
  hashAncV1EnrollmentChallenge,
  hashAncV1BrokerReplacementFreezeId,
  hashAncV1RecoveryWrap,
  verifyAncV1BrokerReplacementApproval,
  verifyAncV1BrokerDrainAttestation,
  verifyAncV1BrokerReplacementChallenge,
  verifyAncV1BrokerReplacementSasDecision,
  type ControlLogState,
  type EndpointRequestProof,
} from "@agent-native/core/e2ee";
import { getOrgContext } from "@agent-native/core/org";
import {
  getCurrentBetterAuthSession,
  runWithRequestContext,
} from "@agent-native/core/server";
import { and, eq } from "drizzle-orm";
import type { H3Event } from "h3";

import { getDb, schema } from "../db/index.js";
import {
  createPrivateVaultBrokerReplacementTranscriptService,
  PrivateVaultBrokerReplacementError,
  privateVaultBrokerReplacementLimits,
  type PrivateVaultBrokerReplacementBindings,
  type PrivateVaultBrokerReplacementScope,
  type PrivateVaultBrokerReplacementStatus,
} from "./private-vault-broker-replacement.js";
import {
  appendPrivateVaultControlLogRotation,
  PrivateVaultControlLogAppendError,
} from "./private-vault-control-log-append.js";
import { privateVaultControlLogService } from "./private-vault-control-log-runtime.js";
import { resolvePrivateVaultGenesisAccountScope } from "./private-vault-genesis-account-scope.js";
import {
  createPrivateVaultBrokerDrainService,
  PrivateVaultBrokerDrainConflictError,
  PrivateVaultBrokerDrainNotFoundError,
  type PrivateVaultBrokerDrainMetadata,
} from "./private-vault-jobs.js";

const SHA256 = /^[0-9a-f]{64}$/;
const DEADLINE_DECISIONS = [
  "abort",
  "cancel_nonterminal",
  "expire_nonterminal",
] as const;

export type PrivateVaultBrokerReplacementDeadlineDecision =
  (typeof DEADLINE_DECISIONS)[number];

export interface PrivateVaultBrokerReplacementProgress {
  transcript: PrivateVaultBrokerReplacementStatus;
  drain: PrivateVaultBrokerDrainMetadata | null;
}

function bytesEqual(left: Uint8Array, right: Uint8Array) {
  return (
    left.byteLength === right.byteLength &&
    left.every((byte, index) => byte === right[index])
  );
}

function sha256(bytes: Uint8Array) {
  return createHash("sha256").update(bytes).digest("hex");
}

function mapDrainError(error: unknown): never {
  if (error instanceof PrivateVaultBrokerDrainNotFoundError) {
    throw new PrivateVaultBrokerReplacementError("not_found");
  }
  if (error instanceof PrivateVaultBrokerDrainConflictError) {
    throw new PrivateVaultBrokerReplacementError("conflict");
  }
  throw error;
}

function exactCanonicalOffer(bytes: Uint8Array, vaultId: Uint8Array) {
  const offer = decodeAncV1EndpointEnrollmentOffer(bytes, {
    expectedVaultId: vaultId,
  });
  if (!bytesEqual(encodeAncV1EndpointEnrollmentOffer(offer), bytes)) {
    throw new Error("noncanonical offer");
  }
  return offer;
}

function freshState(state: ControlLogState | null, now: Date) {
  if (!state) throw new PrivateVaultBrokerReplacementError("not_found");
  try {
    return assertFreshControlLogHead(state, now);
  } catch {
    throw new PrivateVaultBrokerReplacementError("conflict");
  }
}

function bindingsFor(
  status: PrivateVaultBrokerReplacementStatus,
): PrivateVaultBrokerReplacementBindings {
  return {
    oldBrokerEndpointId: status.oldBrokerEndpointId,
    newBrokerEndpointId: status.newBrokerEndpointId,
    authorizerEndpointId: status.authorizerEndpointId,
  };
}

async function loadState(scope: PrivateVaultBrokerReplacementScope, now: Date) {
  return freshState(
    await privateVaultControlLogService.loadVerifiedState(scope),
    now,
  );
}

async function resolveScope(
  event: H3Event,
  requestedVaultId?: string,
): Promise<PrivateVaultBrokerReplacementScope | null> {
  const session = await getCurrentBetterAuthSession(event).catch(() => null);
  if (!session?.email || !session.userId) return null;
  const org = await getOrgContext(event).catch(() => null);
  if (
    !org?.orgId ||
    org.email.trim().toLowerCase() !== session.email.trim().toLowerCase()
  ) {
    return null;
  }
  const logical = await resolvePrivateVaultGenesisAccountScope({
    userId: session.userId,
    email: session.email,
    orgId: org.orgId,
  });
  if (!logical) return null;
  const conditions = [
    eq(schema.contentEncryptedVaults.ownerEmail, logical.ownerEmail),
    eq(schema.contentEncryptedVaults.accountId, logical.accountId),
    eq(schema.contentEncryptedVaults.orgId, logical.orgId),
    eq(schema.contentEncryptedVaults.workspaceId, logical.workspaceId),
    eq(schema.contentEncryptedVaults.vaultState, "active"),
  ];
  if (requestedVaultId) {
    conditions.push(
      eq(schema.contentEncryptedVaults.vaultId, requestedVaultId),
    );
  }
  const rows = await getDb()
    .select({
      ownerEmail: schema.contentEncryptedVaults.ownerEmail,
      accountId: schema.contentEncryptedVaults.accountId,
      orgId: schema.contentEncryptedVaults.orgId,
      workspaceId: schema.contentEncryptedVaults.workspaceId,
      vaultId: schema.contentEncryptedVaults.vaultId,
    })
    .from(schema.contentEncryptedVaults)
    .where(and(...conditions))
    .limit(2);
  return rows.length === 1 ? rows[0]! : null;
}

export async function withAuthenticatedPrivateVaultBrokerReplacementScope<T>(
  event: H3Event,
  requestedVaultId: string | undefined,
  operation: (scope: PrivateVaultBrokerReplacementScope) => Promise<T>,
): Promise<T | null> {
  const scope = await resolveScope(event, requestedVaultId);
  if (!scope) return null;
  return runWithRequestContext(
    { userEmail: scope.ownerEmail, orgId: scope.orgId },
    () => operation(scope),
  );
}

export function createPrivateVaultBrokerReplacementOrchestration(
  options: { now?: () => Date } = {},
) {
  const now = options.now ?? (() => new Date());
  const transcript = createPrivateVaultBrokerReplacementTranscriptService({
    now,
  });
  const drainService = createPrivateVaultBrokerDrainService({
    now: () => now().toISOString(),
  });

  return {
    async offer(
      scope: PrivateVaultBrokerReplacementScope,
      offerBytes: Uint8Array,
    ) {
      const at = now();
      try {
        const vaultId = ancV1HexToBytes(scope.vaultId);
        const offer = exactCanonicalOffer(offerBytes, vaultId);
        if (
          offer.membershipRole !== "broker" ||
          !offer.unattended ||
          offer.createdAt > Math.floor(at.getTime() / 1000) ||
          offer.expiresAt <= Math.floor(at.getTime() / 1000)
        ) {
          throw new Error();
        }
        const state = await loadState(scope, at);
        const oldBrokers = state.activeMembers.filter(
          (member) => member.role === "broker" && member.unattended,
        );
        const authorizers = state.activeMembers
          .filter((member) => member.role === "endpoint" && !member.unattended)
          .sort((left, right) =>
            left.endpointId.localeCompare(right.endpointId),
          );
        const candidateId = ancV1LifecycleIdToHex(offer.endpointId);
        if (
          oldBrokers.length !== 1 ||
          authorizers.length < 1 ||
          state.activeMembers.some(
            (member) => member.endpointId === candidateId,
          ) ||
          state.removedEndpointIds.includes(candidateId)
        ) {
          throw new PrivateVaultBrokerReplacementError("conflict");
        }
        const offerHash = ancV1BytesToHex(
          await hashAncV1EndpointEnrollmentOffer(offerBytes, {
            expectedVaultId: vaultId,
          }),
        );
        return transcript.establish(scope, {
          transcriptId: offerHash,
          bindings: {
            oldBrokerEndpointId: oldBrokers[0]!.endpointId,
            newBrokerEndpointId: candidateId,
            authorizerEndpointId: authorizers[0]!.endpointId,
          },
          offer: offerBytes.slice(),
          expiresAt: new Date(offer.expiresAt * 1000).toISOString(),
        });
      } catch (error) {
        if (error instanceof PrivateVaultBrokerReplacementError) throw error;
        throw new PrivateVaultBrokerReplacementError("invalid_request");
      }
    },

    async challenge(
      scope: PrivateVaultBrokerReplacementScope,
      transcriptId: string,
      challenge: Uint8Array,
    ) {
      const at = now();
      const status = await transcript.read(scope, transcriptId);
      const state = await loadState(scope, at);
      try {
        const verified = await verifyAncV1BrokerReplacementChallenge(
          challenge,
          {
            encodedOffer: status.offer,
            verifiedControlState: state,
            expectedOldBrokerEndpointId: ancV1HexToBytes(
              status.oldBrokerEndpointId,
            ),
            now: Math.floor(at.getTime() / 1000),
          },
        );
        if (
          ancV1LifecycleIdToHex(verified.challenge.authorizerEndpointId) !==
          status.authorizerEndpointId
        ) {
          throw new Error();
        }
      } catch {
        throw new PrivateVaultBrokerReplacementError("invalid_request");
      }
      return transcript.advance(scope, transcriptId, {
        bindings: bindingsFor(status),
        offerHash: status.offerHash,
        to: "challenge",
        challenge: challenge.slice(),
      });
    },

    async sasDecision(
      scope: PrivateVaultBrokerReplacementScope,
      transcriptId: string,
      sasDecision: Uint8Array,
    ) {
      const at = now();
      const status = await transcript.read(scope, transcriptId);
      if (!status.challenge) {
        throw new PrivateVaultBrokerReplacementError("conflict");
      }
      const state = await loadState(scope, at);
      let verified;
      try {
        verified = await verifyAncV1BrokerReplacementSasDecision(sasDecision, {
          encodedOffer: status.offer,
          encodedChallenge: status.challenge,
          verifiedControlState: state,
          expectedOldBrokerEndpointId: ancV1HexToBytes(
            status.oldBrokerEndpointId,
          ),
          now: Math.floor(at.getTime() / 1000),
        });
      } catch {
        throw new PrivateVaultBrokerReplacementError("invalid_request");
      }
      if (verified.receipt.decision !== "confirmed") {
        return transcript.advance(scope, transcriptId, {
          bindings: bindingsFor(status),
          offerHash: status.offerHash,
          to: "rejected",
        });
      }
      return transcript.advance(scope, transcriptId, {
        bindings: bindingsFor(status),
        offerHash: status.offerHash,
        to: "candidate_confirmed",
        challengeHash: status.challengeHash!,
        sas: sasDecision.slice(),
      });
    },

    async approveAndFreeze(
      scope: PrivateVaultBrokerReplacementScope,
      transcriptId: string,
      signedApproval: Uint8Array,
    ) {
      const at = now();
      let status = await transcript.read(scope, transcriptId);
      if (
        status.phase === "draining" &&
        status.approval &&
        bytesEqual(status.approval, signedApproval)
      ) {
        return status;
      }
      if (
        (status.phase !== "candidate_confirmed" &&
          status.phase !== "authorized") ||
        !status.challenge ||
        !status.sas
      ) {
        throw new PrivateVaultBrokerReplacementError("conflict");
      }
      const state = await loadState(scope, at);
      try {
        const offer = exactCanonicalOffer(
          status.offer,
          ancV1HexToBytes(scope.vaultId),
        );
        const decoded = decodeAncV1BrokerReplacementApproval(signedApproval);
        const authorizer = state.activeMembers.find(
          (member) => member.endpointId === status.authorizerEndpointId,
        );
        if (
          !authorizer ||
          authorizer.role !== "endpoint" ||
          authorizer.unattended
        ) {
          throw new Error();
        }
        await verifyAncV1BrokerReplacementApproval(signedApproval, {
          vaultId: ancV1HexToBytes(scope.vaultId),
          issuerEndpointId: ancV1HexToBytes(status.authorizerEndpointId),
          oldBrokerEndpointId: ancV1HexToBytes(status.oldBrokerEndpointId),
          candidateBrokerEndpointId: offer.endpointId,
          candidateSigningPublicKey: offer.signingPublicKey,
          candidateKeyAgreementPublicKey: offer.keyAgreementPublicKey,
          candidateEnrollmentRef: decoded.envelopeId,
          offerHash: await hashAncV1EndpointEnrollmentOffer(status.offer, {
            expectedVaultId: offer.vaultId,
          }),
          challengeHash: await hashAncV1EnrollmentChallenge(
            status.challenge,
            offer.vaultId,
          ),
          sasDecisionHash: await ancV1Hash(
            "enrollment-sas-decision",
            status.sas,
          ),
          baseSequence: state.sequence,
          baseHeadHash: ancV1HexToBytes(state.headHash),
          baseMembershipHash: ancV1HexToBytes(state.membershipHash),
          baseEpoch: state.epoch,
          drainId: decoded.drainId,
          drainGeneration: decoded.drainGeneration,
          deadlineAtSeconds: decoded.deadlineAtSeconds,
          expectedCreatedAtSeconds: decoded.createdAtSeconds,
          nowSeconds: Math.floor(at.getTime() / 1000),
          issuerSigningPublicKey: ancV1HexToBytes(authorizer.signingPublicKey),
        });
        status = await transcript.advance(scope, transcriptId, {
          bindings: bindingsFor(status),
          offerHash: status.offerHash,
          to: "authorized",
          sasHash: status.sasHash!,
          authorization: signedApproval.slice(),
          approval: signedApproval.slice(),
        });
        const drainId = ancV1BytesToHex(
          await hashAncV1BrokerReplacementFreezeId(signedApproval),
        );
        const drainGeneration = String(decoded.drainGeneration).padStart(
          8,
          "0",
        );
        try {
          await drainService.freeze(scope, {
            drainId,
            oldBrokerEndpointId: status.oldBrokerEndpointId,
            replacementBrokerEndpointId: status.newBrokerEndpointId,
            authorizerEndpointId: status.authorizerEndpointId,
            authorizerApprovalId: drainId,
            authorizerApprovalHash: createHash("sha256")
              .update(signedApproval)
              .digest("hex"),
            drainGeneration,
            deadlineAt: new Date(
              decoded.deadlineAtSeconds * 1000,
            ).toISOString(),
          });
        } catch (error) {
          mapDrainError(error);
        }
        return transcript.advance(scope, transcriptId, {
          bindings: bindingsFor(status),
          offerHash: status.offerHash,
          to: "draining",
          approvalHash: status.approvalHash!,
          drainId,
          drainGeneration,
        });
      } catch (error) {
        if (error instanceof PrivateVaultBrokerReplacementError) throw error;
        throw new PrivateVaultBrokerReplacementError("invalid_request");
      }
    },

    async witnessProgress(
      scope: PrivateVaultBrokerReplacementScope,
      transcriptId: string,
    ) {
      const status = await transcript.read(scope, transcriptId);
      if (status.phase !== "draining" || !status.drainId) {
        throw new PrivateVaultBrokerReplacementError("conflict");
      }
      try {
        return await drainService.witness(scope, status.drainId);
      } catch (error) {
        mapDrainError(error);
      }
    },

    async attestDrain(
      scope: PrivateVaultBrokerReplacementScope,
      transcriptId: string,
      signedAttestation: Uint8Array,
    ) {
      const at = now();
      const status = await transcript.read(scope, transcriptId);
      if (
        status.phase === "drained" &&
        status.drainAttestation &&
        bytesEqual(status.drainAttestation, signedAttestation)
      ) {
        return status;
      }
      if (
        status.phase !== "draining" ||
        !status.challenge ||
        !status.sas ||
        !status.approval ||
        !status.drainId ||
        !status.drainGeneration
      ) {
        throw new PrivateVaultBrokerReplacementError("conflict");
      }
      let drain: PrivateVaultBrokerDrainMetadata;
      try {
        drain = await drainService.witness(scope, status.drainId);
      } catch (error) {
        mapDrainError(error);
      }
      if (
        drain.phase !== "witnessed" ||
        drain.witnessGeneration !== 1 ||
        drain.totalJobCount === null ||
        drain.completedJobCount === null ||
        drain.failedJobCount === null ||
        drain.cancelledJobCount === null ||
        !drain.terminalJobsDigest ||
        drain.oldBrokerEndpointId !== status.oldBrokerEndpointId ||
        drain.replacementBrokerEndpointId !== status.newBrokerEndpointId ||
        drain.authorizerEndpointId !== status.authorizerEndpointId ||
        drain.drainGeneration !== status.drainGeneration
      ) {
        throw new PrivateVaultBrokerReplacementError("conflict");
      }
      const state = await loadState(scope, at);
      try {
        const offer = exactCanonicalOffer(
          status.offer,
          ancV1HexToBytes(scope.vaultId),
        );
        const approval = decodeAncV1BrokerReplacementApproval(status.approval);
        const authorizer = state.activeMembers.find(
          (member) => member.endpointId === status.authorizerEndpointId,
        );
        if (
          !authorizer ||
          authorizer.role !== "endpoint" ||
          authorizer.unattended
        ) {
          throw new Error();
        }
        await verifyAncV1BrokerReplacementApproval(status.approval, {
          vaultId: ancV1HexToBytes(scope.vaultId),
          issuerEndpointId: ancV1HexToBytes(status.authorizerEndpointId),
          oldBrokerEndpointId: ancV1HexToBytes(status.oldBrokerEndpointId),
          candidateBrokerEndpointId: offer.endpointId,
          candidateSigningPublicKey: offer.signingPublicKey,
          candidateKeyAgreementPublicKey: offer.keyAgreementPublicKey,
          candidateEnrollmentRef: approval.envelopeId,
          offerHash: await hashAncV1EndpointEnrollmentOffer(status.offer, {
            expectedVaultId: offer.vaultId,
          }),
          challengeHash: await hashAncV1EnrollmentChallenge(
            status.challenge,
            offer.vaultId,
          ),
          sasDecisionHash: await ancV1Hash(
            "enrollment-sas-decision",
            status.sas,
          ),
          baseSequence: state.sequence,
          baseHeadHash: ancV1HexToBytes(state.headHash),
          baseMembershipHash: ancV1HexToBytes(state.membershipHash),
          baseEpoch: state.epoch,
          drainId: approval.drainId,
          drainGeneration: approval.drainGeneration,
          deadlineAtSeconds: approval.deadlineAtSeconds,
          expectedCreatedAtSeconds: approval.createdAtSeconds,
          nowSeconds: Math.floor(at.getTime() / 1000),
          issuerSigningPublicKey: ancV1HexToBytes(authorizer.signingPublicKey),
        });
        const attestation = await verifyAncV1BrokerDrainAttestation(
          signedAttestation,
          {
            vaultId: ancV1HexToBytes(scope.vaultId),
            issuerEndpointId: ancV1HexToBytes(status.authorizerEndpointId),
            oldBrokerEndpointId: ancV1HexToBytes(status.oldBrokerEndpointId),
            candidateBrokerEndpointId: offer.endpointId,
            candidateSigningPublicKey: offer.signingPublicKey,
            candidateKeyAgreementPublicKey: offer.keyAgreementPublicKey,
            candidateEnrollmentRef: approval.envelopeId,
            baseSequence: state.sequence,
            baseHeadHash: ancV1HexToBytes(state.headHash),
            baseEpoch: state.epoch,
            drainGeneration: approval.drainGeneration,
            drainedJobCount: drain.totalJobCount,
            drainDigest: ancV1HexToBytes(drain.terminalJobsDigest),
            expectedCreatedAtSeconds: Math.floor(
              Date.parse(state.signedAt) / 1000,
            ),
            nowSeconds: Math.floor(at.getTime() / 1000),
            issuerSigningPublicKey: ancV1HexToBytes(
              authorizer.signingPublicKey,
            ),
          },
        );
        if (attestation.outstandingJobCount !== 0) throw new Error();
      } catch {
        throw new PrivateVaultBrokerReplacementError("invalid_request");
      }
      return transcript.advance(scope, transcriptId, {
        bindings: bindingsFor(status),
        offerHash: status.offerHash,
        to: "drained",
        drainId: status.drainId,
        drainGeneration: status.drainGeneration,
        totalCount: drain.totalJobCount,
        completedCount: drain.completedJobCount,
        failedCount: drain.failedJobCount,
        cancelledCount: drain.cancelledJobCount,
        drainDigest: drain.terminalJobsDigest,
        signedDrainAttestation: signedAttestation.slice(),
      });
    },

    async commitRotation(
      scope: PrivateVaultBrokerReplacementScope,
      transcriptId: string,
      body: Uint8Array,
      proof: EndpointRequestProof,
    ) {
      const at = now();
      const status = await transcript.read(scope, transcriptId);
      let request: ReturnType<
        typeof decodeAncV1ControlLogRotationAppendRequest
      >;
      let entry: ReturnType<typeof decodeSignedControlLogEntry>;
      try {
        request = decodeAncV1ControlLogRotationAppendRequest(body);
        entry = decodeSignedControlLogEntry(request.signedEntry);
      } catch {
        throw new PrivateVaultBrokerReplacementError("invalid_request");
      }

      if (status.phase === "rotation_committed") {
        if (!status.rotationReceipt || !status.rotationControlEntryHash) {
          throw new PrivateVaultBrokerReplacementError("unavailable");
        }
        try {
          const verifiedReceipt = await appendPrivateVaultControlLogRotation({
            body,
            proof,
            now: at,
            expectedProofPath: `/api/private-vault/broker-replacement/${transcriptId}/commit`,
            onVerifiedRotationAppend: async () => {
              throw new Error("committed retry attempted a second mutation");
            },
          });
          const committed =
            await privateVaultControlLogService.loadVerifiedEntry(
              scope,
              request.signedEntry,
            );
          const receipt = decodeAncV1ControlLogRotationAppendReceipt(
            status.rotationReceipt,
          );
          const wrapHash = ancV1BytesToHex(
            await hashAncV1RecoveryWrap(
              request.recoveryWrap,
              ancV1HexToBytes(scope.vaultId),
            ),
          );
          const drain = status.drainId
            ? await drainService.get(scope, status.drainId)
            : null;
          if (
            !drain ||
            !bytesEqual(verifiedReceipt, status.rotationReceipt) ||
            drain.phase !== "committed" ||
            drain.completionId !== entry.envelopeId ||
            committed.entryHash !== status.rotationControlEntryHash ||
            committed.entry.envelopeId !== status.rotationControlEntryId ||
            committed.state.sequence !== status.rotationControlSequence ||
            receipt.entryId !== status.rotationControlEntryId ||
            receipt.sequence !== status.rotationControlSequence ||
            receipt.headHash !== status.rotationControlEntryHash ||
            receipt.recoveryWrapHash !== wrapHash ||
            receipt.recoveryWrapByteLength !== request.recoveryWrap.byteLength
          ) {
            throw new Error();
          }
          return status;
        } catch {
          throw new PrivateVaultBrokerReplacementError("conflict");
        }
      }

      if (
        status.phase !== "drained" ||
        !status.challenge ||
        !status.sas ||
        !status.approval ||
        !status.drainId ||
        !status.drainGeneration ||
        !status.drainDigest ||
        !status.drainAttestation ||
        !status.drainAttestationHash
      ) {
        throw new PrivateVaultBrokerReplacementError("conflict");
      }
      const state = await loadState(scope, at);
      let drain: PrivateVaultBrokerDrainMetadata;
      try {
        drain = await drainService.get(scope, status.drainId);
      } catch (error) {
        mapDrainError(error);
      }
      try {
        const offer = exactCanonicalOffer(
          status.offer,
          ancV1HexToBytes(scope.vaultId),
        );
        const approval = decodeAncV1BrokerReplacementApproval(status.approval);
        const authorizer = state.activeMembers.find(
          (member) => member.endpointId === status.authorizerEndpointId,
        );
        const rotation = entry.innerEnvelope;
        const candidate =
          rotation.type === "membership_commit"
            ? rotation.activeMembers.find(
                (member) => member.endpointId === status.newBrokerEndpointId,
              )
            : null;
        if (
          !authorizer ||
          authorizer.role !== "endpoint" ||
          authorizer.unattended ||
          drain.phase !== "witnessed" ||
          drain.witnessGeneration !== 1 ||
          drain.terminalJobsDigest !== status.drainDigest ||
          drain.totalJobCount !== status.drainTotalCount ||
          drain.completedJobCount !== status.drainCompletedCount ||
          drain.failedJobCount !== status.drainFailedCount ||
          drain.cancelledJobCount !== status.drainCancelledCount ||
          entry.vaultId !== scope.vaultId ||
          entry.signerEndpointId !== status.authorizerEndpointId ||
          entry.sequence !== state.sequence + 1 ||
          entry.previousHash !== state.headHash ||
          rotation.type !== "membership_commit" ||
          rotation.ceremonyKind !== "broker_replacement" ||
          rotation.epoch !== state.epoch + 1 ||
          !rotation.rotationCompleted ||
          !rotation.outstandingJobsResolved ||
          rotation.removedEndpointIds.length !== 1 ||
          rotation.removedEndpointIds[0] !== status.oldBrokerEndpointId ||
          !candidate ||
          candidate.role !== "broker" ||
          !candidate.unattended ||
          candidate.signingPublicKey !==
            ancV1BytesToHex(offer.signingPublicKey) ||
          candidate.keyAgreementPublicKey !==
            ancV1BytesToHex(offer.keyAgreementPublicKey) ||
          candidate.enrollmentRef !== ancV1BytesToHex(approval.envelopeId)
        ) {
          throw new Error();
        }
        await verifyAncV1BrokerReplacementApproval(status.approval, {
          vaultId: ancV1HexToBytes(scope.vaultId),
          issuerEndpointId: ancV1HexToBytes(status.authorizerEndpointId),
          oldBrokerEndpointId: ancV1HexToBytes(status.oldBrokerEndpointId),
          candidateBrokerEndpointId: offer.endpointId,
          candidateSigningPublicKey: offer.signingPublicKey,
          candidateKeyAgreementPublicKey: offer.keyAgreementPublicKey,
          candidateEnrollmentRef: approval.envelopeId,
          offerHash: await hashAncV1EndpointEnrollmentOffer(status.offer, {
            expectedVaultId: offer.vaultId,
          }),
          challengeHash: await hashAncV1EnrollmentChallenge(
            status.challenge,
            offer.vaultId,
          ),
          sasDecisionHash: await ancV1Hash(
            "enrollment-sas-decision",
            status.sas,
          ),
          baseSequence: state.sequence,
          baseHeadHash: ancV1HexToBytes(state.headHash),
          baseMembershipHash: ancV1HexToBytes(state.membershipHash),
          baseEpoch: state.epoch,
          drainId: approval.drainId,
          drainGeneration: approval.drainGeneration,
          deadlineAtSeconds: approval.deadlineAtSeconds,
          expectedCreatedAtSeconds: approval.createdAtSeconds,
          nowSeconds: Math.floor(at.getTime() / 1000),
          issuerSigningPublicKey: ancV1HexToBytes(authorizer.signingPublicKey),
        });
        const attestation = await verifyAncV1BrokerDrainAttestation(
          status.drainAttestation,
          {
            vaultId: ancV1HexToBytes(scope.vaultId),
            issuerEndpointId: ancV1HexToBytes(status.authorizerEndpointId),
            oldBrokerEndpointId: ancV1HexToBytes(status.oldBrokerEndpointId),
            candidateBrokerEndpointId: offer.endpointId,
            candidateSigningPublicKey: offer.signingPublicKey,
            candidateKeyAgreementPublicKey: offer.keyAgreementPublicKey,
            candidateEnrollmentRef: approval.envelopeId,
            baseSequence: state.sequence,
            baseHeadHash: ancV1HexToBytes(state.headHash),
            baseEpoch: state.epoch,
            drainGeneration: approval.drainGeneration,
            drainedJobCount: drain.totalJobCount!,
            drainDigest: ancV1HexToBytes(status.drainDigest),
            expectedCreatedAtSeconds: Math.floor(
              Date.parse(state.signedAt) / 1000,
            ),
            nowSeconds: Math.floor(at.getTime() / 1000),
            issuerSigningPublicKey: ancV1HexToBytes(
              authorizer.signingPublicKey,
            ),
          },
        );
        if (attestation.outstandingJobCount !== 0) throw new Error();
      } catch {
        throw new PrivateVaultBrokerReplacementError("invalid_request");
      }

      try {
        await appendPrivateVaultControlLogRotation({
          body,
          proof,
          now: at,
          expectedProofPath: `/api/private-vault/broker-replacement/${transcriptId}/commit`,
          onVerifiedRotationAppend: async ({
            tx,
            entryHash,
            rotationReceipt,
            serverReceivedAt,
          }) => {
            const [committedDrain] = await tx
              .update(schema.contentEncryptedVaultBrokerReplacementDrains)
              .set({
                phase: "committed",
                activeKey: null,
                completionId: entry.envelopeId,
                completedAt: serverReceivedAt,
                updatedAt: serverReceivedAt,
              })
              .where(
                and(
                  eq(
                    schema.contentEncryptedVaultBrokerReplacementDrains.drainId,
                    status.drainId!,
                  ),
                  eq(
                    schema.contentEncryptedVaultBrokerReplacementDrains.vaultId,
                    scope.vaultId,
                  ),
                  eq(
                    schema.contentEncryptedVaultBrokerReplacementDrains
                      .ownerEmail,
                    scope.ownerEmail,
                  ),
                  eq(
                    schema.contentEncryptedVaultBrokerReplacementDrains.orgId,
                    scope.orgId,
                  ),
                  eq(
                    schema.contentEncryptedVaultBrokerReplacementDrains.phase,
                    "witnessed",
                  ),
                  eq(
                    schema.contentEncryptedVaultBrokerReplacementDrains
                      .oldBrokerEndpointId,
                    status.oldBrokerEndpointId,
                  ),
                  eq(
                    schema.contentEncryptedVaultBrokerReplacementDrains
                      .replacementBrokerEndpointId,
                    status.newBrokerEndpointId,
                  ),
                  eq(
                    schema.contentEncryptedVaultBrokerReplacementDrains
                      .authorizerEndpointId,
                    status.authorizerEndpointId,
                  ),
                  eq(
                    schema.contentEncryptedVaultBrokerReplacementDrains
                      .drainGeneration,
                    status.drainGeneration!,
                  ),
                  eq(
                    schema.contentEncryptedVaultBrokerReplacementDrains
                      .witnessGeneration,
                    1,
                  ),
                  eq(
                    schema.contentEncryptedVaultBrokerReplacementDrains
                      .terminalJobsDigest,
                    status.drainDigest!,
                  ),
                ),
              )
              .returning({
                drainId:
                  schema.contentEncryptedVaultBrokerReplacementDrains.drainId,
              });
            if (!committedDrain) throw new Error("drain changed");
            const [committedTranscript] = await tx
              .update(schema.contentEncryptedVaultBrokerReplacementTranscripts)
              .set({
                phase: "rotation_committed",
                rotationControlEntryId: entry.envelopeId,
                rotationControlEntryHash: entryHash,
                rotationControlSequence: entry.sequence,
                rotationReceiptHash: sha256(rotationReceipt),
                rotationReceiptBytesBase64url:
                  Buffer.from(rotationReceipt).toString("base64url"),
                rotationCommittedAt: serverReceivedAt,
                updatedAt: serverReceivedAt,
              })
              .where(
                and(
                  eq(
                    schema.contentEncryptedVaultBrokerReplacementTranscripts
                      .transcriptId,
                    transcriptId,
                  ),
                  eq(
                    schema.contentEncryptedVaultBrokerReplacementTranscripts
                      .ownerEmail,
                    scope.ownerEmail,
                  ),
                  eq(
                    schema.contentEncryptedVaultBrokerReplacementTranscripts
                      .accountId,
                    scope.accountId,
                  ),
                  eq(
                    schema.contentEncryptedVaultBrokerReplacementTranscripts
                      .orgId,
                    scope.orgId,
                  ),
                  eq(
                    schema.contentEncryptedVaultBrokerReplacementTranscripts
                      .workspaceId,
                    scope.workspaceId,
                  ),
                  eq(
                    schema.contentEncryptedVaultBrokerReplacementTranscripts
                      .vaultId,
                    scope.vaultId,
                  ),
                  eq(
                    schema.contentEncryptedVaultBrokerReplacementTranscripts
                      .phase,
                    "drained",
                  ),
                  eq(
                    schema.contentEncryptedVaultBrokerReplacementTranscripts
                      .oldBrokerEndpointId,
                    status.oldBrokerEndpointId,
                  ),
                  eq(
                    schema.contentEncryptedVaultBrokerReplacementTranscripts
                      .newBrokerEndpointId,
                    status.newBrokerEndpointId,
                  ),
                  eq(
                    schema.contentEncryptedVaultBrokerReplacementTranscripts
                      .authorizerEndpointId,
                    status.authorizerEndpointId,
                  ),
                  eq(
                    schema.contentEncryptedVaultBrokerReplacementTranscripts
                      .offerHash,
                    status.offerHash,
                  ),
                  eq(
                    schema.contentEncryptedVaultBrokerReplacementTranscripts
                      .drainId,
                    status.drainId!,
                  ),
                  eq(
                    schema.contentEncryptedVaultBrokerReplacementTranscripts
                      .drainGeneration,
                    status.drainGeneration!,
                  ),
                  eq(
                    schema.contentEncryptedVaultBrokerReplacementTranscripts
                      .drainDigest,
                    status.drainDigest!,
                  ),
                  eq(
                    schema.contentEncryptedVaultBrokerReplacementTranscripts
                      .drainAttestationHash,
                    status.drainAttestationHash!,
                  ),
                ),
              )
              .returning({
                transcriptId:
                  schema.contentEncryptedVaultBrokerReplacementTranscripts
                    .transcriptId,
              });
            if (!committedTranscript) throw new Error("transcript changed");
          },
        });
      } catch (error) {
        if (error instanceof PrivateVaultControlLogAppendError) {
          if (error.code === "conflict") {
            throw new PrivateVaultBrokerReplacementError("conflict");
          }
          if (error.code === "unavailable") {
            throw new PrivateVaultBrokerReplacementError("unavailable");
          }
          throw new PrivateVaultBrokerReplacementError("invalid_request");
        }
        throw error;
      }
      return transcript.read(scope, transcriptId);
    },

    async deadline(
      scope: PrivateVaultBrokerReplacementScope,
      transcriptId: string,
      decision: PrivateVaultBrokerReplacementDeadlineDecision,
    ) {
      const status = await transcript.read(scope, transcriptId);
      if (
        status.phase === "aborted" &&
        status.drainId &&
        decision === "abort"
      ) {
        try {
          const existing = await drainService.get(scope, status.drainId);
          if (
            existing.phase === "aborted" &&
            existing.deadlineDecision === "abort"
          ) {
            return status;
          }
        } catch (error) {
          mapDrainError(error);
        }
      }
      if (status.phase !== "draining" || !status.drainId) {
        throw new PrivateVaultBrokerReplacementError("conflict");
      }
      const decisionId = createHash("sha256")
        .update(
          JSON.stringify([
            "anc/v1/broker-replacement-deadline",
            scope.vaultId,
            transcriptId,
            status.drainId,
            decision,
          ]),
        )
        .digest("hex");
      let drain: PrivateVaultBrokerDrainMetadata;
      try {
        drain = await drainService.resolveDeadline(scope, {
          drainId: status.drainId,
          decisionId,
          decision,
        });
      } catch (error) {
        mapDrainError(error);
      }
      if (drain.phase !== "aborted") return status;
      return transcript.advance(scope, transcriptId, {
        bindings: bindingsFor(status),
        offerHash: status.offerHash,
        to: "aborted",
      });
    },

    async status(
      scope: PrivateVaultBrokerReplacementScope,
      transcriptId: string,
    ): Promise<PrivateVaultBrokerReplacementProgress> {
      const status = await transcript.read(scope, transcriptId);
      if (!status.drainId) return { transcript: status, drain: null };
      let drain: PrivateVaultBrokerDrainMetadata;
      try {
        drain = await drainService.get(scope, status.drainId);
      } catch (error) {
        mapDrainError(error);
      }
      return {
        transcript: status,
        drain,
      };
    },
  };
}

export const privateVaultBrokerReplacementOrchestration =
  createPrivateVaultBrokerReplacementOrchestration();

export const privateVaultBrokerReplacementProtocolLimits = Object.freeze({
  offerBytes: privateVaultBrokerReplacementLimits.offerBytes,
  challengeBytes: privateVaultBrokerReplacementLimits.challengeBytes,
  sasDecisionBytes: privateVaultBrokerReplacementLimits.sasBytes,
  approvalBytes: ANC_BROKER_REPLACEMENT_APPROVAL_LIMITS.encodedBytes,
  rotationAppendBytes: ANC_V1_CONTROL_LOG_APPEND_REQUEST_MAX_BYTES,
  drainAttestationBytes:
    privateVaultBrokerReplacementLimits.drainAttestationBytes,
  deadlineDecisionBytes: Math.max(
    ...DEADLINE_DECISIONS.map((decision) => Buffer.byteLength(decision)),
  ),
});

export function decodePrivateVaultBrokerReplacementDeadlineDecision(
  bytes: Uint8Array,
): PrivateVaultBrokerReplacementDeadlineDecision {
  try {
    const value = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    if (!DEADLINE_DECISIONS.includes(value as never)) throw new Error();
    return value as PrivateVaultBrokerReplacementDeadlineDecision;
  } catch {
    throw new PrivateVaultBrokerReplacementError("invalid_request");
  }
}

export function isPrivateVaultBrokerReplacementTranscriptId(value: string) {
  return SHA256.test(value);
}

export function privateVaultBrokerReplacementOfferVaultId(offer: Uint8Array) {
  try {
    const decoded = decodeAncV1Canonical(offer, {
      maxBytes: privateVaultBrokerReplacementProtocolLimits.offerBytes,
    });
    if (!(decoded instanceof Map)) throw new Error();
    const value = decoded.get(E2EE_ENVELOPE_FIELDS.common.vaultId);
    if (!(value instanceof Uint8Array) || value.byteLength !== 16) {
      throw new Error();
    }
    return ancV1BytesToHex(value);
  } catch {
    throw new PrivateVaultBrokerReplacementError("invalid_request");
  }
}
