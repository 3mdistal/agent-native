import { rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  ancV1BoxKeypairFromSeed,
  ancV1BytesToHex,
  ancV1SigningKeypairFromSeed,
  createAncV1CandidateKeyProof,
  decodeAncV1EndpointEnrollmentOffer,
  encodeAncV1BrokerDrainAttestation,
  encodeAncV1BrokerReplacementApproval,
  encodeAncV1EnrollmentChallenge,
  encodeAncV1EnrollmentSasDecision,
  encodeAncV1EndpointEnrollmentOffer,
  hashAncV1EndpointEnrollmentOffer,
  hashAncV1EnrollmentChallenge,
  hashAncV1EnrollmentSasTranscript,
  ancV1Hash,
  signAncV1BrokerDrainAttestation,
  signAncV1BrokerReplacementApproval,
  signAncV1EnrollmentChallenge,
  signAncV1EnrollmentSasDecision,
  type ControlLogState,
} from "@agent-native/core/e2ee";
import { eq } from "drizzle-orm";
import {
  afterAll,
  beforeAll,
  beforeEach,
  describe,
  expect,
  it,
  vi,
} from "vitest";

const TEST_DB_PATH = join(
  tmpdir(),
  `private-vault-broker-replacement-orchestration-${process.pid}-${Date.now()}.sqlite`,
);
const NOW = new Date("2026-07-19T12:00:00.000Z");
const VAULT_ID = "11".repeat(16);
const AUTHORIZER_ID = "22".repeat(16);
const OLD_BROKER_ID = "33".repeat(16);
const CANDIDATE_ID = "44".repeat(16);
const scope = {
  ownerEmail: "replacement-owner@example.test",
  accountId: "account:replacement",
  orgId: "org:replacement",
  workspaceId: "workspace:replacement",
  vaultId: VAULT_ID,
};

const loadVerifiedState = vi.fn<() => Promise<ControlLogState | null>>();
vi.mock("./private-vault-control-log-runtime.js", () => ({
  privateVaultControlLogService: { loadVerifiedState },
}));

let getDb: (typeof import("../db/index.js"))["getDb"];
let schema: typeof import("../db/schema.js");
let createOrchestration: (typeof import("./private-vault-broker-replacement-orchestration.js"))["createPrivateVaultBrokerReplacementOrchestration"];
let authorizerSigning: Awaited<ReturnType<typeof ancV1SigningKeypairFromSeed>>;
let authorizerAgreement: Awaited<ReturnType<typeof ancV1BoxKeypairFromSeed>>;

function controlState(changes: Partial<ControlLogState> = {}): ControlLogState {
  return {
    vaultId: VAULT_ID,
    sequence: 7,
    headHash: "55".repeat(32),
    membershipHash: "66".repeat(32),
    signedAt: NOW.toISOString(),
    epoch: 3,
    activeMembers: [
      {
        endpointId: AUTHORIZER_ID,
        role: "endpoint",
        unattended: false,
        signingPublicKey: ancV1BytesToHex(authorizerSigning.publicKey),
        keyAgreementPublicKey: ancV1BytesToHex(authorizerAgreement.publicKey),
        enrollmentRef: "77".repeat(16),
      },
      {
        endpointId: OLD_BROKER_ID,
        role: "broker",
        unattended: true,
        signingPublicKey: "88".repeat(32),
        keyAgreementPublicKey: "99".repeat(32),
        enrollmentRef: "aa".repeat(16),
      },
    ],
    removedEndpointIds: [],
    freshnessMode: "endpoint_witnessed",
    recoveryGeneration: 1,
    recoveryId: "bb".repeat(16),
    recoverySigningPublicKey: "cc".repeat(32),
    recoveryKeyAgreementPublicKey: "dd".repeat(32),
    recoveryWrapHash: "ee".repeat(32),
    ...changes,
  };
}

async function candidateOffer() {
  const signing = await ancV1SigningKeypairFromSeed(new Uint8Array(32).fill(3));
  const agreement = await ancV1BoxKeypairFromSeed(new Uint8Array(32).fill(4));
  return {
    signing,
    encoded: encodeAncV1EndpointEnrollmentOffer({
      suite: "anc/v1",
      vaultId: Uint8Array.from(Buffer.from(VAULT_ID, "hex")),
      type: "enrollment-offer",
      createdAt: Math.floor(NOW.getTime() / 1000),
      envelopeId: new Uint8Array(16).fill(5),
      endpointId: Uint8Array.from(Buffer.from(CANDIDATE_ID, "hex")),
      ceremonyId: new Uint8Array(16).fill(6),
      membershipRole: "broker",
      unattended: true,
      signingPublicKey: signing.publicKey,
      keyAgreementPublicKey: agreement.publicKey,
      enrollmentNonce: new Uint8Array(32).fill(7),
      expiresAt: Math.floor(NOW.getTime() / 1000) + 600,
    }),
  };
}

async function ceremony(offerBytes: Uint8Array) {
  const offer = decodeAncV1EndpointEnrollmentOffer(offerBytes, {
    expectedVaultId: Uint8Array.from(Buffer.from(VAULT_ID, "hex")),
  });
  const candidate = await ancV1SigningKeypairFromSeed(
    new Uint8Array(32).fill(3),
  );
  const offerHash = await hashAncV1EndpointEnrollmentOffer(offerBytes, {
    expectedVaultId: offer.vaultId,
  });
  const candidateKeyProof = await createAncV1CandidateKeyProof(
    offerHash,
    candidate.privateKey,
  );
  const state = controlState();
  const challengeBase = {
    suite: "anc/v1" as const,
    vaultId: offer.vaultId,
    type: "enrollment-challenge" as const,
    createdAt: Math.floor(NOW.getTime() / 1000) + 1,
    envelopeId: new Uint8Array(16).fill(8),
    offerHash,
    candidateKeyProof,
    authorizerEndpointId: Uint8Array.from(Buffer.from(AUTHORIZER_ID, "hex")),
    authorizerSigningPublicKey: authorizerSigning.publicKey,
    authorizerKeyAgreementPublicKey: authorizerAgreement.publicKey,
    controlSequence: state.sequence,
    controlHeadHash: Uint8Array.from(Buffer.from(state.headHash, "hex")),
    membershipHash: Uint8Array.from(Buffer.from(state.membershipHash, "hex")),
    targetMembershipRole: "broker" as const,
    challengeNonce: new Uint8Array(32).fill(9),
    expiresAt: Math.floor(NOW.getTime() / 1000) + 300,
  };
  const sasTranscriptHash = await hashAncV1EnrollmentSasTranscript({
    suite: "anc/v1",
    vaultId: offer.vaultId,
    type: "enrollment-sas",
    ceremonyId: offer.ceremonyId,
    offerHash,
    candidateEndpointId: offer.endpointId,
    candidateSigningPublicKey: offer.signingPublicKey,
    candidateKeyAgreementPublicKey: offer.keyAgreementPublicKey,
    candidateKeyProof,
    authorizerEndpointId: challengeBase.authorizerEndpointId,
    authorizerSigningPublicKey: challengeBase.authorizerSigningPublicKey,
    authorizerKeyAgreementPublicKey:
      challengeBase.authorizerKeyAgreementPublicKey,
    controlSequence: challengeBase.controlSequence,
    controlHeadHash: challengeBase.controlHeadHash,
    membershipHash: challengeBase.membershipHash,
    targetMembershipRole: challengeBase.targetMembershipRole,
    challengeNonce: challengeBase.challengeNonce,
    challengeEnvelopeId: challengeBase.envelopeId,
    challengeCreatedAt: challengeBase.createdAt,
    challengeExpiresAt: challengeBase.expiresAt,
  });
  const challenge = encodeAncV1EnrollmentChallenge(
    await signAncV1EnrollmentChallenge(
      { ...challengeBase, sasTranscriptHash },
      authorizerSigning.privateKey,
    ),
  );
  const decision = encodeAncV1EnrollmentSasDecision(
    await signAncV1EnrollmentSasDecision(
      {
        suite: "anc/v1",
        vaultId: offer.vaultId,
        type: "enrollment-sas-decision",
        createdAt: challengeBase.createdAt + 1,
        envelopeId: new Uint8Array(16).fill(10),
        offerHash,
        challengeHash: await hashAncV1EnrollmentChallenge(
          challenge,
          offer.vaultId,
        ),
        sasTranscriptHash,
        candidateEndpointId: offer.endpointId,
        ceremonyId: offer.ceremonyId,
        decision: "confirmed",
      },
      candidate.privateKey,
    ),
  );
  return { challenge, decision };
}

async function approval(
  offerBytes: Uint8Array,
  challenge: Uint8Array,
  decision: Uint8Array,
  deadlineAtSeconds = Math.floor(NOW.getTime() / 1000) + 600,
) {
  const offer = decodeAncV1EndpointEnrollmentOffer(offerBytes, {
    expectedVaultId: Uint8Array.from(Buffer.from(VAULT_ID, "hex")),
  });
  const state = controlState();
  const envelopeId = new Uint8Array(16).fill(11);
  return encodeAncV1BrokerReplacementApproval(
    await signAncV1BrokerReplacementApproval(
      {
        suite: "anc/v1",
        vaultId: offer.vaultId,
        type: "broker_replacement_approval",
        createdAtSeconds: Math.floor(NOW.getTime() / 1000) + 3,
        envelopeId,
        issuerEndpointId: Uint8Array.from(Buffer.from(AUTHORIZER_ID, "hex")),
        oldBrokerEndpointId: Uint8Array.from(Buffer.from(OLD_BROKER_ID, "hex")),
        candidateBrokerEndpointId: offer.endpointId,
        candidateSigningPublicKey: offer.signingPublicKey,
        candidateKeyAgreementPublicKey: offer.keyAgreementPublicKey,
        candidateEnrollmentRef: envelopeId,
        offerHash: await hashAncV1EndpointEnrollmentOffer(offerBytes, {
          expectedVaultId: offer.vaultId,
        }),
        challengeHash: await hashAncV1EnrollmentChallenge(
          challenge,
          offer.vaultId,
        ),
        sasDecisionHash: await ancV1Hash("enrollment-sas-decision", decision),
        baseSequence: state.sequence,
        baseHeadHash: Uint8Array.from(Buffer.from(state.headHash, "hex")),
        baseMembershipHash: Uint8Array.from(
          Buffer.from(state.membershipHash, "hex"),
        ),
        baseEpoch: state.epoch,
        drainId: new Uint8Array(16).fill(12),
        drainGeneration: 8,
        deadlineAtSeconds,
      },
      authorizerSigning.privateKey,
    ),
  );
}

beforeAll(async () => {
  process.env.DATABASE_URL = `file:${TEST_DB_PATH}`;
  authorizerSigning = await ancV1SigningKeypairFromSeed(
    new Uint8Array(32).fill(1),
  );
  authorizerAgreement = await ancV1BoxKeypairFromSeed(
    new Uint8Array(32).fill(2),
  );
  const db = await import("../db/index.js");
  getDb = db.getDb;
  schema = db.schema;
  await (await import("../plugins/db.js")).default(undefined as never);
  createOrchestration = (
    await import("./private-vault-broker-replacement-orchestration.js")
  ).createPrivateVaultBrokerReplacementOrchestration;
}, 60_000);

beforeEach(async () => {
  await getDb().delete(
    schema.contentEncryptedVaultBrokerReplacementTranscripts,
  );
  await getDb().delete(schema.contentEncryptedVaultEndpoints);
  await getDb().delete(schema.contentEncryptedVaults);
  await getDb()
    .insert(schema.contentEncryptedVaults)
    .values({
      ...scope,
      vaultState: "active",
    });
  await getDb()
    .insert(schema.contentEncryptedVaultEndpoints)
    .values(
      [AUTHORIZER_ID, OLD_BROKER_ID].map((endpointId) => ({
        endpointId,
        vaultId: VAULT_ID,
        ownerEmail: scope.ownerEmail,
        orgId: scope.orgId,
        endpointState: "online",
        publicIdentityJson: "{}",
      })),
    );
  loadVerifiedState.mockReset();
  loadVerifiedState.mockResolvedValue(controlState());
});

afterAll(() => {
  for (const suffix of ["", "-shm", "-wal"]) {
    rmSync(`${TEST_DB_PATH}${suffix}`, { force: true });
  }
});

describe("Private Vault broker replacement pre-approval rendezvous", () => {
  it("establishes one scoped replacement and verifies exact challenge and candidate SAS", async () => {
    let clock = NOW;
    const service = createOrchestration({ now: () => clock });
    const offer = await candidateOffer();
    const first = await service.offer(scope, offer.encoded);
    await expect(service.offer(scope, offer.encoded)).resolves.toEqual(first);
    await expect(
      service.status(
        { ...scope, ownerEmail: "attacker@example.test" },
        first.transcriptId,
      ),
    ).rejects.toMatchObject({ code: "not_found" });

    const signed = await ceremony(offer.encoded);
    clock = new Date(NOW.getTime() + 1_000);
    const challenged = await service.challenge(
      scope,
      first.transcriptId,
      signed.challenge,
    );
    clock = new Date(NOW.getTime() + 2_000);
    const confirmed = await service.sasDecision(
      scope,
      first.transcriptId,
      signed.decision,
    );
    expect(challenged.phase).toBe("challenge");
    expect(confirmed.phase).toBe("candidate_confirmed");
    expect(confirmed.authorization).toBeNull();
    expect(confirmed.drainId).toBeNull();

    const signedApproval = await approval(
      offer.encoded,
      signed.challenge,
      signed.decision,
    );
    await getDb()
      .insert(schema.contentEncryptedVaultJobs)
      .values({
        jobId: "job:replacement:pending",
        vaultId: VAULT_ID,
        ownerEmail: scope.ownerEmail,
        orgId: scope.orgId,
        grantId: "grant:replacement:test",
        recipientEndpointId: OLD_BROKER_ID,
        epoch: 3,
        algorithmId: "anc/v1/test",
        ciphertextByteLength: 32,
        issuedAt: NOW.toISOString(),
        expiresAt: new Date(NOW.getTime() + 60_000).toISOString(),
        jobState: "queued",
        serverReceivedAt: NOW.toISOString(),
      });
    clock = new Date(NOW.getTime() + 3_000);
    const forgedApproval = signedApproval.slice();
    forgedApproval[forgedApproval.length - 1] ^= 1;
    await expect(
      service.approveAndFreeze(scope, first.transcriptId, forgedApproval),
    ).rejects.toMatchObject({ code: "invalid_request" });
    const draining = await service.approveAndFreeze(
      scope,
      first.transcriptId,
      signedApproval,
    );
    expect(draining).toMatchObject({
      phase: "draining",
      drainGeneration: "00000008",
    });
    await expect(
      service.approveAndFreeze(scope, first.transcriptId, signedApproval),
    ).resolves.toEqual(draining);

    await expect(
      service.witnessProgress(scope, first.transcriptId),
    ).rejects.toMatchObject({ code: "conflict" });
    await getDb()
      .update(schema.contentEncryptedVaultJobs)
      .set({ jobState: "completed" })
      .where(
        eq(schema.contentEncryptedVaultJobs.jobId, "job:replacement:pending"),
      );
    await service.witnessProgress(scope, first.transcriptId);
    const progress = await service.status(scope, first.transcriptId);
    expect(progress.drain).toMatchObject({ phase: "witnessed" });
    const offerDecoded = decodeAncV1EndpointEnrollmentOffer(offer.encoded, {
      expectedVaultId: Uint8Array.from(Buffer.from(VAULT_ID, "hex")),
    });
    const attestation = encodeAncV1BrokerDrainAttestation(
      await signAncV1BrokerDrainAttestation(
        {
          suite: "anc/v1",
          vaultId: offerDecoded.vaultId,
          type: "broker_drain_attestation",
          createdAtSeconds: Math.floor(NOW.getTime() / 1000),
          envelopeId: new Uint8Array(16).fill(13),
          issuerEndpointId: Uint8Array.from(Buffer.from(AUTHORIZER_ID, "hex")),
          oldBrokerEndpointId: Uint8Array.from(
            Buffer.from(OLD_BROKER_ID, "hex"),
          ),
          candidateBrokerEndpointId: offerDecoded.endpointId,
          candidateSigningPublicKey: offerDecoded.signingPublicKey,
          candidateKeyAgreementPublicKey: offerDecoded.keyAgreementPublicKey,
          candidateEnrollmentRef: new Uint8Array(16).fill(11),
          baseSequence: controlState().sequence,
          baseHeadHash: Uint8Array.from(
            Buffer.from(controlState().headHash, "hex"),
          ),
          baseEpoch: controlState().epoch,
          drainGeneration: 8,
          drainedJobCount: 1,
          drainDigest: Uint8Array.from(
            Buffer.from(progress.drain!.terminalJobsDigest!, "hex"),
          ),
          outstandingJobCount: 0,
        },
        authorizerSigning.privateKey,
      ),
    );
    clock = new Date(NOW.getTime() + 4_000);
    await expect(
      service.attestDrain(scope, first.transcriptId, attestation),
    ).resolves.toMatchObject({ phase: "drained", drainTotalCount: 1 });
    await expect(
      service.attestDrain(scope, first.transcriptId, attestation),
    ).resolves.toMatchObject({ phase: "drained", drainTotalCount: 1 });
  });

  it("keeps transcript and drain coherent for an exact post-deadline abort", async () => {
    let clock = NOW;
    const service = createOrchestration({ now: () => clock });
    const offer = await candidateOffer();
    const offered = await service.offer(scope, offer.encoded);
    const signed = await ceremony(offer.encoded);
    clock = new Date(NOW.getTime() + 1_000);
    await service.challenge(scope, offered.transcriptId, signed.challenge);
    clock = new Date(NOW.getTime() + 2_000);
    await service.sasDecision(scope, offered.transcriptId, signed.decision);
    const signedApproval = await approval(
      offer.encoded,
      signed.challenge,
      signed.decision,
      Math.floor(NOW.getTime() / 1000) + 5,
    );
    clock = new Date(NOW.getTime() + 3_000);
    await service.approveAndFreeze(scope, offered.transcriptId, signedApproval);
    await expect(
      service.deadline(scope, offered.transcriptId, "abort"),
    ).rejects.toMatchObject({ code: "conflict" });
    clock = new Date(NOW.getTime() + 6_000);
    await expect(
      service.deadline(scope, offered.transcriptId, "abort"),
    ).resolves.toMatchObject({ phase: "aborted" });
    await expect(
      service.deadline(scope, offered.transcriptId, "abort"),
    ).resolves.toMatchObject({ phase: "aborted" });
    await expect(
      service.status(scope, offered.transcriptId),
    ).resolves.toMatchObject({
      transcript: { phase: "aborted" },
      drain: { phase: "aborted", deadlineDecision: "abort" },
    });
  });

  it("rejects stale heads, candidate tombstones, forged signatures, and substitutions", async () => {
    const offer = await candidateOffer();
    const service = createOrchestration({ now: () => NOW });
    loadVerifiedState.mockResolvedValueOnce(
      controlState({ signedAt: "2026-07-18T12:00:00.000Z" }),
    );
    await expect(service.offer(scope, offer.encoded)).rejects.toMatchObject({
      code: "conflict",
    });

    loadVerifiedState.mockResolvedValueOnce(
      controlState({ removedEndpointIds: [CANDIDATE_ID] }),
    );
    await expect(service.offer(scope, offer.encoded)).rejects.toMatchObject({
      code: "conflict",
    });

    loadVerifiedState.mockResolvedValue(controlState());
    const status = await service.offer(scope, offer.encoded);
    const signed = await ceremony(offer.encoded);
    const forged = signed.challenge.slice();
    forged[forged.length - 1] ^= 1;
    await expect(
      service.challenge(scope, status.transcriptId, forged),
    ).rejects.toMatchObject({ code: "invalid_request" });

    const substituted = await candidateOffer();
    substituted.encoded[substituted.encoded.length - 1] ^= 1;
    await expect(
      service.offer(scope, substituted.encoded),
    ).rejects.toMatchObject({ code: "invalid_request" });
  });
});
