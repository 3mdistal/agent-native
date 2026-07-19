import { describe, expect, it, vi } from "vitest";

import type {
  PrivateVaultBootstrapPageAcceptance,
  PrivateVaultContentBootstrapTransport,
} from "./content-bootstrap-transport.js";
import type { PrivateVaultTrustedEnrollmentOperator } from "./content-enrollment-coordinator.js";
import type { PrivateVaultContentEnrollmentManifestRevisionSource } from "./content-enrollment-manifest-revision-source.js";
import {
  PrivateVaultContentEnrollmentAuthorizer,
  PrivateVaultContentEnrollmentCandidate,
  PrivateVaultContentEnrollmentRoleError,
  PrivateVaultContentEnrollmentRoleRejectedError,
} from "./content-enrollment-roles.js";
import type {
  PrivateVaultContentEnrollmentTransport,
  PrivateVaultEnrollmentPhase,
} from "./content-enrollment-transport.js";

const vaultId = "00".repeat(16);
const offerHash = "11".repeat(32);
const offer = Uint8Array.of(1, 2, 3);
const proof = new Uint8Array(64).fill(4);
const challenge = Uint8Array.of(5, 6);
const sasDecision = Uint8Array.of(7, 8);
const authorization = Uint8Array.of(9, 10);
const manifestRevision = Uint8Array.of(11, 12);
const manifestCheckpoint = Uint8Array.of(13, 14);
const manifestAuthorization = Uint8Array.of(15, 16);

function hostedTranscript() {
  let phase: PrivateVaultEnrollmentPhase = "offer";
  let currentChallenge: Uint8Array | null = null;
  let currentDecision: Uint8Array | null = null;
  let currentAuthorization: Uint8Array | null = null;
  let currentManifestCheckpoint: Uint8Array | null = null;
  let currentManifestAuthorization: Uint8Array | null = null;
  const status = () => ({
    phase,
    offer: offer.slice(),
    challenge: currentChallenge?.slice() ?? null,
    sasDecision: currentDecision?.slice() ?? null,
    authorization: currentAuthorization?.slice() ?? null,
    manifestCheckpoint: currentManifestCheckpoint?.slice() ?? null,
    manifestAuthorization: currentManifestAuthorization?.slice() ?? null,
    controlEntryId: phase === "committed" ? "22".repeat(16) : null,
    controlEntryHash: phase === "committed" ? "33".repeat(32) : null,
    expiresAt: "2026-07-19T00:00:00.000Z",
  });
  return {
    transport: {
      publishOffer: vi.fn(async () => status()),
      readStatus: vi.fn(async () => status()),
      publishChallenge: vi.fn(async (_hash, _offer, value: Uint8Array) => {
        currentChallenge = value.slice();
        phase = "challenge";
        return status();
      }),
      publishSasDecision: vi.fn(async (_hash, _offer, value: Uint8Array) => {
        currentDecision = value.slice();
        phase = "confirmed";
        return status();
      }),
      publishAuthorization: vi.fn(
        async (
          _hash,
          _offer,
          value: Uint8Array,
          checkpoint: Uint8Array,
          manifestBinding: Uint8Array,
        ) => {
          currentAuthorization = value.slice();
          currentManifestCheckpoint = checkpoint.slice();
          currentManifestAuthorization = manifestBinding.slice();
          phase = "committed";
          return status();
        },
      ),
    } as unknown as PrivateVaultContentEnrollmentTransport,
    reject() {
      currentDecision = sasDecision.slice();
      phase = "rejected";
    },
    removeManifestEvidence() {
      currentManifestCheckpoint = null;
      currentManifestAuthorization = null;
    },
  };
}

function candidateNative(): PrivateVaultTrustedEnrollmentOperator & {
  acceptEnrollmentBootstrapPage(
    vaultId: string,
    encoded: Uint8Array,
  ): Promise<PrivateVaultBootstrapPageAcceptance>;
} {
  return {
    prepareBrokerEnrollment: vi.fn(
      async () =>
        ({
          version: 1,
          suite: "anc/v1",
          operation: "prepare_enroll",
          state: "offered",
          vaultId,
          candidateEndpointId: "44".repeat(16),
          offerHash,
          offer,
          candidateKeyProof: proof,
        }) as const,
    ),
    confirmBrokerEnrollment: vi.fn(
      async () =>
        ({
          version: 1,
          suite: "anc/v1",
          operation: "confirm_enroll",
          state: "confirmed",
          sasDecision,
        }) as const,
    ),
    activateBrokerEnrollment: vi.fn(
      async () =>
        ({
          version: 1,
          suite: "anc/v1",
          operation: "activate_enroll",
          state: "active",
          vaultId,
          custodyGeneration: 3,
          activeEpoch: 1,
          sequence: 1,
          headHash: "55".repeat(32),
        }) as const,
    ),
    buildBrokerEnrollmentChallenge: vi.fn(async () => {
      throw new Error("candidate must not authorize");
    }),
    buildBrokerEnrollmentAuthorization: vi.fn(async () => {
      throw new Error("candidate must not authorize");
    }),
    acceptEnrollmentBootstrapPage: vi.fn(async () => ({
      vaultId,
      throughSequence: 0,
      head: { sequence: 0, hash: "66".repeat(32) },
      complete: true,
    })),
  };
}

function bootstrapTransport(): PrivateVaultContentBootstrapTransport {
  return {
    transfer: vi.fn(async (consumer) =>
      consumer.acceptPage(Uint8Array.of(0xa1)),
    ),
  } as unknown as PrivateVaultContentBootstrapTransport;
}

function manifestSource(input?: {
  readonly rejectVerification?: boolean;
}): PrivateVaultContentEnrollmentManifestRevisionSource {
  return {
    readTrustedCurrentRevision: vi.fn(async () => manifestRevision.slice()),
    verifyUniqueHostedRevision: vi.fn(async () => {
      if (input?.rejectVerification) throw new Error();
      return {
        version: 3,
        suite: "anc/v1",
        operation: "verify_manifest",
        state: "verified",
        vaultId,
        checkpointDigest: new Uint8Array(32).fill(17),
      } as const;
    }),
  } as unknown as PrivateVaultContentEnrollmentManifestRevisionSource;
}

describe("Private Vault cross-device enrollment roles", () => {
  it("alternates two Macs through public hosted state without merging custody roles", async () => {
    const shared = hostedTranscript();
    const candidateOperator = candidateNative();
    let authorizerManifestSeen: Uint8Array | null = null;
    const authorizerOperator = {
      buildBrokerEnrollmentChallenge: vi.fn(async () => ({
        encoded: challenge,
      })),
      buildBrokerEnrollmentAuthorization: vi.fn(async (input) => {
        authorizerManifestSeen = input.manifestRevision?.slice() ?? null;
        return {
          encoded: authorization,
          manifestCheckpoint,
          manifestAuthorization,
        };
      }),
    };
    const manifest = manifestSource();
    const candidate = new PrivateVaultContentEnrollmentCandidate({
      native: candidateOperator,
      hosted: shared.transport,
      bootstrap: bootstrapTransport(),
      manifest,
    });
    const authorizer = new PrivateVaultContentEnrollmentAuthorizer({
      native: authorizerOperator,
      hosted: shared.transport,
      manifest,
    });

    const begun = await candidate.begin(vaultId);
    expect(begun.state).toBe("awaiting-authorizer");
    if (begun.state !== "awaiting-authorizer") throw new Error();
    const invitation = begun.invitation;
    await expect(authorizer.advance(invitation)).resolves.toEqual({
      state: "awaiting-candidate",
    });
    await expect(candidate.advance(invitation)).resolves.toEqual({
      state: "awaiting-authorization",
    });
    await expect(authorizer.advance(invitation)).resolves.toEqual({
      state: "committed",
    });
    await expect(candidate.advance(invitation)).resolves.toMatchObject({
      state: "active",
      result: { custodyGeneration: 3 },
    });

    expect(
      candidateOperator.buildBrokerEnrollmentChallenge,
    ).not.toHaveBeenCalled();
    expect(
      candidateOperator.buildBrokerEnrollmentAuthorization,
    ).not.toHaveBeenCalled();
    expect(
      authorizerOperator.buildBrokerEnrollmentChallenge,
    ).toHaveBeenCalledWith({ vaultId, offer, candidateKeyProof: proof });
    expect(
      authorizerOperator.buildBrokerEnrollmentAuthorization,
    ).toHaveBeenCalledWith({
      vaultId,
      offer,
      challenge,
      sasDecision,
      manifestRevision: expect.any(Uint8Array),
    });
    expect(authorizerManifestSeen).toEqual(manifestRevision);
    expect(manifest.verifyUniqueHostedRevision).toHaveBeenCalledWith({
      vaultId,
      challenge,
      authorization,
      manifestCheckpoint,
      manifestAuthorization,
    });
    expect(
      vi.mocked(manifest.verifyUniqueHostedRevision).mock
        .invocationCallOrder[0],
    ).toBeLessThan(
      vi.mocked(candidateOperator.activateBrokerEnrollment).mock
        .invocationCallOrder[0]!,
    );
    expect(candidateOperator.confirmBrokerEnrollment).toHaveBeenCalledWith(
      vaultId,
      challenge,
    );
    expect(
      candidateOperator.acceptEnrollmentBootstrapPage,
    ).toHaveBeenCalledOnce();
    expect(
      vi.mocked(candidateOperator.acceptEnrollmentBootstrapPage).mock
        .invocationCallOrder[0],
    ).toBeLessThan(
      vi.mocked(candidateOperator.confirmBrokerEnrollment).mock
        .invocationCallOrder[0]!,
    );
  });

  it("treats a hosted mismatch as terminal on both devices", async () => {
    const shared = hostedTranscript();
    shared.reject();
    const begun = await new PrivateVaultContentEnrollmentCandidate({
      native: candidateNative(),
      hosted: shared.transport,
      bootstrap: bootstrapTransport(),
      manifest: manifestSource(),
    }).begin(vaultId);
    if (begun.state !== "awaiting-authorizer") throw new Error();
    const authorizer = new PrivateVaultContentEnrollmentAuthorizer({
      native: {
        buildBrokerEnrollmentChallenge: vi.fn(),
        buildBrokerEnrollmentAuthorization: vi.fn(),
      },
      hosted: shared.transport,
      manifest: manifestSource(),
    });
    await expect(authorizer.advance(begun.invitation)).rejects.toBeInstanceOf(
      PrivateVaultContentEnrollmentRoleRejectedError,
    );
  });

  it("cannot activate a committed enrollment unless native verifies the hosted manifest", async () => {
    const shared = hostedTranscript();
    const native = candidateNative();
    const candidate = new PrivateVaultContentEnrollmentCandidate({
      native,
      hosted: shared.transport,
      bootstrap: bootstrapTransport(),
      manifest: manifestSource({ rejectVerification: true }),
    });
    const authorizer = new PrivateVaultContentEnrollmentAuthorizer({
      native: {
        buildBrokerEnrollmentChallenge: vi.fn(async () => ({
          encoded: challenge,
        })),
        buildBrokerEnrollmentAuthorization: vi.fn(async () => ({
          encoded: authorization,
          manifestCheckpoint,
          manifestAuthorization,
        })),
      },
      hosted: shared.transport,
      manifest: manifestSource(),
    });
    const begun = await candidate.begin(vaultId);
    if (begun.state !== "awaiting-authorizer") throw new Error();

    await authorizer.advance(begun.invitation);
    await candidate.advance(begun.invitation);
    await authorizer.advance(begun.invitation);
    await expect(candidate.advance(begun.invitation)).rejects.toBeInstanceOf(
      PrivateVaultContentEnrollmentRoleError,
    );
    expect(native.activateBrokerEnrollment).not.toHaveBeenCalled();
  });

  it("fails closed when a committed status omits manifest evidence", async () => {
    const shared = hostedTranscript();
    const native = candidateNative();
    const manifest = manifestSource();
    const candidate = new PrivateVaultContentEnrollmentCandidate({
      native,
      hosted: shared.transport,
      bootstrap: bootstrapTransport(),
      manifest,
    });
    const authorizer = new PrivateVaultContentEnrollmentAuthorizer({
      native: {
        buildBrokerEnrollmentChallenge: vi.fn(async () => ({
          encoded: challenge,
        })),
        buildBrokerEnrollmentAuthorization: vi.fn(async () => ({
          encoded: authorization,
          manifestCheckpoint,
          manifestAuthorization,
        })),
      },
      hosted: shared.transport,
      manifest: manifestSource(),
    });
    const begun = await candidate.begin(vaultId);
    if (begun.state !== "awaiting-authorizer") throw new Error();
    await authorizer.advance(begun.invitation);
    await candidate.advance(begun.invitation);
    await authorizer.advance(begun.invitation);
    shared.removeManifestEvidence();

    await expect(candidate.advance(begun.invitation)).rejects.toBeInstanceOf(
      PrivateVaultContentEnrollmentRoleError,
    );
    expect(manifest.verifyUniqueHostedRevision).not.toHaveBeenCalled();
    expect(native.activateBrokerEnrollment).not.toHaveBeenCalled();
  });
});
