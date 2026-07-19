import type { PrivateVaultContentBootstrapTransport } from "./content-bootstrap-transport.js";
import type { PrivateVaultBootstrapPageAcceptance } from "./content-bootstrap-transport.js";
import type {
  PrivateVaultEnrollmentAuthorizerResult,
  PrivateVaultTrustedEnrollmentOperator,
} from "./content-enrollment-coordinator.js";
import {
  decodePrivateVaultContentEnrollmentInvitation,
  encodePrivateVaultContentEnrollmentInvitation,
} from "./content-enrollment-invitation.js";
import type { PrivateVaultContentEnrollmentManifestRevisionSource } from "./content-enrollment-manifest-revision-source.js";
import type {
  PrivateVaultContentEnrollmentTransport,
  PrivateVaultHostedEnrollmentStatus,
} from "./content-enrollment-transport.js";
import type {
  NativeActivateEnrollmentResult,
  PrivateVaultNativeServiceClient,
} from "./native-service-client.js";

type PrivateVaultCandidateEnrollmentOperator =
  PrivateVaultTrustedEnrollmentOperator & {
    acceptEnrollmentBootstrapPage(
      vaultId: string,
      encoded: Uint8Array,
    ): Promise<PrivateVaultBootstrapPageAcceptance>;
  };

type PrivateVaultAuthorizerEnrollmentOperator = Pick<
  PrivateVaultNativeServiceClient,
  "buildBrokerEnrollmentChallenge" | "buildBrokerEnrollmentAuthorization"
>;

export type PrivateVaultCandidateEnrollmentProgress =
  | Readonly<{ state: "awaiting-authorizer"; invitation: Uint8Array }>
  | Readonly<{ state: "awaiting-authorization" }>
  | Readonly<{ state: "active"; result: NativeActivateEnrollmentResult }>;

export type PrivateVaultAuthorizerEnrollmentProgress = Readonly<{
  state: "awaiting-candidate" | "committed";
}>;

export class PrivateVaultContentEnrollmentRoleError extends Error {
  constructor() {
    super("Private Vault cross-device enrollment could not be completed");
    this.name = "PrivateVaultContentEnrollmentRoleError";
  }
}

export class PrivateVaultContentEnrollmentRoleRejectedError extends Error {
  constructor() {
    super("Private Vault cross-device enrollment was permanently rejected");
    this.name = "PrivateVaultContentEnrollmentRoleRejectedError";
  }
}

function same(left: Uint8Array, right: Uint8Array): boolean {
  return (
    left.byteLength === right.byteLength &&
    left.every((value, index) => value === right[index])
  );
}

function statusMatchesOffer(
  status: PrivateVaultHostedEnrollmentStatus,
  offer: Uint8Array,
): boolean {
  return same(status.offer, offer);
}

abstract class SerializedEnrollmentRole {
  #tail: Promise<void> = Promise.resolve();

  protected enqueue<Result>(operation: () => Promise<Result>): Promise<Result> {
    const result = this.#tail.then(operation, operation);
    this.#tail = result.then(
      () => undefined,
      () => undefined,
    );
    return result;
  }
}

/** Runs only the new broker candidate half on the Mac being enrolled. */
export class PrivateVaultContentEnrollmentCandidate extends SerializedEnrollmentRole {
  readonly #native: PrivateVaultCandidateEnrollmentOperator;
  readonly #hosted: PrivateVaultContentEnrollmentTransport;
  readonly #bootstrap: PrivateVaultContentBootstrapTransport;
  readonly #manifest: PrivateVaultContentEnrollmentManifestRevisionSource;

  constructor(input: {
    readonly native: PrivateVaultCandidateEnrollmentOperator;
    readonly hosted: PrivateVaultContentEnrollmentTransport;
    readonly bootstrap: PrivateVaultContentBootstrapTransport;
    readonly manifest: PrivateVaultContentEnrollmentManifestRevisionSource;
  }) {
    super();
    this.#native = input.native;
    this.#hosted = input.hosted;
    this.#bootstrap = input.bootstrap;
    this.#manifest = input.manifest;
  }

  begin(vaultId: string): Promise<PrivateVaultCandidateEnrollmentProgress> {
    return this.enqueue(async () => {
      try {
        const prepared = await this.#native.prepareBrokerEnrollment(vaultId);
        const invitation = encodePrivateVaultContentEnrollmentInvitation({
          vaultId: prepared.vaultId,
          offerHash: prepared.offerHash,
          offer: prepared.offer,
          candidateKeyProof: prepared.candidateKeyProof,
        });
        const status = await this.#hosted.publishOffer(
          prepared.offerHash,
          prepared.offer.slice(),
        );
        if (!statusMatchesOffer(status, prepared.offer)) throw new Error();
        return Object.freeze({
          state: "awaiting-authorizer",
          invitation: invitation.slice(),
        });
      } catch {
        throw new PrivateVaultContentEnrollmentRoleError();
      }
    });
  }

  advance(
    encodedInvitation: Uint8Array,
  ): Promise<PrivateVaultCandidateEnrollmentProgress> {
    return this.enqueue(async () => {
      try {
        const invitation =
          decodePrivateVaultContentEnrollmentInvitation(encodedInvitation);
        let status = await this.#hosted.readStatus(
          invitation.offerHash,
          invitation.offer.slice(),
        );
        if (!statusMatchesOffer(status, invitation.offer)) throw new Error();
        if (status.phase === "rejected") {
          throw new PrivateVaultContentEnrollmentRoleRejectedError();
        }
        if (status.phase === "offer") {
          return Object.freeze({
            state: "awaiting-authorizer",
            invitation: encodedInvitation.slice(),
          });
        }
        if (!status.challenge) throw new Error();
        if (status.phase === "challenge") {
          const bootstrapped = await this.#bootstrap.transfer({
            acceptPage: (encoded) =>
              this.#native.acceptEnrollmentBootstrapPage(
                invitation.vaultId,
                encoded,
              ),
          });
          if (bootstrapped.vaultId !== invitation.vaultId) throw new Error();
          const decision = await this.#native.confirmBrokerEnrollment(
            invitation.vaultId,
            status.challenge.slice(),
          );
          status = await this.#hosted.publishSasDecision(
            invitation.offerHash,
            invitation.offer.slice(),
            decision.sasDecision.slice(),
          );
          if (
            !statusMatchesOffer(status, invitation.offer) ||
            !status.sasDecision ||
            !same(status.sasDecision, decision.sasDecision)
          ) {
            throw new Error();
          }
          if (decision.state === "mismatch") {
            if (status.phase !== "rejected") throw new Error();
            throw new PrivateVaultContentEnrollmentRoleRejectedError();
          }
          if (status.phase !== "confirmed" && status.phase !== "committed") {
            throw new Error();
          }
        }
        if (status.phase === "confirmed") {
          return Object.freeze({ state: "awaiting-authorization" });
        }
        if (
          status.phase !== "committed" ||
          !status.challenge ||
          !status.authorization ||
          !status.manifestCheckpoint ||
          !status.manifestAuthorization
        ) {
          throw new Error();
        }
        await this.#manifest.verifyUniqueHostedRevision({
          vaultId: invitation.vaultId,
          challenge: status.challenge.slice(),
          authorization: status.authorization.slice(),
          manifestCheckpoint: status.manifestCheckpoint.slice(),
          manifestAuthorization: status.manifestAuthorization.slice(),
        });
        const result = await this.#native.activateBrokerEnrollment(
          invitation.vaultId,
          status.challenge.slice(),
          status.authorization.slice(),
        );
        return Object.freeze({ state: "active", result });
      } catch (error) {
        if (error instanceof PrivateVaultContentEnrollmentRoleRejectedError) {
          throw error;
        }
        throw new PrivateVaultContentEnrollmentRoleError();
      }
    });
  }
}

/** Runs only the existing trusted endpoint half on a different enrolled Mac. */
export class PrivateVaultContentEnrollmentAuthorizer extends SerializedEnrollmentRole {
  readonly #native: PrivateVaultAuthorizerEnrollmentOperator;
  readonly #hosted: PrivateVaultContentEnrollmentTransport;
  readonly #manifest: PrivateVaultContentEnrollmentManifestRevisionSource;

  constructor(input: {
    readonly native: PrivateVaultAuthorizerEnrollmentOperator;
    readonly hosted: PrivateVaultContentEnrollmentTransport;
    readonly manifest: PrivateVaultContentEnrollmentManifestRevisionSource;
  }) {
    super();
    this.#native = input.native;
    this.#hosted = input.hosted;
    this.#manifest = input.manifest;
  }

  advance(
    encodedInvitation: Uint8Array,
  ): Promise<PrivateVaultAuthorizerEnrollmentProgress> {
    return this.enqueue(async () => {
      try {
        const invitation =
          decodePrivateVaultContentEnrollmentInvitation(encodedInvitation);
        let status = await this.#hosted.readStatus(
          invitation.offerHash,
          invitation.offer.slice(),
        );
        if (!statusMatchesOffer(status, invitation.offer)) throw new Error();
        if (status.phase === "rejected") {
          throw new PrivateVaultContentEnrollmentRoleRejectedError();
        }
        if (status.phase === "offer") {
          const challenge = await this.#native.buildBrokerEnrollmentChallenge({
            vaultId: invitation.vaultId,
            offer: invitation.offer.slice(),
            candidateKeyProof: invitation.candidateKeyProof.slice(),
          });
          status = await this.#publishChallenge(invitation, challenge);
        }
        if (status.phase === "challenge") {
          return Object.freeze({ state: "awaiting-candidate" });
        }
        if (status.phase === "confirmed") {
          if (!status.challenge || !status.sasDecision) throw new Error();
          const manifestRevision =
            await this.#manifest.readTrustedCurrentRevision(invitation.vaultId);
          let authorization;
          try {
            authorization =
              await this.#native.buildBrokerEnrollmentAuthorization({
                vaultId: invitation.vaultId,
                offer: invitation.offer.slice(),
                challenge: status.challenge.slice(),
                sasDecision: status.sasDecision.slice(),
                manifestRevision,
              });
          } finally {
            manifestRevision.fill(0);
          }
          if (
            !authorization.manifestCheckpoint ||
            !authorization.manifestAuthorization
          ) {
            throw new Error();
          }
          status = await this.#hosted.publishAuthorization(
            invitation.offerHash,
            invitation.offer.slice(),
            authorization.encoded.slice(),
            authorization.manifestCheckpoint.slice(),
            authorization.manifestAuthorization.slice(),
          );
          if (
            status.phase !== "committed" ||
            !status.authorization ||
            !status.manifestCheckpoint ||
            !status.manifestAuthorization ||
            !same(status.authorization, authorization.encoded) ||
            !same(
              status.manifestCheckpoint,
              authorization.manifestCheckpoint,
            ) ||
            !same(
              status.manifestAuthorization,
              authorization.manifestAuthorization,
            )
          ) {
            throw new Error();
          }
        }
        if (status.phase !== "committed") throw new Error();
        return Object.freeze({ state: "committed" });
      } catch (error) {
        if (error instanceof PrivateVaultContentEnrollmentRoleRejectedError) {
          throw error;
        }
        throw new PrivateVaultContentEnrollmentRoleError();
      }
    });
  }

  async #publishChallenge(
    invitation: ReturnType<
      typeof decodePrivateVaultContentEnrollmentInvitation
    >,
    challenge: PrivateVaultEnrollmentAuthorizerResult,
  ): Promise<PrivateVaultHostedEnrollmentStatus> {
    const status = await this.#hosted.publishChallenge(
      invitation.offerHash,
      invitation.offer.slice(),
      challenge.encoded.slice(),
    );
    if (
      status.phase !== "challenge" ||
      !status.challenge ||
      !same(status.offer, invitation.offer) ||
      !same(status.challenge, challenge.encoded)
    ) {
      throw new Error();
    }
    return status;
  }
}
