import type { PrivateVaultContentEnrollmentManifestRevisionSource } from "./content-enrollment-manifest-revision-source.js";
import type {
  PrivateVaultContentEnrollmentTransport,
  PrivateVaultHostedEnrollmentStatus,
} from "./content-enrollment-transport.js";
import type {
  NativeActivateEnrollmentResult,
  NativeConfirmEnrollmentResult,
  NativePrepareEnrollmentResult,
} from "./native-service-client.js";

export interface PrivateVaultEnrollmentAuthorizerResult {
  readonly encoded: Uint8Array;
  readonly manifestCheckpoint?: Uint8Array;
  readonly manifestAuthorization?: Uint8Array;
}

export interface PrivateVaultTrustedEnrollmentOperator {
  prepareBrokerEnrollment(
    vaultId: string,
  ): Promise<NativePrepareEnrollmentResult>;
  buildBrokerEnrollmentChallenge(input: {
    readonly vaultId: string;
    readonly offer: Uint8Array;
    readonly candidateKeyProof: Uint8Array;
  }): Promise<PrivateVaultEnrollmentAuthorizerResult>;
  confirmBrokerEnrollment(
    vaultId: string,
    challenge: Uint8Array,
  ): Promise<NativeConfirmEnrollmentResult>;
  buildBrokerEnrollmentAuthorization(input: {
    readonly vaultId: string;
    readonly offer: Uint8Array;
    readonly challenge: Uint8Array;
    readonly sasDecision: Uint8Array;
    readonly manifestRevision?: Uint8Array;
  }): Promise<PrivateVaultEnrollmentAuthorizerResult>;
  activateBrokerEnrollment(
    vaultId: string,
    challenge: Uint8Array,
    authorization: Uint8Array,
  ): Promise<NativeActivateEnrollmentResult>;
}

export class PrivateVaultContentEnrollmentCoordinatorError extends Error {
  constructor() {
    super("Private Vault broker enrollment could not be completed");
    this.name = "PrivateVaultContentEnrollmentCoordinatorError";
  }
}

export class PrivateVaultContentEnrollmentRejectedError extends Error {
  constructor() {
    super("Private Vault broker enrollment was rejected at SAS comparison");
    this.name = "PrivateVaultContentEnrollmentRejectedError";
  }
}

function same(left: Uint8Array, right: Uint8Array): boolean {
  return (
    left.byteLength === right.byteLength &&
    left.every((value, index) => value === right[index])
  );
}

/**
 * Drives one same-device broker enrollment using only public ceremony bytes.
 * Candidate and endpoint secrets remain in separate native custody domains;
 * hosted Content stores the byte-stable transcript and committed control edge.
 */
export class PrivateVaultContentEnrollmentCoordinator {
  readonly #native: PrivateVaultTrustedEnrollmentOperator;
  readonly #hosted: PrivateVaultContentEnrollmentTransport;
  readonly #manifest: Pick<
    PrivateVaultContentEnrollmentManifestRevisionSource,
    "readTrustedCurrentRevision"
  >;
  #tail: Promise<void> = Promise.resolve();

  constructor(input: {
    readonly native: PrivateVaultTrustedEnrollmentOperator;
    readonly hosted: PrivateVaultContentEnrollmentTransport;
    readonly manifest: Pick<
      PrivateVaultContentEnrollmentManifestRevisionSource,
      "readTrustedCurrentRevision"
    >;
  }) {
    this.#native = input.native;
    this.#hosted = input.hosted;
    this.#manifest = input.manifest;
  }

  enroll(vaultId: string): Promise<NativeActivateEnrollmentResult> {
    return this.#enqueue(async () => {
      try {
        const prepared = await this.#native.prepareBrokerEnrollment(vaultId);
        let status = await this.#hosted.publishOffer(
          prepared.offerHash,
          prepared.offer.slice(),
        );
        status = await this.#ensureChallenge(prepared, status);
        if (!status.challenge) throw new Error();
        const challenge = status.challenge.slice();
        if (status.phase !== "committed") {
          const decision = await this.#native.confirmBrokerEnrollment(
            vaultId,
            challenge.slice(),
          );
          status = await this.#hosted.publishSasDecision(
            prepared.offerHash,
            prepared.offer.slice(),
            decision.sasDecision.slice(),
          );
          if (decision.state === "mismatch") {
            if (
              status.phase !== "rejected" ||
              !status.sasDecision ||
              !same(status.sasDecision, decision.sasDecision)
            ) {
              throw new Error();
            }
            throw new PrivateVaultContentEnrollmentRejectedError();
          }
          if (
            (status.phase !== "confirmed" && status.phase !== "committed") ||
            !status.sasDecision ||
            !same(status.sasDecision, decision.sasDecision)
          ) {
            throw new Error();
          }
          const manifestRevision =
            await this.#manifest.readTrustedCurrentRevision(vaultId);
          let built: PrivateVaultEnrollmentAuthorizerResult;
          try {
            built = await this.#native.buildBrokerEnrollmentAuthorization({
              vaultId,
              offer: prepared.offer.slice(),
              challenge: challenge.slice(),
              sasDecision: status.sasDecision.slice(),
              manifestRevision,
            });
          } finally {
            manifestRevision.fill(0);
          }
          if (!built.manifestCheckpoint || !built.manifestAuthorization) {
            throw new Error();
          }
          status = await this.#hosted.publishAuthorization(
            prepared.offerHash,
            prepared.offer.slice(),
            built.encoded.slice(),
            built.manifestCheckpoint.slice(),
            built.manifestAuthorization.slice(),
          );
          if (
            status.phase !== "committed" ||
            !status.authorization ||
            !status.manifestCheckpoint ||
            !status.manifestAuthorization ||
            !same(status.authorization, built.encoded) ||
            !same(status.manifestCheckpoint, built.manifestCheckpoint) ||
            !same(status.manifestAuthorization, built.manifestAuthorization)
          ) {
            throw new Error();
          }
        }
        if (status.phase !== "committed" || !status.authorization) {
          throw new Error();
        }
        return await this.#native.activateBrokerEnrollment(
          vaultId,
          challenge,
          status.authorization.slice(),
        );
      } catch (error) {
        if (error instanceof PrivateVaultContentEnrollmentRejectedError) {
          throw error;
        }
        throw new PrivateVaultContentEnrollmentCoordinatorError();
      }
    });
  }

  async #ensureChallenge(
    prepared: NativePrepareEnrollmentResult,
    status: PrivateVaultHostedEnrollmentStatus,
  ): Promise<PrivateVaultHostedEnrollmentStatus> {
    if (status.phase !== "offer") return status;
    const built = await this.#native.buildBrokerEnrollmentChallenge({
      vaultId: prepared.vaultId,
      offer: prepared.offer.slice(),
      candidateKeyProof: prepared.candidateKeyProof.slice(),
    });
    const challenged = await this.#hosted.publishChallenge(
      prepared.offerHash,
      prepared.offer.slice(),
      built.encoded.slice(),
    );
    if (
      challenged.phase !== "challenge" ||
      !challenged.challenge ||
      !same(challenged.challenge, built.encoded)
    ) {
      throw new Error();
    }
    return challenged;
  }

  #enqueue<Result>(operation: () => Promise<Result>): Promise<Result> {
    const result = this.#tail.then(operation, operation);
    this.#tail = result.then(
      () => undefined,
      () => undefined,
    );
    return result;
  }
}
