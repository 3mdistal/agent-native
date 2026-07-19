import { PrivateVaultContentBootstrapTransport } from "./content-bootstrap-transport.js";
import { PrivateVaultContentEnrollmentCoordinator } from "./content-enrollment-coordinator.js";
import { PrivateVaultContentEnrollmentManifestRevisionSource } from "./content-enrollment-manifest-revision-source.js";
import {
  PrivateVaultContentEnrollmentAuthorizer,
  PrivateVaultContentEnrollmentCandidate,
} from "./content-enrollment-roles.js";
import { PrivateVaultContentEnrollmentTransport } from "./content-enrollment-transport.js";
import { PrivateVaultContentObjectTransport } from "./content-object-transport.js";
import { createEncryptedContentIndexStore } from "./encrypted-content-index-store.js";
import {
  createPrivateVaultNativeServiceClient,
  type PrivateVaultNativeServiceClient,
} from "./native-service-client.js";

interface ContentEnrollmentSession {
  fetch(input: string, init: RequestInit): Promise<Response>;
}

interface EnrollmentRoles {
  readonly candidate: PrivateVaultContentEnrollmentCandidate;
  readonly authorizer: PrivateVaultContentEnrollmentAuthorizer;
}

/** Process-local composition root for the two cross-device enrollment roles. */
export class PrivateVaultContentEnrollmentRuntime {
  readonly #native: PrivateVaultNativeServiceClient;
  readonly #roles = new WeakMap<
    ContentEnrollmentSession,
    Map<string, EnrollmentRoles>
  >();
  readonly #coordinators = new WeakMap<
    ContentEnrollmentSession,
    Map<string, PrivateVaultContentEnrollmentCoordinator>
  >();

  constructor(native: PrivateVaultNativeServiceClient) {
    this.#native = native;
  }

  roles(input: {
    readonly session: ContentEnrollmentSession;
    readonly origin: string;
  }): EnrollmentRoles {
    let byOrigin = this.#roles.get(input.session);
    if (!byOrigin) {
      byOrigin = new Map();
      this.#roles.set(input.session, byOrigin);
    }
    const existing = byOrigin.get(input.origin);
    if (existing) return existing;
    const hosted = new PrivateVaultContentEnrollmentTransport(input);
    const manifest = new PrivateVaultContentEnrollmentManifestRevisionSource({
      index: createEncryptedContentIndexStore(),
      transport: new PrivateVaultContentObjectTransport({
        ...input,
        native: this.#native,
      }),
      native: this.#native,
    });
    const roles = Object.freeze({
      candidate: new PrivateVaultContentEnrollmentCandidate({
        native: this.#native,
        hosted,
        bootstrap: new PrivateVaultContentBootstrapTransport(input),
        manifest,
      }),
      authorizer: new PrivateVaultContentEnrollmentAuthorizer({
        native: this.#native,
        hosted,
        manifest,
      }),
    });
    byOrigin.set(input.origin, roles);
    return roles;
  }

  coordinator(input: {
    readonly session: ContentEnrollmentSession;
    readonly origin: string;
  }): PrivateVaultContentEnrollmentCoordinator {
    let byOrigin = this.#coordinators.get(input.session);
    if (!byOrigin) {
      byOrigin = new Map();
      this.#coordinators.set(input.session, byOrigin);
    }
    const existing = byOrigin.get(input.origin);
    if (existing) return existing;
    const objectTransport = new PrivateVaultContentObjectTransport({
      ...input,
      native: this.#native,
    });
    const manifest = new PrivateVaultContentEnrollmentManifestRevisionSource({
      index: createEncryptedContentIndexStore(),
      transport: objectTransport,
      native: this.#native,
    });
    const coordinator = new PrivateVaultContentEnrollmentCoordinator({
      native: this.#native,
      hosted: new PrivateVaultContentEnrollmentTransport(input),
      manifest,
    });
    byOrigin.set(input.origin, coordinator);
    return coordinator;
  }
}

export function createPrivateVaultContentEnrollmentRuntime(): PrivateVaultContentEnrollmentRuntime {
  return new PrivateVaultContentEnrollmentRuntime(
    createPrivateVaultNativeServiceClient(),
  );
}
