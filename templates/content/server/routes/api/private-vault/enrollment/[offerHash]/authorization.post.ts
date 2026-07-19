import { defineEventHandler, getRouterParam } from "h3";

import { readPrivateVaultBoundedBody } from "../../../../../lib/private-vault-bounded-body.js";
import {
  hasPrivateVaultEnrollmentCsrf,
  hasPrivateVaultEnrollmentMediaType,
  preparePrivateVaultEnrollmentResponse,
  privateVaultEnrollmentErrorResponse,
  privateVaultEnrollmentFailure,
  privateVaultEnrollmentLength,
  serializePrivateVaultEnrollmentStatus,
} from "../../../../../lib/private-vault-enrollment-http.js";
import {
  commitPrivateVaultEnrollmentAuthorization,
  privateVaultEnrollmentLimits,
} from "../../../../../lib/private-vault-enrollment.js";
import { resolveAuthenticatedPrivateVaultBootstrapScope } from "../../../../../lib/private-vault-genesis-account-scope.js";

export default defineEventHandler(async (event) => {
  preparePrivateVaultEnrollmentResponse(event);
  if (!hasPrivateVaultEnrollmentCsrf(event)) {
    return privateVaultEnrollmentFailure(event, 403);
  }
  const offerHash = getRouterParam(event, "offerHash") ?? "";
  const length = privateVaultEnrollmentLength(event);
  if (
    !/^[0-9a-f]{64}$/.test(offerHash) ||
    !hasPrivateVaultEnrollmentMediaType(event) ||
    !Number.isSafeInteger(length) ||
    length > privateVaultEnrollmentLimits.authorizationBundleBytes
  ) {
    return privateVaultEnrollmentFailure(event, 404);
  }
  const authorizationBundle = await readPrivateVaultBoundedBody(
    event,
    length,
    privateVaultEnrollmentLimits.authorizationBundleBytes,
  ).catch(() => null);
  const scope = await resolveAuthenticatedPrivateVaultBootstrapScope(event);
  if (!authorizationBundle || !scope) {
    return privateVaultEnrollmentFailure(event, 404);
  }
  try {
    return serializePrivateVaultEnrollmentStatus(
      await commitPrivateVaultEnrollmentAuthorization({
        scope,
        offerHash,
        authorizationBundle,
      }),
    );
  } catch (error) {
    return privateVaultEnrollmentErrorResponse(event, error);
  }
});
