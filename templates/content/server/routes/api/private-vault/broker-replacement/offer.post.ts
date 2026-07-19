import { defineEventHandler } from "h3";

import { readPrivateVaultBoundedBody } from "../../../../lib/private-vault-bounded-body.js";
import {
  hasPrivateVaultBrokerReplacementCsrf,
  hasPrivateVaultBrokerReplacementMediaType,
  preparePrivateVaultBrokerReplacementResponse,
  privateVaultBrokerReplacementErrorResponse,
  privateVaultBrokerReplacementFailure,
  privateVaultBrokerReplacementLength,
  serializePrivateVaultBrokerReplacementStatus,
} from "../../../../lib/private-vault-broker-replacement-http.js";
import {
  privateVaultBrokerReplacementOfferVaultId,
  privateVaultBrokerReplacementOrchestration,
  privateVaultBrokerReplacementProtocolLimits,
  withAuthenticatedPrivateVaultBrokerReplacementScope,
} from "../../../../lib/private-vault-broker-replacement-orchestration.js";

export default defineEventHandler(async (event) => {
  preparePrivateVaultBrokerReplacementResponse(event);
  if (!hasPrivateVaultBrokerReplacementCsrf(event)) {
    return privateVaultBrokerReplacementFailure(event, 403);
  }
  const length = privateVaultBrokerReplacementLength(event);
  if (
    !hasPrivateVaultBrokerReplacementMediaType(event) ||
    !Number.isSafeInteger(length) ||
    length > privateVaultBrokerReplacementProtocolLimits.offerBytes
  ) {
    return privateVaultBrokerReplacementFailure(event, 400);
  }
  const offer = await readPrivateVaultBoundedBody(
    event,
    length,
    privateVaultBrokerReplacementProtocolLimits.offerBytes,
  ).catch(() => null);
  if (!offer) return privateVaultBrokerReplacementFailure(event, 400);
  try {
    const result = await withAuthenticatedPrivateVaultBrokerReplacementScope(
      event,
      privateVaultBrokerReplacementOfferVaultId(offer),
      async (scope) =>
        serializePrivateVaultBrokerReplacementStatus(
          await privateVaultBrokerReplacementOrchestration.offer(scope, offer),
        ),
    );
    return result ?? privateVaultBrokerReplacementFailure(event, 404);
  } catch (error) {
    return privateVaultBrokerReplacementErrorResponse(event, error);
  }
});
