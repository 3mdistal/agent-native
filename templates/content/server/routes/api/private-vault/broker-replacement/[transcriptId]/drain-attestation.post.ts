import { defineEventHandler, getRouterParam } from "h3";

import { readPrivateVaultBoundedBody } from "../../../../../lib/private-vault-bounded-body.js";
import {
  hasPrivateVaultBrokerReplacementCsrf,
  hasPrivateVaultBrokerReplacementMediaType,
  preparePrivateVaultBrokerReplacementResponse,
  privateVaultBrokerReplacementErrorResponse,
  privateVaultBrokerReplacementFailure,
  privateVaultBrokerReplacementLength,
  serializePrivateVaultBrokerReplacementStatus,
} from "../../../../../lib/private-vault-broker-replacement-http.js";
import {
  isPrivateVaultBrokerReplacementTranscriptId,
  privateVaultBrokerReplacementOrchestration,
  privateVaultBrokerReplacementProtocolLimits,
  withAuthenticatedPrivateVaultBrokerReplacementScope,
} from "../../../../../lib/private-vault-broker-replacement-orchestration.js";

export default defineEventHandler(async (event) => {
  preparePrivateVaultBrokerReplacementResponse(event);
  if (!hasPrivateVaultBrokerReplacementCsrf(event)) {
    return privateVaultBrokerReplacementFailure(event, 403);
  }
  const transcriptId = getRouterParam(event, "transcriptId") ?? "";
  const length = privateVaultBrokerReplacementLength(event);
  if (
    !isPrivateVaultBrokerReplacementTranscriptId(transcriptId) ||
    !hasPrivateVaultBrokerReplacementMediaType(event) ||
    !Number.isSafeInteger(length) ||
    length > privateVaultBrokerReplacementProtocolLimits.drainAttestationBytes
  ) {
    return privateVaultBrokerReplacementFailure(event, 404);
  }
  const attestation = await readPrivateVaultBoundedBody(
    event,
    length,
    privateVaultBrokerReplacementProtocolLimits.drainAttestationBytes,
  ).catch(() => null);
  if (!attestation) return privateVaultBrokerReplacementFailure(event, 400);
  try {
    const result = await withAuthenticatedPrivateVaultBrokerReplacementScope(
      event,
      undefined,
      async (scope) =>
        serializePrivateVaultBrokerReplacementStatus(
          await privateVaultBrokerReplacementOrchestration.attestDrain(
            scope,
            transcriptId,
            attestation,
          ),
        ),
    );
    return result ?? privateVaultBrokerReplacementFailure(event, 404);
  } catch (error) {
    return privateVaultBrokerReplacementErrorResponse(event, error);
  }
});
