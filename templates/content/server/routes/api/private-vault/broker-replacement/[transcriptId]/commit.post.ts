import { defineEventHandler, getRouterParam } from "h3";

import { readPrivateVaultBoundedBody } from "../../../../../lib/private-vault-bounded-body.js";
import {
  hasPrivateVaultBrokerReplacementCsrf,
  hasPrivateVaultBrokerReplacementMediaType,
  preparePrivateVaultBrokerReplacementResponse,
  privateVaultBrokerReplacementEndpointProof,
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
  const proof = privateVaultBrokerReplacementEndpointProof(event);
  if (
    !isPrivateVaultBrokerReplacementTranscriptId(transcriptId) ||
    !hasPrivateVaultBrokerReplacementMediaType(event) ||
    !proof ||
    !Number.isSafeInteger(length) ||
    length > privateVaultBrokerReplacementProtocolLimits.rotationAppendBytes
  ) {
    return privateVaultBrokerReplacementFailure(event, 404);
  }
  const body = await readPrivateVaultBoundedBody(
    event,
    length,
    privateVaultBrokerReplacementProtocolLimits.rotationAppendBytes,
  ).catch(() => null);
  if (!body) return privateVaultBrokerReplacementFailure(event, 400);
  try {
    const result = await withAuthenticatedPrivateVaultBrokerReplacementScope(
      event,
      undefined,
      async (scope) =>
        serializePrivateVaultBrokerReplacementStatus(
          await privateVaultBrokerReplacementOrchestration.commitRotation(
            scope,
            transcriptId,
            body,
            proof,
          ),
        ),
    );
    return result ?? privateVaultBrokerReplacementFailure(event, 404);
  } catch (error) {
    return privateVaultBrokerReplacementErrorResponse(event, error);
  }
});
