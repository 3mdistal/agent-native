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
    length > privateVaultBrokerReplacementProtocolLimits.sasDecisionBytes
  ) {
    return privateVaultBrokerReplacementFailure(event, 404);
  }
  const decision = await readPrivateVaultBoundedBody(
    event,
    length,
    privateVaultBrokerReplacementProtocolLimits.sasDecisionBytes,
  ).catch(() => null);
  if (!decision) return privateVaultBrokerReplacementFailure(event, 400);
  try {
    const result = await withAuthenticatedPrivateVaultBrokerReplacementScope(
      event,
      undefined,
      async (scope) =>
        serializePrivateVaultBrokerReplacementStatus(
          await privateVaultBrokerReplacementOrchestration.sasDecision(
            scope,
            transcriptId,
            decision,
          ),
        ),
    );
    return result ?? privateVaultBrokerReplacementFailure(event, 404);
  } catch (error) {
    return privateVaultBrokerReplacementErrorResponse(event, error);
  }
});
