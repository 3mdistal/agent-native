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
  decodePrivateVaultBrokerReplacementDeadlineDecision,
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
    length > privateVaultBrokerReplacementProtocolLimits.deadlineDecisionBytes
  ) {
    return privateVaultBrokerReplacementFailure(event, 404);
  }
  const body = await readPrivateVaultBoundedBody(
    event,
    length,
    privateVaultBrokerReplacementProtocolLimits.deadlineDecisionBytes,
  ).catch(() => null);
  if (!body) return privateVaultBrokerReplacementFailure(event, 400);
  try {
    const decision = decodePrivateVaultBrokerReplacementDeadlineDecision(body);
    const result = await withAuthenticatedPrivateVaultBrokerReplacementScope(
      event,
      undefined,
      async (scope) =>
        serializePrivateVaultBrokerReplacementStatus(
          await privateVaultBrokerReplacementOrchestration.deadline(
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
