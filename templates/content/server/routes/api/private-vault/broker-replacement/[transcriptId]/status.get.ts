import { defineEventHandler, getRouterParam } from "h3";

import {
  preparePrivateVaultBrokerReplacementResponse,
  privateVaultBrokerReplacementErrorResponse,
  privateVaultBrokerReplacementFailure,
  serializePrivateVaultBrokerReplacementProgress,
} from "../../../../../lib/private-vault-broker-replacement-http.js";
import {
  isPrivateVaultBrokerReplacementTranscriptId,
  privateVaultBrokerReplacementOrchestration,
  withAuthenticatedPrivateVaultBrokerReplacementScope,
} from "../../../../../lib/private-vault-broker-replacement-orchestration.js";

export default defineEventHandler(async (event) => {
  preparePrivateVaultBrokerReplacementResponse(event);
  const transcriptId = getRouterParam(event, "transcriptId") ?? "";
  if (!isPrivateVaultBrokerReplacementTranscriptId(transcriptId)) {
    return privateVaultBrokerReplacementFailure(event, 404);
  }
  try {
    const result = await withAuthenticatedPrivateVaultBrokerReplacementScope(
      event,
      undefined,
      async (scope) =>
        serializePrivateVaultBrokerReplacementProgress(
          await privateVaultBrokerReplacementOrchestration.status(
            scope,
            transcriptId,
          ),
        ),
    );
    return result ?? privateVaultBrokerReplacementFailure(event, 404);
  } catch (error) {
    return privateVaultBrokerReplacementErrorResponse(event, error);
  }
});
