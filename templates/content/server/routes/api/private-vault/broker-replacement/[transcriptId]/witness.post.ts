import { defineEventHandler, getRouterParam } from "h3";

import { readPrivateVaultBoundedBody } from "../../../../../lib/private-vault-bounded-body.js";
import {
  hasPrivateVaultBrokerReplacementCsrf,
  hasPrivateVaultBrokerReplacementMediaType,
  preparePrivateVaultBrokerReplacementResponse,
  privateVaultBrokerReplacementErrorResponse,
  privateVaultBrokerReplacementFailure,
  privateVaultBrokerReplacementLength,
} from "../../../../../lib/private-vault-broker-replacement-http.js";
import {
  isPrivateVaultBrokerReplacementTranscriptId,
  privateVaultBrokerReplacementOrchestration,
  withAuthenticatedPrivateVaultBrokerReplacementScope,
} from "../../../../../lib/private-vault-broker-replacement-orchestration.js";

const WITNESS = Uint8Array.from(Buffer.from("witness"));

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
    length !== WITNESS.byteLength
  ) {
    return privateVaultBrokerReplacementFailure(event, 404);
  }
  const body = await readPrivateVaultBoundedBody(
    event,
    length,
    WITNESS.byteLength,
  ).catch(() => null);
  if (!body || !body.every((byte, index) => byte === WITNESS[index])) {
    return privateVaultBrokerReplacementFailure(event, 400);
  }
  try {
    const result = await withAuthenticatedPrivateVaultBrokerReplacementScope(
      event,
      undefined,
      async (scope) => ({
        version: 1 as const,
        suite: "anc/v1" as const,
        witness:
          await privateVaultBrokerReplacementOrchestration.witnessProgress(
            scope,
            transcriptId,
          ),
      }),
    );
    return result ?? privateVaultBrokerReplacementFailure(event, 404);
  } catch (error) {
    return privateVaultBrokerReplacementErrorResponse(event, error);
  }
});
