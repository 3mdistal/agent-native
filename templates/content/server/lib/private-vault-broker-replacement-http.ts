import { endpointRequestProofSchema } from "@agent-native/core/e2ee";
import {
  getHeader,
  setResponseHeader,
  setResponseStatus,
  type H3Event,
} from "h3";

import type { PrivateVaultBrokerReplacementProgress } from "./private-vault-broker-replacement-orchestration.js";
import {
  PrivateVaultBrokerReplacementError,
  type PrivateVaultBrokerReplacementStatus,
} from "./private-vault-broker-replacement.js";

export const PRIVATE_VAULT_BROKER_REPLACEMENT_MEDIA_TYPE =
  "application/vnd.agent-native.private-vault-broker-replacement+cbor";

export function preparePrivateVaultBrokerReplacementResponse(event: H3Event) {
  setResponseHeader(event, "Cache-Control", "no-store");
  setResponseHeader(event, "Referrer-Policy", "no-referrer");
  setResponseHeader(event, "X-Content-Type-Options", "nosniff");
}

export function hasPrivateVaultBrokerReplacementCsrf(event: H3Event) {
  return (
    getHeader(event, "x-agent-native-csrf")?.trim() === "1" ||
    getHeader(event, "sec-fetch-site")?.trim() === "same-origin"
  );
}

export function hasPrivateVaultBrokerReplacementMediaType(event: H3Event) {
  return (
    getHeader(event, "content-type")?.trim().toLowerCase() ===
    PRIVATE_VAULT_BROKER_REPLACEMENT_MEDIA_TYPE
  );
}

export function privateVaultBrokerReplacementLength(event: H3Event) {
  const value = getHeader(event, "content-length")?.trim() ?? "";
  if (!/^[1-9][0-9]*$/.test(value)) return Number.NaN;
  return Number(value);
}

export function privateVaultBrokerReplacementEndpointProof(event: H3Event) {
  const value = getHeader(event, "x-anc-endpoint-request-proof")?.trim() ?? "";
  if (!value || value.length > 8_192 || !/^[A-Za-z0-9_-]+$/.test(value)) {
    return null;
  }
  try {
    const bytes = Buffer.from(value, "base64url");
    if (bytes.toString("base64url") !== value || bytes.byteLength > 6_144) {
      return null;
    }
    return endpointRequestProofSchema.parse(JSON.parse(bytes.toString("utf8")));
  } catch {
    return null;
  }
}

export function privateVaultBrokerReplacementFailure(
  event: H3Event,
  status: number,
) {
  setResponseStatus(event, status);
  return { error: status === 404 ? "Not found" : "Request unavailable" };
}

export function privateVaultBrokerReplacementErrorResponse(
  event: H3Event,
  error: unknown,
) {
  if (error instanceof PrivateVaultBrokerReplacementError) {
    if (error.code === "invalid_request") {
      return privateVaultBrokerReplacementFailure(event, 400);
    }
    if (error.code === "conflict" || error.code === "expired") {
      return privateVaultBrokerReplacementFailure(event, 409);
    }
    if (error.code === "unavailable") {
      return privateVaultBrokerReplacementFailure(event, 503);
    }
  }
  return privateVaultBrokerReplacementFailure(event, 404);
}

function serializeBytes(value: Uint8Array | null) {
  return value === null ? null : Buffer.from(value).toString("base64url");
}

export function serializePrivateVaultBrokerReplacementStatus(
  status: PrivateVaultBrokerReplacementStatus,
) {
  return {
    version: 1 as const,
    suite: "anc/v1" as const,
    transcriptId: status.transcriptId,
    phase: status.phase,
    oldBrokerEndpointId: status.oldBrokerEndpointId,
    newBrokerEndpointId: status.newBrokerEndpointId,
    authorizerEndpointId: status.authorizerEndpointId,
    offer: serializeBytes(status.offer),
    challenge: serializeBytes(status.challenge),
    sasDecision: serializeBytes(status.sas),
    replacementApproval: serializeBytes(status.approval),
    drainId: status.drainId,
    drainGeneration: status.drainGeneration,
    drain: {
      totalCount: status.drainTotalCount,
      completedCount: status.drainCompletedCount,
      failedCount: status.drainFailedCount,
      cancelledCount: status.drainCancelledCount,
      digest: status.drainDigest,
      signedAttestation: serializeBytes(status.drainAttestation),
    },
    rotation: {
      controlEntryId: status.rotationControlEntryId,
      controlEntryHash: status.rotationControlEntryHash,
      controlSequence: status.rotationControlSequence,
      receipt: serializeBytes(status.rotationReceipt),
    },
    expiresAt: status.expiresAt,
  };
}

export function serializePrivateVaultBrokerReplacementProgress(
  progress: PrivateVaultBrokerReplacementProgress,
) {
  return {
    ...serializePrivateVaultBrokerReplacementStatus(progress.transcript),
    witnessedProgress: progress.drain,
  };
}
