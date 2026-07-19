import { ANC_ROTATION_EVIDENCE_SIZE_LIMITS } from "@agent-native/core/e2ee";
import {
  getHeader,
  setResponseHeader,
  setResponseStatus,
  type H3Event,
} from "h3";

import { readPrivateVaultBoundedBody } from "./private-vault-bounded-body.js";
import {
  authenticatePrivateVaultAttendedEndpoint,
  decodePrivateVaultEndpointProofHeader,
} from "./private-vault-endpoint-auth.js";
import { privateVaultRotationEvidenceIngress } from "./private-vault-rotation-evidence-runtime.js";

export const PRIVATE_VAULT_ROTATION_EVIDENCE_PATHS = Object.freeze({
  checkpoint: "/api/private-vault/rotation-evidence/checkpoint",
  offer: "/api/private-vault/rotation-evidence/offer",
} as const);

export type PrivateVaultRotationEvidenceRoute =
  keyof typeof PRIVATE_VAULT_ROTATION_EVIDENCE_PATHS;

function fail(event: H3Event) {
  setResponseStatus(event, 404);
  return { error: "Not found" };
}

function boundedLength(value: string, maximum: number): number {
  if (!/^[1-9][0-9]*$/.test(value)) return Number.NaN;
  const length = Number(value);
  return Number.isSafeInteger(length) && length <= maximum
    ? length
    : Number.NaN;
}

function decodeWrap(value: string): Uint8Array {
  if (!/^[A-Za-z0-9_-]+$/.test(value) || value.length > 4_096)
    throw new Error();
  const bytes = Uint8Array.from(Buffer.from(value, "base64url"));
  if (
    bytes.byteLength < 1 ||
    bytes.byteLength > 2_048 ||
    Buffer.from(bytes).toString("base64url") !== value
  )
    throw new Error();
  return bytes;
}

export async function handlePrivateVaultRotationEvidence(
  event: H3Event,
  route: PrivateVaultRotationEvidenceRoute,
) {
  setResponseHeader(event, "Cache-Control", "no-store");
  setResponseHeader(event, "Referrer-Policy", "no-referrer");
  setResponseHeader(event, "X-Content-Type-Options", "nosniff");
  const maximum =
    route === "checkpoint"
      ? ANC_ROTATION_EVIDENCE_SIZE_LIMITS.checkpointBytes
      : ANC_ROTATION_EVIDENCE_SIZE_LIMITS.offerBytes;
  const length = boundedLength(
    getHeader(event, "content-length")?.trim() ?? "",
    maximum,
  );
  if (
    getHeader(event, "content-type")?.trim().toLowerCase() !==
      "application/octet-stream" ||
    !Number.isSafeInteger(length)
  )
    return fail(event);
  const body = await readPrivateVaultBoundedBody(event, length, maximum).catch(
    () => null,
  );
  if (!body || body.byteLength !== length) return fail(event);
  try {
    const proof = decodePrivateVaultEndpointProofHeader(
      getHeader(event, "x-anc-endpoint-proof")?.trim() ?? "",
    );
    const principal = await authenticatePrivateVaultAttendedEndpoint({
      proof,
      method: "POST",
      path: PRIVATE_VAULT_ROTATION_EVIDENCE_PATHS[route],
      body,
    });
    const status =
      route === "checkpoint"
        ? await privateVaultRotationEvidenceIngress.appendCheckpoint(
            principal,
            body,
          )
        : await privateVaultRotationEvidenceIngress.appendOffer(
            principal,
            body,
            decodeWrap(getHeader(event, "x-anc-eek-wrap")?.trim() ?? ""),
          );
    return {
      state: "stored",
      ceremonyId: status.ceremonyId,
      phase: status.phase,
      expectedRecipientCount: status.expectedRecipientCount,
    };
  } catch {
    return fail(event);
  } finally {
    body.fill(0);
  }
}
