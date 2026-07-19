import { createHash } from "node:crypto";

import {
  defineEventHandler,
  getHeader,
  setResponseHeader,
  setResponseStatus,
} from "h3";

import { readPrivateVaultBoundedBody } from "../../../../lib/private-vault-bounded-body.js";
import {
  authenticatePrivateVaultAttendedEndpoint,
  decodePrivateVaultEndpointProofHeader,
} from "../../../../lib/private-vault-endpoint-auth.js";
import { resolveAuthenticatedPrivateVaultScope } from "../../../../lib/private-vault-genesis-account-scope.js";
import {
  type PrivateVaultManifestHeadCas,
  PrivateVaultManifestHeadConflictError,
} from "../../../../lib/private-vault-manifest-head.js";
import {
  PRIVATE_VAULT_OBJECT_MAX_BYTES,
  PrivateVaultObjectConflictError,
  PrivateVaultObjectNotFoundError,
  privateVaultObjectRevisionInputSchema,
  privateVaultObjectService,
} from "../../../../lib/private-vault-objects.js";

function secureHeaders(event: Parameters<typeof setResponseHeader>[0]) {
  setResponseHeader(event, "Cache-Control", "no-store");
  setResponseHeader(event, "Referrer-Policy", "no-referrer");
  setResponseHeader(event, "X-Content-Type-Options", "nosniff");
}

function fail(event: Parameters<typeof setResponseStatus>[0], status: number) {
  setResponseStatus(event, status);
  return { error: status === 404 ? "Not found" : "Request unavailable" };
}

function header(event: Parameters<typeof getHeader>[0], name: string) {
  return getHeader(event, name)?.trim() ?? "";
}

function parseInteger(value: string): number {
  if (!/^[1-9][0-9]*$/.test(value)) return Number.NaN;
  return Number(value);
}

function manifestCas(
  event: Parameters<typeof getHeader>[0],
  next: { objectId: string; revisionId: string; revision: number },
): PrivateVaultManifestHeadCas {
  const generation = header(event, "x-anc-prior-manifest-generation");
  const objectId = header(event, "x-anc-prior-manifest-object-id");
  const revisionId = header(event, "x-anc-prior-manifest-revision-id");
  if (generation === "0" && !objectId && !revisionId) {
    return {
      prior: null,
      next: {
        objectId: next.objectId,
        revisionId: next.revisionId,
        generation: next.revision,
      },
    };
  }
  const parsedGeneration = parseInteger(generation);
  if (!objectId || !revisionId || !Number.isSafeInteger(parsedGeneration))
    throw new Error();
  return {
    prior: { objectId, revisionId, generation: parsedGeneration },
    next: {
      objectId: next.objectId,
      revisionId: next.revisionId,
      generation: next.revision,
    },
  };
}

export function privateVaultManifestWriteAuthorizationBody(input: {
  metadata: {
    vaultId: string;
    objectId: string;
    revisionId: string;
    revision: number;
    objectType: string;
    algorithmId: string;
    epoch: number;
    parentRevisionIds: readonly string[];
    ciphertextByteLength: number;
  };
  cas: PrivateVaultManifestHeadCas;
  ciphertext: Uint8Array;
}) {
  const ciphertextSha256 = createHash("sha256")
    .update(input.ciphertext)
    .digest("hex");
  return Uint8Array.from(
    Buffer.from(
      JSON.stringify([
        "anc/v1/private-vault-manifest-write",
        input.metadata.vaultId,
        input.metadata.objectId,
        input.metadata.revisionId,
        input.metadata.revision,
        input.metadata.objectType,
        input.metadata.algorithmId,
        input.metadata.epoch,
        input.metadata.parentRevisionIds,
        input.metadata.ciphertextByteLength,
        input.cas.prior?.objectId ?? null,
        input.cas.prior?.revisionId ?? null,
        input.cas.prior?.generation ?? 0,
        ciphertextSha256,
      ]),
      "utf8",
    ),
  );
}

export default defineEventHandler(async (event) => {
  secureHeaders(event);
  if (
    header(event, "x-agent-native-csrf") !== "1" &&
    header(event, "sec-fetch-site") !== "same-origin"
  ) {
    return fail(event, 403);
  }
  const parentHeader = header(event, "x-anc-parent-revision-ids");
  let parentRevisionIds: unknown = [];
  try {
    parentRevisionIds = parentHeader
      ? JSON.parse(Buffer.from(parentHeader, "base64url").toString("utf8"))
      : [];
  } catch {
    return fail(event, 400);
  }
  const metadata = privateVaultObjectRevisionInputSchema.safeParse({
    vaultId: header(event, "x-anc-vault-id"),
    objectId: header(event, "x-anc-object-id"),
    revisionId: header(event, "x-anc-revision-id"),
    revision: parseInteger(header(event, "x-anc-revision")),
    objectType: header(event, "x-anc-object-type"),
    algorithmId: header(event, "x-anc-algorithm-id"),
    epoch: parseInteger(header(event, "x-anc-epoch")),
    parentRevisionIds,
    ciphertextByteLength: parseInteger(
      header(event, "x-anc-ciphertext-byte-length"),
    ),
  });
  if (!metadata.success) return fail(event, 400);
  const contentType = header(event, "content-type").toLowerCase();
  const contentLength = parseInteger(header(event, "content-length"));
  if (
    contentType !== "application/octet-stream" ||
    contentLength !== metadata.data.ciphertextByteLength ||
    contentLength > PRIVATE_VAULT_OBJECT_MAX_BYTES
  ) {
    return fail(event, 400);
  }

  const scope = await resolveAuthenticatedPrivateVaultScope(
    event,
    metadata.data.vaultId,
  );
  if (!scope) return fail(event, 404);
  try {
    // Parent authorization is deliberately complete before the body is read.
    await privateVaultObjectService.authorizePut(scope, metadata.data);
  } catch (error) {
    return error instanceof PrivateVaultObjectNotFoundError
      ? fail(event, 404)
      : fail(event, 409);
  }

  const raw = await readPrivateVaultBoundedBody(
    event,
    contentLength,
    PRIVATE_VAULT_OBJECT_MAX_BYTES,
  ).catch(() => undefined);
  if (!(raw instanceof Uint8Array) || raw.byteLength !== contentLength) {
    return fail(event, 400);
  }
  let cas: PrivateVaultManifestHeadCas | null = null;
  if (metadata.data.objectType === "vault-manifest") {
    try {
      cas = manifestCas(event, metadata.data);
      const principal = await authenticatePrivateVaultAttendedEndpoint({
        proof: decodePrivateVaultEndpointProofHeader(
          header(event, "x-anc-endpoint-proof"),
        ),
        method: "POST",
        path: "/api/private-vault/objects",
        body: privateVaultManifestWriteAuthorizationBody({
          metadata: metadata.data,
          cas,
          ciphertext: raw,
        }),
      });
      if (
        principal.ownerEmail !== scope.ownerEmail ||
        principal.orgId !== scope.orgId ||
        principal.vaultId !== scope.vaultId
      )
        throw new Error();
    } catch {
      raw.fill(0);
      return fail(event, 404);
    }
  }
  try {
    const revision = { ...metadata.data, ciphertext: raw };
    return cas
      ? await privateVaultObjectService.putRevision(scope, revision, cas)
      : await privateVaultObjectService.putRevision(scope, revision);
  } catch (error) {
    if (error instanceof PrivateVaultObjectNotFoundError)
      return fail(event, 404);
    if (
      error instanceof PrivateVaultObjectConflictError ||
      error instanceof PrivateVaultManifestHeadConflictError
    )
      return fail(event, 409);
    return fail(event, 503);
  }
});
