import { opaqueIdSchema, opaqueRevisionSchema } from "@agent-native/core/e2ee";
import { and, eq } from "drizzle-orm";
import { z } from "zod";

import { getDb, schema } from "../db/index.js";
import {
  type PrivateVaultMutationKind,
  type PrivateVaultMutationScope,
  type PrivateVaultMutationTransaction,
  withPrivateVaultMutationGate,
} from "./private-vault-mutation-gate.js";

const aliasesSchema = z
  .object({
    ownerEmail: z.string().trim().email().max(320),
    orgId: opaqueIdSchema,
    vaultId: opaqueIdSchema,
  })
  .strip();

export interface PrivateVaultHostedScope {
  readonly ownerEmail: string;
  readonly orgId: string;
  readonly vaultId: string;
}

export interface PrivateVaultManifestHead {
  readonly objectId: string;
  readonly revisionId: string;
  readonly generation: number;
}

export interface PrivateVaultManifestHeadCas {
  readonly prior: PrivateVaultManifestHead | null;
  readonly next: PrivateVaultManifestHead;
}

export class PrivateVaultManifestHeadConflictError extends Error {
  constructor() {
    super("Private Vault manifest head conflict");
    this.name = "PrivateVaultManifestHeadConflictError";
  }
}

function fail(): never {
  throw new PrivateVaultManifestHeadConflictError();
}

function sameHead(
  left: PrivateVaultManifestHead | null,
  right: PrivateVaultManifestHead | null,
) {
  return (
    left === right ||
    (left !== null &&
      right !== null &&
      left.objectId === right.objectId &&
      left.revisionId === right.revisionId &&
      left.generation === right.generation)
  );
}

function exactHead(value: PrivateVaultManifestHead): PrivateVaultManifestHead {
  const parsed = z
    .object({
      objectId: opaqueIdSchema,
      revisionId: opaqueIdSchema,
      generation: z.number().int().positive().max(Number.MAX_SAFE_INTEGER),
    })
    .strict()
    .safeParse(value);
  if (!parsed.success) return fail();
  return parsed.data;
}

async function resolveMutationScope(
  input: PrivateVaultHostedScope,
): Promise<PrivateVaultMutationScope> {
  const parsed = aliasesSchema.safeParse(input);
  if (!parsed.success) return fail();
  const aliases = {
    ...parsed.data,
    ownerEmail: parsed.data.ownerEmail.toLowerCase(),
  };
  const rows = await getDb()
    .select({
      accountId: schema.contentEncryptedVaults.accountId,
      workspaceId: schema.contentEncryptedVaults.workspaceId,
    })
    .from(schema.contentEncryptedVaults)
    .where(
      and(
        eq(schema.contentEncryptedVaults.vaultId, aliases.vaultId),
        eq(schema.contentEncryptedVaults.ownerEmail, aliases.ownerEmail),
        eq(schema.contentEncryptedVaults.orgId, aliases.orgId),
        eq(schema.contentEncryptedVaults.vaultState, "active"),
      ),
    )
    .limit(2);
  if (rows.length !== 1) return fail();
  return {
    ...aliases,
    accountId: opaqueIdSchema.parse(rows[0]!.accountId),
    workspaceId: opaqueIdSchema.parse(rows[0]!.workspaceId),
  };
}

async function readManifestHead(
  transaction: PrivateVaultMutationTransaction,
  scope: PrivateVaultMutationScope,
): Promise<PrivateVaultManifestHead | null> {
  const objects = await transaction
    .select({ objectId: schema.contentEncryptedVaultObjects.objectId })
    .from(schema.contentEncryptedVaultObjects)
    .where(
      and(
        eq(schema.contentEncryptedVaultObjects.vaultId, scope.vaultId),
        eq(schema.contentEncryptedVaultObjects.ownerEmail, scope.ownerEmail),
        eq(schema.contentEncryptedVaultObjects.orgId, scope.orgId),
        eq(schema.contentEncryptedVaultObjects.objectType, "vault-manifest"),
        eq(schema.contentEncryptedVaultObjects.objectState, "active"),
      ),
    )
    .limit(2);
  if (objects.length === 0) return null;
  // A vault has one manifest lineage. Multiple active manifest objects make
  // the head ambiguous and are never repaired by choosing one heuristically.
  if (objects.length !== 1) return fail();
  const objectId = opaqueIdSchema.parse(objects[0]!.objectId);
  const rows = await transaction
    .select({
      revisionId: schema.contentEncryptedVaultObjectRevisions.revisionId,
      opaqueRevisionJson:
        schema.contentEncryptedVaultObjectRevisions.opaqueRevisionJson,
    })
    .from(schema.contentEncryptedVaultObjectRevisions)
    .where(
      and(
        eq(schema.contentEncryptedVaultObjectRevisions.vaultId, scope.vaultId),
        eq(
          schema.contentEncryptedVaultObjectRevisions.ownerEmail,
          scope.ownerEmail,
        ),
        eq(schema.contentEncryptedVaultObjectRevisions.orgId, scope.orgId),
        eq(schema.contentEncryptedVaultObjectRevisions.objectId, objectId),
      ),
    )
    .limit(100_001);
  if (rows.length === 0 || rows.length > 100_000) return fail();
  let head: PrivateVaultManifestHead | null = null;
  for (const row of rows) {
    let opaque: z.infer<typeof opaqueRevisionSchema>;
    try {
      opaque = opaqueRevisionSchema.parse(JSON.parse(row.opaqueRevisionJson));
    } catch {
      return fail();
    }
    if (
      opaque.vaultId !== scope.vaultId ||
      opaque.objectId !== objectId ||
      opaque.revisionId !== row.revisionId
    )
      return fail();
    const candidate = exactHead({
      objectId,
      revisionId: row.revisionId,
      generation: opaque.revision,
    });
    if (head?.generation === candidate.generation) return fail();
    if (!head || candidate.generation > head.generation) head = candidate;
  }
  return head;
}

export async function withPrivateVaultOrdinaryWrite<T>(
  scope: PrivateVaultHostedScope,
  manifestCas: PrivateVaultManifestHeadCas | null,
  run: (transaction: PrivateVaultMutationTransaction) => Promise<T>,
): Promise<T> {
  const mutationScope = await resolveMutationScope(scope);
  return withPrivateVaultMutationGate(mutationScope, async (gate) => {
    if (gate.current().phase !== "open") return fail();
    if (manifestCas) {
      const prior = manifestCas.prior ? exactHead(manifestCas.prior) : null;
      const next = exactHead(manifestCas.next);
      const expectedGeneration = (prior?.generation ?? 0) + 1;
      if (
        next.generation !== expectedGeneration ||
        (prior !== null && prior.objectId !== next.objectId)
      )
        return fail();
      const current = await readManifestHead(gate.transaction, mutationScope);
      // The exact destination is the sole lost-response retry. A different
      // writer from the same prior head is stale after the winner commits.
      if (!sameHead(current, prior) && !sameHead(current, next)) return fail();
    }
    return run(gate.transaction);
  });
}

export async function freezePrivateVaultRotation(input: {
  readonly scope: PrivateVaultHostedScope;
  readonly kind: Extract<
    PrivateVaultMutationKind,
    "remove_device" | "remove_broker" | "broker_replacement" | "rotate_epoch"
  >;
  readonly ceremonyId: string;
  readonly baseEpoch: number;
  readonly targetEpoch: number;
  readonly manifest: PrivateVaultManifestHead;
}) {
  const mutationScope = await resolveMutationScope(input.scope);
  const manifest = exactHead(input.manifest);
  return withPrivateVaultMutationGate(mutationScope, async (gate) => {
    const current = gate.current();
    const destination = {
      phase: "rotating" as const,
      kind: input.kind,
      ceremonyId: opaqueIdSchema.parse(input.ceremonyId),
      baseEpoch: input.baseEpoch,
      targetEpoch: input.targetEpoch,
      manifestObjectId: manifest.objectId,
      manifestRevisionId: manifest.revisionId,
      manifestGeneration: manifest.generation,
    };
    if (current.phase === "rotating") {
      if (
        current.kind === destination.kind &&
        current.ceremonyId === destination.ceremonyId &&
        current.baseEpoch === destination.baseEpoch &&
        current.targetEpoch === destination.targetEpoch &&
        current.manifestObjectId === destination.manifestObjectId &&
        current.manifestRevisionId === destination.manifestRevisionId &&
        current.manifestGeneration === destination.manifestGeneration
      )
        return { state: current, idempotent: true };
      return fail();
    }
    if (current.phase !== "open") return fail();
    if (
      !sameHead(
        await readManifestHead(gate.transaction, mutationScope),
        manifest,
      )
    )
      return fail();
    try {
      return await gate.transition(current, destination);
    } catch {
      return fail();
    }
  });
}
