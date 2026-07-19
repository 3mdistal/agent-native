import { opaqueIdSchema } from "@agent-native/core/e2ee";
import { and, eq, isNull, sql } from "drizzle-orm";
import { z } from "zod";

import { getDb, schema } from "../db/index.js";

const MAX_SERIAL = Number.MAX_SAFE_INTEGER - 1;
const MAX_EPOCH = Number.MAX_SAFE_INTEGER;
const MAX_GENERATION = Number.MAX_SAFE_INTEGER;

const mutationKindSchema = z.enum([
  "add_device",
  "add_broker",
  "remove_device",
  "remove_broker",
  "broker_replacement",
  "rotate_epoch",
  "recovery",
]);
const scopeSchema = z
  .object({
    ownerEmail: z.string().trim().email().max(320),
    accountId: opaqueIdSchema,
    orgId: opaqueIdSchema,
    workspaceId: opaqueIdSchema,
    vaultId: opaqueIdSchema,
  })
  .strict();

export type PrivateVaultMutationKind = z.infer<typeof mutationKindSchema>;

export type PrivateVaultMutationPhase = "open" | "draining" | "rotating";

export interface PrivateVaultMutationScope {
  ownerEmail: string;
  accountId: string;
  orgId: string;
  workspaceId: string;
  vaultId: string;
}

interface PrivateVaultMutationMetadata {
  kind: PrivateVaultMutationKind | null;
  ceremonyId: string | null;
  baseEpoch: number | null;
  targetEpoch: number | null;
  manifestObjectId: string | null;
  manifestRevisionId: string | null;
  manifestGeneration: number | null;
}

export interface PrivateVaultMutationState extends PrivateVaultMutationMetadata {
  serial: number;
  phase: PrivateVaultMutationPhase;
}

export type PrivateVaultMutationDestination = Omit<
  PrivateVaultMutationState,
  "serial"
>;

export interface PrivateVaultMutationTransitionResult {
  state: PrivateVaultMutationState;
  idempotent: boolean;
}

export type PrivateVaultMutationGateErrorCode =
  | "not_found"
  | "invalid_state"
  | "invalid_transition"
  | "conflict";

export class PrivateVaultMutationGateError extends Error {
  readonly code: PrivateVaultMutationGateErrorCode;

  constructor(code: PrivateVaultMutationGateErrorCode) {
    super(code);
    this.name = "PrivateVaultMutationGateError";
    this.code = code;
  }
}

type ContentDb = ReturnType<typeof getDb>;
export type PrivateVaultMutationTransaction = Parameters<
  Parameters<ContentDb["transaction"]>[0]
>[0];

export interface PrivateVaultLockedMutationGate {
  readonly transaction: PrivateVaultMutationTransaction;
  current(): PrivateVaultMutationState;
  transition(
    expected: PrivateVaultMutationState,
    destination: PrivateVaultMutationDestination,
  ): Promise<PrivateVaultMutationTransitionResult>;
}

type StoredMutationRow = {
  mutationSerial: number;
  mutationPhase: string;
  mutationKind: string | null;
  mutationCeremonyId: string | null;
  mutationBaseEpoch: number | null;
  mutationTargetEpoch: number | null;
  mutationManifestObjectId: string | null;
  mutationManifestRevisionId: string | null;
  mutationManifestGeneration: number | null;
};

const mutationProjection = {
  mutationSerial: schema.contentEncryptedVaults.mutationSerial,
  mutationPhase: schema.contentEncryptedVaults.mutationPhase,
  mutationKind: schema.contentEncryptedVaults.mutationKind,
  mutationCeremonyId: schema.contentEncryptedVaults.mutationCeremonyId,
  mutationBaseEpoch: schema.contentEncryptedVaults.mutationBaseEpoch,
  mutationTargetEpoch: schema.contentEncryptedVaults.mutationTargetEpoch,
  mutationManifestObjectId:
    schema.contentEncryptedVaults.mutationManifestObjectId,
  mutationManifestRevisionId:
    schema.contentEncryptedVaults.mutationManifestRevisionId,
  mutationManifestGeneration:
    schema.contentEncryptedVaults.mutationManifestGeneration,
};

function validEpochPair(baseEpoch: unknown, targetEpoch: unknown): boolean {
  return (
    Number.isSafeInteger(baseEpoch) &&
    Number.isSafeInteger(targetEpoch) &&
    (baseEpoch as number) > 0 &&
    (targetEpoch as number) === (baseEpoch as number) + 1 &&
    (targetEpoch as number) <= MAX_EPOCH
  );
}

function metadataAllNull(state: PrivateVaultMutationMetadata): boolean {
  return (
    state.kind === null &&
    state.ceremonyId === null &&
    state.baseEpoch === null &&
    state.targetEpoch === null &&
    state.manifestObjectId === null &&
    state.manifestRevisionId === null &&
    state.manifestGeneration === null
  );
}

/** Validate the durable phase invariants without repairing or weakening them. */
export function isValidPrivateVaultMutationState(
  state: PrivateVaultMutationState,
): boolean {
  if (
    !Number.isSafeInteger(state.serial) ||
    state.serial < 0 ||
    state.serial > MAX_SERIAL + 1
  ) {
    return false;
  }
  if (state.phase === "open") return metadataAllNull(state);
  if (state.phase !== "draining" && state.phase !== "rotating") return false;
  if (
    !mutationKindSchema.safeParse(state.kind).success ||
    !opaqueIdSchema.safeParse(state.ceremonyId).success ||
    !validEpochPair(state.baseEpoch, state.targetEpoch)
  ) {
    return false;
  }
  if (state.phase === "draining") {
    return (
      state.manifestObjectId === null &&
      state.manifestRevisionId === null &&
      state.manifestGeneration === null
    );
  }
  return (
    opaqueIdSchema.safeParse(state.manifestObjectId).success &&
    opaqueIdSchema.safeParse(state.manifestRevisionId).success &&
    Number.isSafeInteger(state.manifestGeneration) &&
    (state.manifestGeneration as number) > 0 &&
    (state.manifestGeneration as number) <= MAX_GENERATION
  );
}

function stateFromRow(row: StoredMutationRow): PrivateVaultMutationState {
  const state = {
    serial: row.mutationSerial,
    phase: row.mutationPhase as PrivateVaultMutationPhase,
    kind: row.mutationKind as PrivateVaultMutationKind | null,
    ceremonyId: row.mutationCeremonyId,
    baseEpoch: row.mutationBaseEpoch,
    targetEpoch: row.mutationTargetEpoch,
    manifestObjectId: row.mutationManifestObjectId,
    manifestRevisionId: row.mutationManifestRevisionId,
    manifestGeneration: row.mutationManifestGeneration,
  };
  if (!isValidPrivateVaultMutationState(state)) {
    throw new PrivateVaultMutationGateError("invalid_state");
  }
  return state;
}

function stateEquals(
  left: PrivateVaultMutationState,
  right: PrivateVaultMutationState,
): boolean {
  return (
    left.serial === right.serial &&
    left.phase === right.phase &&
    left.kind === right.kind &&
    left.ceremonyId === right.ceremonyId &&
    left.baseEpoch === right.baseEpoch &&
    left.targetEpoch === right.targetEpoch &&
    left.manifestObjectId === right.manifestObjectId &&
    left.manifestRevisionId === right.manifestRevisionId &&
    left.manifestGeneration === right.manifestGeneration
  );
}

function isAllowedPhaseTransition(
  from: PrivateVaultMutationPhase,
  to: PrivateVaultMutationPhase,
): boolean {
  return (
    (from === "open" && (to === "draining" || to === "rotating")) ||
    (from === "draining" && (to === "rotating" || to === "open")) ||
    (from === "rotating" && to === "open")
  );
}

function exactColumn(column: unknown, value: string | number | null) {
  return value === null ? isNull(column as never) : eq(column as never, value);
}

function scopedActiveVault(scope: PrivateVaultMutationScope) {
  return and(
    eq(schema.contentEncryptedVaults.vaultId, scope.vaultId),
    eq(schema.contentEncryptedVaults.ownerEmail, scope.ownerEmail),
    eq(schema.contentEncryptedVaults.accountId, scope.accountId),
    eq(schema.contentEncryptedVaults.orgId, scope.orgId),
    eq(schema.contentEncryptedVaults.workspaceId, scope.workspaceId),
    eq(schema.contentEncryptedVaults.vaultState, "active"),
  );
}

function normalizeScope(
  input: PrivateVaultMutationScope,
): PrivateVaultMutationScope {
  const parsed = scopeSchema.safeParse(input);
  if (!parsed.success) {
    throw new PrivateVaultMutationGateError("not_found");
  }
  return { ...parsed.data, ownerEmail: parsed.data.ownerEmail.toLowerCase() };
}

function exactStoredState(state: PrivateVaultMutationState) {
  return and(
    eq(schema.contentEncryptedVaults.mutationSerial, state.serial),
    eq(schema.contentEncryptedVaults.mutationPhase, state.phase),
    exactColumn(schema.contentEncryptedVaults.mutationKind, state.kind),
    exactColumn(
      schema.contentEncryptedVaults.mutationCeremonyId,
      state.ceremonyId,
    ),
    exactColumn(
      schema.contentEncryptedVaults.mutationBaseEpoch,
      state.baseEpoch,
    ),
    exactColumn(
      schema.contentEncryptedVaults.mutationTargetEpoch,
      state.targetEpoch,
    ),
    exactColumn(
      schema.contentEncryptedVaults.mutationManifestObjectId,
      state.manifestObjectId,
    ),
    exactColumn(
      schema.contentEncryptedVaults.mutationManifestRevisionId,
      state.manifestRevisionId,
    ),
    exactColumn(
      schema.contentEncryptedVaults.mutationManifestGeneration,
      state.manifestGeneration,
    ),
  );
}

function destinationState(
  expected: PrivateVaultMutationState,
  destination: PrivateVaultMutationDestination,
): PrivateVaultMutationState {
  if (expected.serial > MAX_SERIAL) {
    throw new PrivateVaultMutationGateError("invalid_transition");
  }
  const desired = { ...destination, serial: expected.serial + 1 };
  if (!isValidPrivateVaultMutationState(desired)) {
    throw new PrivateVaultMutationGateError("invalid_transition");
  }
  return desired;
}

/**
 * Run work while holding the vault row's write lock.
 *
 * The no-op UPDATE is intentional: Postgres holds the tuple lock until this
 * transaction finishes, while local SQLite transactions begin IMMEDIATE and
 * serialize writers. A SELECT predicate would not provide that guarantee.
 */
export async function withPrivateVaultMutationGate<T>(
  scopeInput: PrivateVaultMutationScope,
  run: (gate: PrivateVaultLockedMutationGate) => Promise<T>,
): Promise<T> {
  const scope = normalizeScope(scopeInput);
  return getDb().transaction(async (transaction) => {
    const [lockedRow] = (await transaction
      .update(schema.contentEncryptedVaults)
      .set({
        mutationSerial: sql`${schema.contentEncryptedVaults.mutationSerial}`,
      })
      .where(scopedActiveVault(scope))
      .returning(mutationProjection)) as StoredMutationRow[];
    if (!lockedRow) throw new PrivateVaultMutationGateError("not_found");

    let state = stateFromRow(lockedRow);
    const gate: PrivateVaultLockedMutationGate = {
      transaction,
      current: () => ({ ...state }),
      // This checks only serialization and phase shape. In particular,
      // rotating -> open does not itself prove whether completion or abort is
      // authorized; the caller must establish that semantic proof in this same
      // transaction before requesting the transition.
      async transition(expected, destination) {
        const desired = destinationState(expected, destination);
        if (!isValidPrivateVaultMutationState(expected)) {
          throw new PrivateVaultMutationGateError("invalid_transition");
        }
        if (!isAllowedPhaseTransition(expected.phase, desired.phase)) {
          throw new PrivateVaultMutationGateError("invalid_transition");
        }

        // The only idempotent retry is the exact destination at serial N+1.
        if (stateEquals(state, desired)) {
          return { state: { ...state }, idempotent: true };
        }
        if (!stateEquals(state, expected)) {
          throw new PrivateVaultMutationGateError("conflict");
        }

        const [updated] = (await transaction
          .update(schema.contentEncryptedVaults)
          .set({
            mutationSerial: desired.serial,
            mutationPhase: desired.phase,
            mutationKind: desired.kind,
            mutationCeremonyId: desired.ceremonyId,
            mutationBaseEpoch: desired.baseEpoch,
            mutationTargetEpoch: desired.targetEpoch,
            mutationManifestObjectId: desired.manifestObjectId,
            mutationManifestRevisionId: desired.manifestRevisionId,
            mutationManifestGeneration: desired.manifestGeneration,
          })
          .where(and(scopedActiveVault(scope), exactStoredState(expected)))
          .returning(mutationProjection)) as StoredMutationRow[];
        if (!updated) throw new PrivateVaultMutationGateError("conflict");
        state = stateFromRow(updated);
        if (!stateEquals(state, desired)) {
          throw new PrivateVaultMutationGateError("invalid_state");
        }
        return { state: { ...state }, idempotent: false };
      },
    };
    return run(gate);
  });
}
