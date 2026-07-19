import { createHash } from "node:crypto";

import { and, eq, inArray } from "drizzle-orm";
import { z } from "zod";

import { getDb, schema } from "../db/index.js";

const OFFER_MAX_BYTES = 64 * 1024;
const CHALLENGE_MAX_BYTES = 64 * 1024;
const SAS_MAX_BYTES = 2 * 1024;
const AUTHORIZATION_MAX_BYTES = 256 * 1024;
const APPROVAL_MAX_BYTES = 256 * 1024;
const DRAIN_ATTESTATION_MAX_BYTES = 1024;
const ROTATION_RECEIPT_MAX_BYTES = 16 * 1024;

const identifierSchema = z.string().trim().min(1).max(512);
const hashSchema = z.string().regex(/^[0-9a-f]{64}$/);
const timestampSchema = z.string().datetime({ offset: true });

export type PrivateVaultBrokerReplacementPhase =
  | "offer"
  | "challenge"
  | "candidate_confirmed"
  | "authorized"
  | "draining"
  | "drained"
  | "rotation_committed"
  | "activated"
  | "rejected"
  | "expired"
  | "aborted";

const phases = [
  "offer",
  "challenge",
  "candidate_confirmed",
  "authorized",
  "draining",
  "drained",
  "rotation_committed",
  "activated",
  "rejected",
  "expired",
  "aborted",
] as const;

const phaseSchema = z.enum(phases);
const terminalPhases = new Set<PrivateVaultBrokerReplacementPhase>([
  "activated",
  "rejected",
  "expired",
  "aborted",
]);

export interface PrivateVaultBrokerReplacementScope {
  ownerEmail: string;
  accountId: string;
  orgId: string;
  workspaceId: string;
  vaultId: string;
}

export interface PrivateVaultBrokerReplacementBindings {
  oldBrokerEndpointId: string;
  newBrokerEndpointId: string;
  authorizerEndpointId: string;
}

export interface PrivateVaultBrokerReplacementStatus extends PrivateVaultBrokerReplacementBindings {
  transcriptId: string;
  phase: PrivateVaultBrokerReplacementPhase;
  offerHash: string;
  offer: Uint8Array;
  challengeHash: string | null;
  challenge: Uint8Array | null;
  sasHash: string | null;
  sas: Uint8Array | null;
  authorizationHash: string | null;
  authorization: Uint8Array | null;
  approvalHash: string | null;
  approval: Uint8Array | null;
  drainId: string | null;
  drainGeneration: string | null;
  drainTotalCount: number | null;
  drainCompletedCount: number | null;
  drainFailedCount: number | null;
  drainCancelledCount: number | null;
  drainDigest: string | null;
  drainAttestationHash: string | null;
  drainAttestation: Uint8Array | null;
  rotationControlEntryId: string | null;
  rotationControlEntryHash: string | null;
  rotationControlSequence: number | null;
  rotationReceiptHash: string | null;
  rotationReceipt: Uint8Array | null;
  expiresAt: string;
}

export class PrivateVaultBrokerReplacementError extends Error {
  constructor(
    readonly code:
      | "invalid_request"
      | "not_found"
      | "conflict"
      | "expired"
      | "unavailable",
  ) {
    super("Private Vault broker replacement unavailable");
    this.name = "PrivateVaultBrokerReplacementError";
  }
}

const scopeSchema = z
  .object({
    ownerEmail: z.string().trim().email().max(320),
    accountId: identifierSchema,
    orgId: z.string().trim().max(512),
    workspaceId: identifierSchema,
    vaultId: identifierSchema,
  })
  .strict();

const bindingsSchema = z
  .object({
    oldBrokerEndpointId: identifierSchema,
    newBrokerEndpointId: identifierSchema,
    authorizerEndpointId: identifierSchema,
  })
  .strict()
  .superRefine((value, ctx) => {
    if (new Set(Object.values(value)).size !== 3) {
      ctx.addIssue({
        code: "custom",
        path: ["oldBrokerEndpointId"],
        message: "Broker replacement endpoints must be distinct",
      });
    }
  });

const establishSchema = z
  .object({
    transcriptId: identifierSchema,
    bindings: bindingsSchema,
    offer: z.instanceof(Uint8Array),
    expiresAt: timestampSchema,
  })
  .strict();

const commonAdvanceSchema = {
  bindings: bindingsSchema,
  offerHash: hashSchema,
} as const;

const advanceSchema = z.discriminatedUnion("to", [
  z.object({
    ...commonAdvanceSchema,
    to: z.literal("challenge"),
    challenge: z.instanceof(Uint8Array),
  }),
  z.object({
    ...commonAdvanceSchema,
    to: z.literal("candidate_confirmed"),
    challengeHash: hashSchema,
    sas: z.instanceof(Uint8Array),
  }),
  z.object({
    ...commonAdvanceSchema,
    to: z.literal("authorized"),
    sasHash: hashSchema,
    authorization: z.instanceof(Uint8Array),
    approval: z.instanceof(Uint8Array),
  }),
  z.object({
    ...commonAdvanceSchema,
    to: z.literal("draining"),
    approvalHash: hashSchema,
    drainId: identifierSchema,
    drainGeneration: identifierSchema,
  }),
  z.object({
    ...commonAdvanceSchema,
    to: z.literal("drained"),
    drainId: identifierSchema,
    drainGeneration: identifierSchema,
    totalCount: z.number().int().nonnegative(),
    completedCount: z.number().int().nonnegative(),
    failedCount: z.number().int().nonnegative(),
    cancelledCount: z.number().int().nonnegative(),
    drainDigest: hashSchema,
    signedDrainAttestation: z.instanceof(Uint8Array),
  }),
  z.object({
    ...commonAdvanceSchema,
    to: z.literal("rotation_committed"),
    drainAttestationHash: hashSchema,
    controlEntryId: identifierSchema,
    controlEntryHash: hashSchema,
    controlSequence: z.number().int().positive(),
    rotationReceipt: z.instanceof(Uint8Array),
  }),
  z.object({
    ...commonAdvanceSchema,
    to: z.literal("activated"),
    controlEntryId: identifierSchema,
    controlEntryHash: hashSchema,
    controlSequence: z.number().int().positive(),
    rotationReceiptHash: hashSchema,
  }),
  z.object({
    ...commonAdvanceSchema,
    to: z.enum(["rejected", "expired", "aborted"]),
  }),
]);

type TranscriptRow =
  typeof schema.contentEncryptedVaultBrokerReplacementTranscripts.$inferSelect;
type AdvanceInput = z.infer<typeof advanceSchema>;

function normalizeScope(input: PrivateVaultBrokerReplacementScope) {
  const scope = scopeSchema.parse(input);
  return { ...scope, ownerEmail: scope.ownerEmail.toLowerCase() };
}

function hashBytes(bytes: Uint8Array) {
  return createHash("sha256").update(bytes).digest("hex");
}

function bounded(bytes: Uint8Array, maximum: number) {
  if (bytes.byteLength < 1 || bytes.byteLength > maximum) {
    throw new PrivateVaultBrokerReplacementError("invalid_request");
  }
  return bytes.slice();
}

function encode(bytes: Uint8Array) {
  return Buffer.from(bytes).toString("base64url");
}

function decode(value: string | null, maximum: number): Uint8Array | null {
  if (value === null || !/^[A-Za-z0-9_-]+$/.test(value)) return null;
  const bytes = Uint8Array.from(Buffer.from(value, "base64url"));
  if (
    bytes.byteLength < 1 ||
    bytes.byteLength > maximum ||
    encode(bytes) !== value
  ) {
    return null;
  }
  return bytes;
}

function internalId(
  scope: ReturnType<typeof normalizeScope>,
  transcriptId: string,
) {
  return createHash("sha256")
    .update(
      JSON.stringify([
        scope.ownerEmail,
        scope.accountId,
        scope.orgId,
        scope.workspaceId,
        scope.vaultId,
        transcriptId,
      ]),
    )
    .digest("hex");
}

function activeKey(
  scope: ReturnType<typeof normalizeScope>,
  oldBrokerEndpointId: string,
) {
  return createHash("sha256")
    .update(
      JSON.stringify([
        scope.accountId,
        scope.orgId,
        scope.workspaceId,
        scope.vaultId,
        oldBrokerEndpointId,
      ]),
    )
    .digest("hex");
}

function scoped(
  scope: ReturnType<typeof normalizeScope>,
  transcriptId: string,
) {
  const table = schema.contentEncryptedVaultBrokerReplacementTranscripts;
  return and(
    eq(table.id, internalId(scope, transcriptId)),
    eq(table.transcriptId, transcriptId),
    eq(table.ownerEmail, scope.ownerEmail),
    eq(table.accountId, scope.accountId),
    eq(table.orgId, scope.orgId),
    eq(table.workspaceId, scope.workspaceId),
    eq(table.vaultId, scope.vaultId),
  );
}

function assertHash(bytes: Uint8Array | null, hash: string | null) {
  return bytes !== null && hash !== null && hashBytes(bytes) === hash;
}

function statusFromRow(
  row: TranscriptRow,
): PrivateVaultBrokerReplacementStatus {
  const phase = phaseSchema.safeParse(row.phase);
  const offer = decode(row.offerBytesBase64url, OFFER_MAX_BYTES);
  const challenge = decode(row.challengeBytesBase64url, CHALLENGE_MAX_BYTES);
  const sas = decode(row.sasBytesBase64url, SAS_MAX_BYTES);
  const authorization = decode(
    row.authorizationBytesBase64url,
    AUTHORIZATION_MAX_BYTES,
  );
  const approval = decode(row.approvalBytesBase64url, APPROVAL_MAX_BYTES);
  const drainAttestation = decode(
    row.drainAttestationBytesBase64url,
    DRAIN_ATTESTATION_MAX_BYTES,
  );
  const rotationReceipt = decode(
    row.rotationReceiptBytesBase64url,
    ROTATION_RECEIPT_MAX_BYTES,
  );
  if (
    !phase.success ||
    !offer ||
    hashBytes(offer) !== row.offerHash ||
    ((challenge !== null || row.challengeHash !== null) &&
      !assertHash(challenge, row.challengeHash)) ||
    ((sas !== null || row.sasHash !== null) && !assertHash(sas, row.sasHash)) ||
    ((authorization !== null || row.authorizationHash !== null) &&
      !assertHash(authorization, row.authorizationHash)) ||
    ((approval !== null || row.approvalHash !== null) &&
      !assertHash(approval, row.approvalHash)) ||
    ((drainAttestation !== null || row.drainAttestationHash !== null) &&
      !assertHash(drainAttestation, row.drainAttestationHash)) ||
    ((rotationReceipt !== null || row.rotationReceiptHash !== null) &&
      !assertHash(rotationReceipt, row.rotationReceiptHash))
  ) {
    throw new PrivateVaultBrokerReplacementError("unavailable");
  }
  return {
    transcriptId: row.transcriptId,
    phase: phase.data,
    oldBrokerEndpointId: row.oldBrokerEndpointId,
    newBrokerEndpointId: row.newBrokerEndpointId,
    authorizerEndpointId: row.authorizerEndpointId,
    offerHash: row.offerHash,
    offer,
    challengeHash: row.challengeHash,
    challenge,
    sasHash: row.sasHash,
    sas,
    authorizationHash: row.authorizationHash,
    authorization,
    approvalHash: row.approvalHash,
    approval,
    drainId: row.drainId,
    drainGeneration: row.drainGeneration,
    drainTotalCount: row.drainTotalCount,
    drainCompletedCount: row.drainCompletedCount,
    drainFailedCount: row.drainFailedCount,
    drainCancelledCount: row.drainCancelledCount,
    drainDigest: row.drainDigest,
    drainAttestationHash: row.drainAttestationHash,
    drainAttestation,
    rotationControlEntryId: row.rotationControlEntryId,
    rotationControlEntryHash: row.rotationControlEntryHash,
    rotationControlSequence: row.rotationControlSequence,
    rotationReceiptHash: row.rotationReceiptHash,
    rotationReceipt,
    expiresAt: row.expiresAt,
  };
}

function bindingsMatch(
  status: PrivateVaultBrokerReplacementStatus,
  bindings: PrivateVaultBrokerReplacementBindings,
) {
  return (
    status.oldBrokerEndpointId === bindings.oldBrokerEndpointId &&
    status.newBrokerEndpointId === bindings.newBrokerEndpointId &&
    status.authorizerEndpointId === bindings.authorizerEndpointId
  );
}

function expectedPhase(
  to: AdvanceInput["to"],
): PrivateVaultBrokerReplacementPhase {
  switch (to) {
    case "challenge":
      return "offer";
    case "candidate_confirmed":
      return "challenge";
    case "authorized":
      return "candidate_confirmed";
    case "draining":
      return "authorized";
    case "drained":
      return "draining";
    case "rotation_committed":
      return "drained";
    case "activated":
      return "rotation_committed";
    default:
      return "offer";
  }
}

function updateFor(input: AdvanceInput, at: string): Partial<TranscriptRow> {
  switch (input.to) {
    case "challenge": {
      const bytes = bounded(input.challenge, CHALLENGE_MAX_BYTES);
      return {
        phase: input.to,
        challengeHash: hashBytes(bytes),
        challengeBytesBase64url: encode(bytes),
        challengedAt: at,
      };
    }
    case "candidate_confirmed": {
      const bytes = bounded(input.sas, SAS_MAX_BYTES);
      return {
        phase: input.to,
        sasHash: hashBytes(bytes),
        sasBytesBase64url: encode(bytes),
        candidateConfirmedAt: at,
      };
    }
    case "authorized": {
      const authorization = bounded(
        input.authorization,
        AUTHORIZATION_MAX_BYTES,
      );
      const approval = bounded(input.approval, APPROVAL_MAX_BYTES);
      return {
        phase: input.to,
        authorizationHash: hashBytes(authorization),
        authorizationBytesBase64url: encode(authorization),
        approvalHash: hashBytes(approval),
        approvalBytesBase64url: encode(approval),
        authorizedAt: at,
      };
    }
    case "draining":
      return {
        phase: input.to,
        drainId: input.drainId,
        drainGeneration: input.drainGeneration,
        drainingAt: at,
      };
    case "drained": {
      if (
        input.completedCount + input.failedCount + input.cancelledCount !==
        input.totalCount
      ) {
        throw new PrivateVaultBrokerReplacementError("invalid_request");
      }
      const attestation = bounded(
        input.signedDrainAttestation,
        DRAIN_ATTESTATION_MAX_BYTES,
      );
      return {
        phase: input.to,
        drainTotalCount: input.totalCount,
        drainCompletedCount: input.completedCount,
        drainFailedCount: input.failedCount,
        drainCancelledCount: input.cancelledCount,
        drainDigest: input.drainDigest,
        drainAttestationHash: hashBytes(attestation),
        drainAttestationBytesBase64url: encode(attestation),
        drainedAt: at,
      };
    }
    case "rotation_committed": {
      const receipt = bounded(
        input.rotationReceipt,
        ROTATION_RECEIPT_MAX_BYTES,
      );
      return {
        phase: input.to,
        rotationControlEntryId: input.controlEntryId,
        rotationControlEntryHash: input.controlEntryHash,
        rotationControlSequence: input.controlSequence,
        rotationReceiptHash: hashBytes(receipt),
        rotationReceiptBytesBase64url: encode(receipt),
        rotationCommittedAt: at,
      };
    }
    case "activated":
      return { phase: input.to, activeKey: null, activatedAt: at };
    default:
      return {
        phase: input.to,
        activeKey: null,
        terminatedAt: at,
      };
  }
}

function exactUpdate(row: TranscriptRow, update: Partial<TranscriptRow>) {
  return Object.entries(update).every(
    ([key, value]) => row[key as keyof TranscriptRow] === value,
  );
}

export function createPrivateVaultBrokerReplacementTranscriptService(
  options: { now?: () => Date } = {},
) {
  const now = options.now ?? (() => new Date());

  const read = async (
    scopeInput: PrivateVaultBrokerReplacementScope,
    transcriptIdInput: string,
  ) => {
    const scope = normalizeScope(scopeInput);
    const transcriptId = identifierSchema.parse(transcriptIdInput);
    const [row] = await getDb()
      .select()
      .from(schema.contentEncryptedVaultBrokerReplacementTranscripts)
      .where(scoped(scope, transcriptId))
      .limit(1);
    if (!row) throw new PrivateVaultBrokerReplacementError("not_found");
    return statusFromRow(row);
  };

  return {
    read,
    async establish(
      scopeInput: PrivateVaultBrokerReplacementScope,
      inputValue: z.input<typeof establishSchema>,
    ) {
      const scope = normalizeScope(scopeInput);
      const input = establishSchema.parse(inputValue);
      const at = now();
      const offer = bounded(input.offer, OFFER_MAX_BYTES);
      if (Date.parse(input.expiresAt) <= at.getTime()) {
        throw new PrivateVaultBrokerReplacementError("expired");
      }
      const row = {
        id: internalId(scope, input.transcriptId),
        transcriptId: input.transcriptId,
        ...scope,
        oldBrokerEndpointId: input.bindings.oldBrokerEndpointId,
        newBrokerEndpointId: input.bindings.newBrokerEndpointId,
        authorizerEndpointId: input.bindings.authorizerEndpointId,
        phase: "offer",
        activeKey: activeKey(scope, input.bindings.oldBrokerEndpointId),
        offerHash: hashBytes(offer),
        offerBytesBase64url: encode(offer),
        expiresAt: input.expiresAt,
        offeredAt: at.toISOString(),
        createdAt: at.toISOString(),
        updatedAt: at.toISOString(),
      } as const;
      try {
        return await getDb().transaction(async (tx) => {
          const [vault] = await tx
            .select({ vaultId: schema.contentEncryptedVaults.vaultId })
            .from(schema.contentEncryptedVaults)
            .where(
              and(
                eq(schema.contentEncryptedVaults.ownerEmail, scope.ownerEmail),
                eq(schema.contentEncryptedVaults.accountId, scope.accountId),
                eq(schema.contentEncryptedVaults.orgId, scope.orgId),
                eq(
                  schema.contentEncryptedVaults.workspaceId,
                  scope.workspaceId,
                ),
                eq(schema.contentEncryptedVaults.vaultId, scope.vaultId),
                eq(schema.contentEncryptedVaults.vaultState, "active"),
              ),
            )
            .limit(1);
          if (!vault) {
            throw new PrivateVaultBrokerReplacementError("not_found");
          }
          const endpoints = await tx
            .select({
              endpointId: schema.contentEncryptedVaultEndpoints.endpointId,
            })
            .from(schema.contentEncryptedVaultEndpoints)
            .where(
              and(
                eq(
                  schema.contentEncryptedVaultEndpoints.ownerEmail,
                  scope.ownerEmail,
                ),
                eq(schema.contentEncryptedVaultEndpoints.orgId, scope.orgId),
                eq(
                  schema.contentEncryptedVaultEndpoints.vaultId,
                  scope.vaultId,
                ),
                eq(
                  schema.contentEncryptedVaultEndpoints.endpointState,
                  "online",
                ),
                inArray(schema.contentEncryptedVaultEndpoints.endpointId, [
                  input.bindings.oldBrokerEndpointId,
                  input.bindings.authorizerEndpointId,
                  input.bindings.newBrokerEndpointId,
                ]),
              ),
            );
          const found = new Set(endpoints.map(({ endpointId }) => endpointId));
          if (
            !found.has(input.bindings.oldBrokerEndpointId) ||
            !found.has(input.bindings.authorizerEndpointId) ||
            found.has(input.bindings.newBrokerEndpointId)
          ) {
            throw new PrivateVaultBrokerReplacementError("conflict");
          }
          await tx
            .insert(schema.contentEncryptedVaultBrokerReplacementTranscripts)
            .values(row)
            .onConflictDoNothing();
          const [stored] = await tx
            .select()
            .from(schema.contentEncryptedVaultBrokerReplacementTranscripts)
            .where(scoped(scope, input.transcriptId))
            .limit(1);
          if (!stored || !exactUpdate(stored, row)) {
            throw new PrivateVaultBrokerReplacementError("conflict");
          }
          return statusFromRow(stored);
        });
      } catch (error) {
        if (error instanceof PrivateVaultBrokerReplacementError) throw error;
        throw new PrivateVaultBrokerReplacementError("conflict");
      }
    },
    async advance(
      scopeInput: PrivateVaultBrokerReplacementScope,
      transcriptIdInput: string,
      inputValue: z.input<typeof advanceSchema>,
    ) {
      const scope = normalizeScope(scopeInput);
      const transcriptId = identifierSchema.parse(transcriptIdInput);
      const input = advanceSchema.parse(inputValue);
      const at = now();
      return getDb().transaction(async (tx) => {
        const [row] = await tx
          .select()
          .from(schema.contentEncryptedVaultBrokerReplacementTranscripts)
          .where(scoped(scope, transcriptId))
          .limit(1);
        if (!row) throw new PrivateVaultBrokerReplacementError("not_found");
        const status = statusFromRow(row);
        if (
          !bindingsMatch(status, input.bindings) ||
          status.offerHash !== input.offerHash
        ) {
          throw new PrivateVaultBrokerReplacementError("conflict");
        }
        if (status.phase === input.to) {
          const retryUpdate = {
            ...updateFor(input, row.updatedAt),
            updatedAt: row.updatedAt,
          };
          if (exactUpdate(row, retryUpdate)) return status;
          throw new PrivateVaultBrokerReplacementError("conflict");
        }
        if (terminalPhases.has(status.phase)) {
          throw new PrivateVaultBrokerReplacementError("conflict");
        }
        const beforeDrain =
          status.phase === "offer" ||
          status.phase === "challenge" ||
          status.phase === "candidate_confirmed" ||
          status.phase === "authorized";
        if (input.to === "expired") {
          if (!beforeDrain || at.getTime() < Date.parse(status.expiresAt)) {
            throw new PrivateVaultBrokerReplacementError("conflict");
          }
        } else if (
          beforeDrain &&
          at.getTime() >= Date.parse(status.expiresAt)
        ) {
          throw new PrivateVaultBrokerReplacementError("expired");
        }
        if (
          input.to !== "rejected" &&
          input.to !== "expired" &&
          input.to !== "aborted" &&
          status.phase !== expectedPhase(input.to)
        ) {
          throw new PrivateVaultBrokerReplacementError("conflict");
        }
        if (
          (input.to === "rejected" &&
            status.phase !== "offer" &&
            status.phase !== "challenge" &&
            status.phase !== "candidate_confirmed") ||
          (input.to === "aborted" &&
            status.phase !== "authorized" &&
            status.phase !== "draining" &&
            status.phase !== "drained")
        ) {
          throw new PrivateVaultBrokerReplacementError("conflict");
        }
        const hasBindingConflict =
          (input.to === "candidate_confirmed" &&
            input.challengeHash !== status.challengeHash) ||
          (input.to === "authorized" && input.sasHash !== status.sasHash) ||
          (input.to === "draining" &&
            input.approvalHash !== status.approvalHash) ||
          (input.to === "drained" &&
            (input.drainId !== status.drainId ||
              input.drainGeneration !== status.drainGeneration)) ||
          (input.to === "rotation_committed" &&
            input.drainAttestationHash !== status.drainAttestationHash) ||
          (input.to === "activated" &&
            (input.controlEntryId !== status.rotationControlEntryId ||
              input.controlEntryHash !== status.rotationControlEntryHash ||
              input.controlSequence !== status.rotationControlSequence ||
              input.rotationReceiptHash !== status.rotationReceiptHash));
        if (hasBindingConflict) {
          throw new PrivateVaultBrokerReplacementError("conflict");
        }
        const update = {
          ...updateFor(input, at.toISOString()),
          updatedAt: at.toISOString(),
        };
        const [updated] = await tx
          .update(schema.contentEncryptedVaultBrokerReplacementTranscripts)
          .set(update)
          .where(
            and(
              scoped(scope, transcriptId),
              eq(
                schema.contentEncryptedVaultBrokerReplacementTranscripts.phase,
                status.phase,
              ),
            ),
          )
          .returning();
        if (!updated) {
          throw new PrivateVaultBrokerReplacementError("conflict");
        }
        return statusFromRow(updated);
      });
    },
  };
}

export const privateVaultBrokerReplacementLimits = Object.freeze({
  offerBytes: OFFER_MAX_BYTES,
  challengeBytes: CHALLENGE_MAX_BYTES,
  sasBytes: SAS_MAX_BYTES,
  authorizationBytes: AUTHORIZATION_MAX_BYTES,
  approvalBytes: APPROVAL_MAX_BYTES,
  drainAttestationBytes: DRAIN_ATTESTATION_MAX_BYTES,
  rotationReceiptBytes: ROTATION_RECEIPT_MAX_BYTES,
});
