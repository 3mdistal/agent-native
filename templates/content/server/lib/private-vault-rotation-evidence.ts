import { createHash } from "node:crypto";

import {
  ANC_V1_CONTROL_LOG_APPEND_RECOVERY_WRAP_MAX_BYTES,
  ANC_V1_CONTROL_LOG_APPEND_REQUEST_MAX_BYTES,
  ANC_V1_CONTROL_LOG_APPEND_SIGNED_ENTRY_MAX_BYTES,
  decodeAncV1ControlLogRotationAppendRequest,
  encodeAncV1ControlLogRotationAppendRequest,
} from "@agent-native/core/e2ee";
import {
  deleteEncryptedPrivateBlob,
  putEncryptedPrivateBlob,
  readEncryptedPrivateBlob,
  type PrivateBlobHandle,
} from "@agent-native/core/private-blob";
import { and, asc, eq, inArray, lte, ne } from "drizzle-orm";
import { z } from "zod";

import { getDb, schema } from "../db/index.js";

const EVIDENCE_MAX_BYTES = 1_024;
const EEK_WRAP_MAX_BYTES = 2_048;
const MAX_RECIPIENTS = 64;
const TERMINAL_RETENTION_MILLISECONDS = 90 * 24 * 60 * 60 * 1_000;

const identifierSchema = z.string().trim().min(1).max(512);
const opaqueIdSchema = z.string().regex(/^[0-9a-f]{32}$/);
const scopeSchema = z
  .object({
    ownerEmail: z.string().trim().email().max(320),
    accountId: identifierSchema,
    orgId: z.string().trim().max(512),
    workspaceId: identifierSchema,
    vaultId: identifierSchema,
  })
  .strict();

export interface PrivateVaultRotationEvidenceScope {
  ownerEmail: string;
  accountId: string;
  orgId: string;
  workspaceId: string;
  vaultId: string;
}

export type PrivateVaultRotationEvidencePhase =
  | "collecting_offers"
  | "awaiting_acknowledgements"
  | "awaiting_destructions"
  | "awaiting_hosted_receipt"
  | "awaiting_completion"
  | "completed";

export interface PrivateVaultRotationRecipientEvidence {
  readonly recipientEndpointId: string;
  readonly offer: Uint8Array;
  readonly eekWrap: Uint8Array;
  readonly acknowledgement: Uint8Array | null;
  readonly destructionAttestation: Uint8Array | null;
}

export interface PrivateVaultRotationEvidenceStatus {
  readonly ceremonyId: string;
  readonly phase: PrivateVaultRotationEvidencePhase;
  readonly expectedRecipientCount: number;
  readonly checkpoint: Uint8Array;
  readonly controlBundle: {
    readonly signedEntrySha256: string;
    readonly signedEntryByteLength: number;
    readonly recoveryWrapSha256: string;
    readonly recoveryWrapByteLength: number;
    readonly bundleSha256: string;
    readonly bundleByteLength: number;
  } | null;
  readonly recipients: readonly PrivateVaultRotationRecipientEvidence[];
  readonly hostedReceipt: Uint8Array | null;
  readonly completionAttestation: Uint8Array | null;
  readonly terminalAt: string | null;
  readonly purgeEligibleAt: string | null;
}

export class PrivateVaultRotationEvidenceError extends Error {
  constructor(
    readonly code: "invalid_request" | "not_found" | "conflict" | "unavailable",
  ) {
    super("Private Vault rotation evidence unavailable");
    this.name = "PrivateVaultRotationEvidenceError";
  }
}

type ArtifactRow =
  typeof schema.contentEncryptedVaultRotationEvidenceArtifacts.$inferSelect;
type DbTransaction = Parameters<
  Parameters<ReturnType<typeof getDb>["transaction"]>[0]
>[0];

function normalizeScope(input: PrivateVaultRotationEvidenceScope) {
  try {
    const value = scopeSchema.parse(input);
    return { ...value, ownerEmail: value.ownerEmail.toLowerCase() };
  } catch {
    throw new PrivateVaultRotationEvidenceError("invalid_request");
  }
}

function opaqueId(value: unknown): string {
  const result = opaqueIdSchema.safeParse(value);
  if (!result.success)
    throw new PrivateVaultRotationEvidenceError("invalid_request");
  return result.data;
}

const ARTIFACT_KINDS = [
  "ceremony",
  "checkpoint",
  "control_bundle",
  "recipient_offer",
  "recipient_acknowledgement",
  "destruction_attestation",
  "hosted_receipt",
  "completion_attestation",
] as const;

function hasOnlyNullMetadata(row: ArtifactRow): boolean {
  return (
    row.expectedRecipientCount === null &&
    row.phase === null &&
    row.terminalAt === null &&
    row.purgeEligibleAt === null
  );
}

function hasOnlyNullBlobMetadata(row: ArtifactRow): boolean {
  return (
    row.privateBlobHandleJson === null &&
    row.privateBlobSha256 === null &&
    row.privateBlobByteLength === null &&
    row.bundleSha256 === null &&
    row.signedEntrySha256 === null &&
    row.signedEntryByteLength === null &&
    row.recoveryWrapSha256 === null &&
    row.recoveryWrapByteLength === null
  );
}

function validateArtifactRow(row: ArtifactRow): void {
  if (
    row.formatVersion !== 1 ||
    !ARTIFACT_KINDS.includes(
      row.artifactKind as (typeof ARTIFACT_KINDS)[number],
    )
  )
    throw new PrivateVaultRotationEvidenceError("unavailable");

  const isCeremony =
    row.artifactKind === "ceremony" &&
    row.artifactKey === "ceremony" &&
    row.recipientEndpointId === null &&
    row.evidenceBytesBase64url === null &&
    row.eekWrapBytesBase64url === null &&
    hasOnlyNullBlobMetadata(row);
  const isCheckpoint =
    row.artifactKind === "checkpoint" &&
    row.artifactKey === "singleton" &&
    row.recipientEndpointId === null &&
    row.evidenceBytesBase64url !== null &&
    row.eekWrapBytesBase64url === null &&
    hasOnlyNullMetadata(row) &&
    hasOnlyNullBlobMetadata(row);
  const isControlBundle =
    row.artifactKind === "control_bundle" &&
    row.artifactKey === "singleton" &&
    row.recipientEndpointId === null &&
    row.evidenceBytesBase64url === null &&
    row.eekWrapBytesBase64url === null &&
    row.privateBlobHandleJson !== null &&
    row.privateBlobSha256 !== null &&
    row.privateBlobByteLength !== null &&
    row.bundleSha256 !== null &&
    row.signedEntrySha256 !== null &&
    row.signedEntryByteLength !== null &&
    row.recoveryWrapSha256 !== null &&
    row.recoveryWrapByteLength !== null &&
    hasOnlyNullMetadata(row);
  const isRecipient =
    (row.artifactKind === "recipient_offer" ||
      row.artifactKind === "recipient_acknowledgement" ||
      row.artifactKind === "destruction_attestation") &&
    row.recipientEndpointId !== null &&
    row.artifactKey === row.recipientEndpointId &&
    row.evidenceBytesBase64url !== null &&
    (row.artifactKind === "recipient_offer"
      ? row.eekWrapBytesBase64url !== null
      : row.eekWrapBytesBase64url === null) &&
    hasOnlyNullMetadata(row) &&
    hasOnlyNullBlobMetadata(row);
  const isSingleton =
    (row.artifactKind === "hosted_receipt" ||
      row.artifactKind === "completion_attestation") &&
    row.artifactKey === "singleton" &&
    row.recipientEndpointId === null &&
    row.evidenceBytesBase64url !== null &&
    row.eekWrapBytesBase64url === null &&
    hasOnlyNullMetadata(row) &&
    hasOnlyNullBlobMetadata(row);
  if (
    !isCeremony &&
    !isCheckpoint &&
    !isControlBundle &&
    !isRecipient &&
    !isSingleton
  )
    throw new PrivateVaultRotationEvidenceError("unavailable");
}

function bounded(value: unknown, maximum: number): Uint8Array {
  if (
    !(value instanceof Uint8Array) ||
    value.byteLength < 1 ||
    value.byteLength > maximum
  )
    throw new PrivateVaultRotationEvidenceError("invalid_request");
  return value.slice();
}

function encode(value: Uint8Array): string {
  return Buffer.from(value).toString("base64url");
}

function decode(value: string | null, maximum: number): Uint8Array | null {
  if (value === null || !/^[A-Za-z0-9_-]+$/.test(value)) return null;
  const bytes = Uint8Array.from(Buffer.from(value, "base64url"));
  if (
    bytes.byteLength < 1 ||
    bytes.byteLength > maximum ||
    Buffer.from(bytes).toString("base64url") !== value
  )
    return null;
  return bytes;
}

function exact(left: Uint8Array, right: Uint8Array): boolean {
  return (
    left.byteLength === right.byteLength &&
    left.every((byte, index) => byte === right[index])
  );
}

function sha256(value: Uint8Array): string {
  return createHash("sha256").update(value).digest("hex");
}

function parseBlobHandle(value: string | null): PrivateBlobHandle | null {
  if (!value || value.length > 16_384) return null;
  try {
    const handle = JSON.parse(value) as PrivateBlobHandle;
    return handle &&
      handle.opaque === true &&
      handle.encrypted === true &&
      typeof handle.id === "string" &&
      handle.id.length > 0 &&
      typeof handle.provider === "string" &&
      handle.provider.length > 0
      ? handle
      : null;
  } catch {
    return null;
  }
}

function scopeWhere(
  table: typeof schema.contentEncryptedVaultRotationEvidenceArtifacts,
  scope: ReturnType<typeof normalizeScope>,
) {
  return and(
    eq(table.ownerEmail, scope.ownerEmail),
    eq(table.accountId, scope.accountId),
    eq(table.orgId, scope.orgId),
    eq(table.workspaceId, scope.workspaceId),
    eq(table.vaultId, scope.vaultId),
  );
}

function ceremonyWhere(
  scope: ReturnType<typeof normalizeScope>,
  ceremonyId: string,
) {
  const table = schema.contentEncryptedVaultRotationEvidenceArtifacts;
  return and(scopeWhere(table, scope), eq(table.ceremonyId, ceremonyId));
}

function rowId(
  scope: ReturnType<typeof normalizeScope>,
  ceremonyId: string,
  kind: string,
  key: string,
) {
  return createHash("sha256")
    .update(
      [
        scope.ownerEmail,
        scope.accountId,
        scope.orgId,
        scope.workspaceId,
        scope.vaultId,
        ceremonyId,
        kind,
        key,
      ].join("\0"),
    )
    .digest("hex");
}

async function rowsFor(
  tx: DbTransaction,
  scope: ReturnType<typeof normalizeScope>,
  ceremonyId: string,
) {
  return tx
    .select()
    .from(schema.contentEncryptedVaultRotationEvidenceArtifacts)
    .where(ceremonyWhere(scope, ceremonyId))
    .orderBy(
      asc(
        schema.contentEncryptedVaultRotationEvidenceArtifacts
          .recipientEndpointId,
      ),
      asc(schema.contentEncryptedVaultRotationEvidenceArtifacts.artifactKind),
    );
}

function metadata(rows: readonly ArtifactRow[]): ArtifactRow {
  const row = rows.find(
    (candidate) =>
      candidate.artifactKind === "ceremony" &&
      candidate.artifactKey === "ceremony",
  );
  if (!row) throw new PrivateVaultRotationEvidenceError("not_found");
  return row;
}

function parseRows(
  rows: readonly ArtifactRow[],
): PrivateVaultRotationEvidenceStatus {
  for (const row of rows) validateArtifactRow(row);
  const ceremony = metadata(rows);
  const phases: readonly PrivateVaultRotationEvidencePhase[] = [
    "collecting_offers",
    "awaiting_acknowledgements",
    "awaiting_destructions",
    "awaiting_hosted_receipt",
    "awaiting_completion",
    "completed",
  ];
  if (
    !phases.includes(ceremony.phase as PrivateVaultRotationEvidencePhase) ||
    !Number.isSafeInteger(ceremony.expectedRecipientCount) ||
    ceremony.expectedRecipientCount! < 1 ||
    ceremony.expectedRecipientCount! > MAX_RECIPIENTS ||
    ceremony.evidenceBytesBase64url !== null ||
    ceremony.eekWrapBytesBase64url !== null ||
    ceremony.recipientEndpointId !== null
  )
    throw new PrivateVaultRotationEvidenceError("unavailable");
  const checkpointRows = rows.filter(
    (row) => row.artifactKind === "checkpoint",
  );
  const checkpoint =
    checkpointRows.length === 1
      ? decode(checkpointRows[0]!.evidenceBytesBase64url, EVIDENCE_MAX_BYTES)
      : null;
  if (!checkpoint) throw new PrivateVaultRotationEvidenceError("unavailable");
  const controlRows = rows.filter(
    (row) => row.artifactKind === "control_bundle",
  );
  const controlRow = controlRows.length === 1 ? controlRows[0]! : null;
  const controlBundle = controlRow
    ? parseBlobHandle(controlRow.privateBlobHandleJson) &&
      /^[0-9a-f]{64}$/.test(controlRow.privateBlobSha256 ?? "") &&
      Number.isSafeInteger(controlRow.privateBlobByteLength) &&
      controlRow.privateBlobByteLength! > 0 &&
      controlRow.privateBlobByteLength! <=
        ANC_V1_CONTROL_LOG_APPEND_REQUEST_MAX_BYTES &&
      controlRow.privateBlobSha256 === controlRow.bundleSha256 &&
      /^[0-9a-f]{64}$/.test(controlRow.bundleSha256 ?? "") &&
      /^[0-9a-f]{64}$/.test(controlRow.signedEntrySha256 ?? "") &&
      Number.isSafeInteger(controlRow.signedEntryByteLength) &&
      controlRow.signedEntryByteLength! > 0 &&
      controlRow.signedEntryByteLength! <=
        ANC_V1_CONTROL_LOG_APPEND_SIGNED_ENTRY_MAX_BYTES &&
      /^[0-9a-f]{64}$/.test(controlRow.recoveryWrapSha256 ?? "") &&
      Number.isSafeInteger(controlRow.recoveryWrapByteLength) &&
      controlRow.recoveryWrapByteLength! > 0 &&
      controlRow.recoveryWrapByteLength! <=
        ANC_V1_CONTROL_LOG_APPEND_RECOVERY_WRAP_MAX_BYTES
      ? Object.freeze({
          signedEntrySha256: controlRow.signedEntrySha256!,
          signedEntryByteLength: controlRow.signedEntryByteLength!,
          recoveryWrapSha256: controlRow.recoveryWrapSha256!,
          recoveryWrapByteLength: controlRow.recoveryWrapByteLength!,
          bundleSha256: controlRow.bundleSha256!,
          bundleByteLength: controlRow.privateBlobByteLength!,
        })
      : null
    : null;
  if (controlRows.length > 1 || (controlRow && !controlBundle))
    throw new PrivateVaultRotationEvidenceError("unavailable");

  const offers = new Map<
    string,
    {
      recipientEndpointId: string;
      offer: Uint8Array;
      eekWrap: Uint8Array;
      acknowledgement: Uint8Array | null;
      destructionAttestation: Uint8Array | null;
    }
  >();
  for (const row of rows) {
    if (row.artifactKind !== "recipient_offer") continue;
    const recipient = row.recipientEndpointId;
    const offer = decode(row.evidenceBytesBase64url, EVIDENCE_MAX_BYTES);
    const eekWrap = decode(row.eekWrapBytesBase64url, EEK_WRAP_MAX_BYTES);
    if (!recipient || offers.has(recipient) || !offer || !eekWrap)
      throw new PrivateVaultRotationEvidenceError("unavailable");
    offers.set(recipient, {
      recipientEndpointId: recipient,
      offer,
      eekWrap,
      acknowledgement: null,
      destructionAttestation: null,
    });
  }
  const attach = (
    kind: "recipient_acknowledgement" | "destruction_attestation",
    field: "acknowledgement" | "destructionAttestation",
  ) => {
    for (const row of rows) {
      if (row.artifactKind !== kind) continue;
      const recipient = row.recipientEndpointId;
      const value = decode(row.evidenceBytesBase64url, EVIDENCE_MAX_BYTES);
      const target = recipient ? offers.get(recipient) : undefined;
      if (!target || !value || target[field] !== null)
        throw new PrivateVaultRotationEvidenceError("unavailable");
      target[field] = value;
    }
  };
  attach("recipient_acknowledgement", "acknowledgement");
  attach("destruction_attestation", "destructionAttestation");
  const receiptRows = rows.filter(
    (row) => row.artifactKind === "hosted_receipt",
  );
  const completionRows = rows.filter(
    (row) => row.artifactKind === "completion_attestation",
  );
  const hostedReceipt =
    receiptRows.length === 0
      ? null
      : receiptRows.length === 1
        ? decode(receiptRows[0]!.evidenceBytesBase64url, EVIDENCE_MAX_BYTES)
        : null;
  const completionAttestation =
    completionRows.length === 0
      ? null
      : completionRows.length === 1
        ? decode(completionRows[0]!.evidenceBytesBase64url, EVIDENCE_MAX_BYTES)
        : null;
  if (
    (receiptRows.length > 0 && !hostedReceipt) ||
    (completionRows.length > 0 && !completionAttestation)
  )
    throw new PrivateVaultRotationEvidenceError("unavailable");

  const recipients = [...offers.values()].sort((left, right) =>
    left.recipientEndpointId.localeCompare(right.recipientEndpointId),
  );
  const acknowledgements = recipients.filter(
    (value) => value.acknowledgement !== null,
  ).length;
  const destructions = recipients.filter(
    (value) => value.destructionAttestation !== null,
  ).length;
  const expected = ceremony.expectedRecipientCount!;
  const phase = ceremony.phase as PrivateVaultRotationEvidencePhase;
  const structurallyValid =
    (phase === "collecting_offers" &&
      recipients.length < expected &&
      acknowledgements === 0 &&
      destructions === 0 &&
      !hostedReceipt &&
      !completionAttestation) ||
    (phase === "awaiting_acknowledgements" &&
      recipients.length === expected &&
      acknowledgements < expected &&
      destructions === 0 &&
      !hostedReceipt &&
      !completionAttestation) ||
    (phase === "awaiting_destructions" &&
      recipients.length === expected &&
      acknowledgements === expected &&
      destructions < expected &&
      !hostedReceipt &&
      !completionAttestation) ||
    (phase === "awaiting_hosted_receipt" &&
      recipients.length === expected &&
      acknowledgements === expected &&
      destructions === expected &&
      !hostedReceipt &&
      !completionAttestation) ||
    (phase === "awaiting_completion" &&
      recipients.length === expected &&
      acknowledgements === expected &&
      destructions === expected &&
      !!hostedReceipt &&
      !completionAttestation) ||
    (phase === "completed" &&
      recipients.length === expected &&
      acknowledgements === expected &&
      destructions === expected &&
      !!hostedReceipt &&
      !!completionAttestation &&
      ceremony.terminalAt !== null &&
      ceremony.purgeEligibleAt !== null);
  if (
    !structurallyValid ||
    (phase !== "completed" &&
      (ceremony.terminalAt !== null || ceremony.purgeEligibleAt !== null))
  )
    throw new PrivateVaultRotationEvidenceError("unavailable");
  return Object.freeze({
    ceremonyId: ceremony.ceremonyId,
    phase,
    expectedRecipientCount: expected,
    checkpoint,
    controlBundle,
    recipients: Object.freeze(recipients),
    hostedReceipt,
    completionAttestation,
    terminalAt: ceremony.terminalAt,
    purgeEligibleAt: ceremony.purgeEligibleAt,
  });
}

async function requireVaultScope(
  tx: DbTransaction,
  scope: ReturnType<typeof normalizeScope>,
) {
  const table = schema.contentEncryptedVaults;
  const [vault] = await tx
    .select({ vaultId: table.vaultId })
    .from(table)
    .where(
      and(
        eq(table.vaultId, scope.vaultId),
        eq(table.ownerEmail, scope.ownerEmail),
        eq(table.accountId, scope.accountId),
        eq(table.orgId, scope.orgId),
        eq(table.workspaceId, scope.workspaceId),
      ),
    )
    .limit(1);
  if (!vault) throw new PrivateVaultRotationEvidenceError("not_found");
}

export function createPrivateVaultRotationEvidenceStore(input?: {
  now?: () => Date;
  blobs?: {
    put: typeof putEncryptedPrivateBlob;
    read: typeof readEncryptedPrivateBlob;
    delete: typeof deleteEncryptedPrivateBlob;
  };
}) {
  const now = input?.now ?? (() => new Date());
  const blobs = input?.blobs ?? {
    put: putEncryptedPrivateBlob,
    read: readEncryptedPrivateBlob,
    delete: deleteEncryptedPrivateBlob,
  };

  async function readControlBundle(
    scopeInput: PrivateVaultRotationEvidenceScope,
    ceremonyIdInput: string,
  ) {
    const scope = normalizeScope(scopeInput);
    const ceremonyId = opaqueId(ceremonyIdInput);
    const rows = await getDb().transaction((tx) =>
      rowsFor(tx, scope, ceremonyId),
    );
    const status = parseRows(rows);
    const row = rows.find((value) => value.artifactKind === "control_bundle");
    if (!row || !status.controlBundle)
      throw new PrivateVaultRotationEvidenceError("not_found");
    const handle = parseBlobHandle(row.privateBlobHandleJson);
    if (!handle) throw new PrivateVaultRotationEvidenceError("unavailable");
    let encodedBundle: Uint8Array;
    try {
      const result = await blobs.read(handle);
      encodedBundle = bounded(
        result.data,
        ANC_V1_CONTROL_LOG_APPEND_REQUEST_MAX_BYTES,
      );
    } catch {
      throw new PrivateVaultRotationEvidenceError("unavailable");
    }
    if (
      encodedBundle.byteLength !== status.controlBundle.bundleByteLength ||
      sha256(encodedBundle) !== status.controlBundle.bundleSha256
    )
      throw new PrivateVaultRotationEvidenceError("unavailable");
    let bundle: ReturnType<typeof decodeAncV1ControlLogRotationAppendRequest>;
    try {
      bundle = decodeAncV1ControlLogRotationAppendRequest(encodedBundle);
    } catch {
      throw new PrivateVaultRotationEvidenceError("unavailable");
    }
    if (
      bundle.signedEntry.byteLength !==
        status.controlBundle.signedEntryByteLength ||
      sha256(bundle.signedEntry) !== status.controlBundle.signedEntrySha256 ||
      bundle.recoveryWrap.byteLength !==
        status.controlBundle.recoveryWrapByteLength ||
      sha256(bundle.recoveryWrap) !== status.controlBundle.recoveryWrapSha256
    )
      throw new PrivateVaultRotationEvidenceError("unavailable");
    return Object.freeze({
      signedEntry: bundle.signedEntry,
      recoveryWrap: bundle.recoveryWrap,
      bundleSha256: status.controlBundle.bundleSha256,
    });
  }

  async function read(
    scopeInput: PrivateVaultRotationEvidenceScope,
    ceremonyIdInput: string,
  ) {
    const scope = normalizeScope(scopeInput);
    const ceremonyId = opaqueId(ceremonyIdInput);
    return getDb().transaction(async (tx) =>
      parseRows(await rowsFor(tx, scope, ceremonyId)),
    );
  }

  async function putRecipientArtifact(input: {
    scope: PrivateVaultRotationEvidenceScope;
    ceremonyId: string;
    recipientEndpointId: string;
    kind:
      | "recipient_offer"
      | "recipient_acknowledgement"
      | "destruction_attestation";
    evidence: Uint8Array;
    eekWrap?: Uint8Array;
  }) {
    const scope = normalizeScope(input.scope);
    const ceremonyId = opaqueId(input.ceremonyId);
    const recipientEndpointId = opaqueId(input.recipientEndpointId);
    const evidence = bounded(input.evidence, EVIDENCE_MAX_BYTES);
    const eekWrap =
      input.kind === "recipient_offer"
        ? bounded(input.eekWrap, EEK_WRAP_MAX_BYTES)
        : input.eekWrap === undefined
          ? null
          : (() => {
              throw new PrivateVaultRotationEvidenceError("invalid_request");
            })();
    return getDb().transaction(async (tx) => {
      const before = await rowsFor(tx, scope, ceremonyId);
      const ceremony = metadata(before);
      const existing = before.find(
        (row) =>
          row.artifactKind === input.kind &&
          row.artifactKey === recipientEndpointId,
      );
      if (existing) {
        const prior = decode(
          existing.evidenceBytesBase64url,
          EVIDENCE_MAX_BYTES,
        );
        const priorWrap = decode(
          existing.eekWrapBytesBase64url,
          EEK_WRAP_MAX_BYTES,
        );
        if (
          prior &&
          exact(prior, evidence) &&
          ((eekWrap === null && priorWrap === null) ||
            (eekWrap !== null &&
              priorWrap !== null &&
              exact(priorWrap, eekWrap)))
        )
          return parseRows(before);
        throw new PrivateVaultRotationEvidenceError("conflict");
      }
      const expectedPhase =
        input.kind === "recipient_offer"
          ? "collecting_offers"
          : input.kind === "recipient_acknowledgement"
            ? "awaiting_acknowledgements"
            : "awaiting_destructions";
      if (ceremony.phase !== expectedPhase)
        throw new PrivateVaultRotationEvidenceError("conflict");
      if (
        input.kind === "recipient_acknowledgement" &&
        !before.some((row) => row.artifactKind === "control_bundle")
      )
        throw new PrivateVaultRotationEvidenceError("conflict");
      const offer = before.find(
        (row) =>
          row.artifactKind === "recipient_offer" &&
          row.artifactKey === recipientEndpointId,
      );
      const acknowledgement = before.find(
        (row) =>
          row.artifactKind === "recipient_acknowledgement" &&
          row.artifactKey === recipientEndpointId,
      );
      if (
        (input.kind !== "recipient_offer" && !offer) ||
        (input.kind === "destruction_attestation" && !acknowledgement)
      )
        throw new PrivateVaultRotationEvidenceError("conflict");
      const at = now();
      if (!Number.isFinite(at.getTime()))
        throw new PrivateVaultRotationEvidenceError("unavailable");
      await tx
        .insert(schema.contentEncryptedVaultRotationEvidenceArtifacts)
        .values({
          id: rowId(scope, ceremonyId, input.kind, recipientEndpointId),
          ...scope,
          ceremonyId,
          artifactKind: input.kind,
          artifactKey: recipientEndpointId,
          recipientEndpointId,
          evidenceBytesBase64url: encode(evidence),
          eekWrapBytesBase64url: eekWrap ? encode(eekWrap) : null,
          updatedAt: at.toISOString(),
        });
      const afterInsert = await rowsFor(tx, scope, ceremonyId);
      const kindCount = afterInsert.filter(
        (row) => row.artifactKind === input.kind,
      ).length;
      const recipientCount = ceremony.expectedRecipientCount!;
      if (kindCount > recipientCount)
        throw new PrivateVaultRotationEvidenceError("conflict");
      const nextPhase =
        kindCount !== recipientCount
          ? expectedPhase
          : input.kind === "recipient_offer"
            ? "awaiting_acknowledgements"
            : input.kind === "recipient_acknowledgement"
              ? "awaiting_destructions"
              : "awaiting_hosted_receipt";
      if (nextPhase !== expectedPhase) {
        const [updated] = await tx
          .update(schema.contentEncryptedVaultRotationEvidenceArtifacts)
          .set({ phase: nextPhase, updatedAt: at.toISOString() })
          .where(
            and(
              eq(
                schema.contentEncryptedVaultRotationEvidenceArtifacts.id,
                ceremony.id,
              ),
              eq(
                schema.contentEncryptedVaultRotationEvidenceArtifacts.phase,
                expectedPhase,
              ),
            ),
          )
          .returning({
            id: schema.contentEncryptedVaultRotationEvidenceArtifacts.id,
          });
        if (!updated) throw new PrivateVaultRotationEvidenceError("conflict");
      }
      return parseRows(await rowsFor(tx, scope, ceremonyId));
    });
  }

  async function putSingletonArtifact(input: {
    scope: PrivateVaultRotationEvidenceScope;
    ceremonyId: string;
    kind: "hosted_receipt" | "completion_attestation";
    evidence: Uint8Array;
  }) {
    const scope = normalizeScope(input.scope);
    const ceremonyId = opaqueId(input.ceremonyId);
    const evidence = bounded(input.evidence, EVIDENCE_MAX_BYTES);
    return getDb().transaction(async (tx) => {
      const before = await rowsFor(tx, scope, ceremonyId);
      const ceremony = metadata(before);
      const existing = before.find((row) => row.artifactKind === input.kind);
      if (existing) {
        const prior = decode(
          existing.evidenceBytesBase64url,
          EVIDENCE_MAX_BYTES,
        );
        if (prior && exact(prior, evidence)) return parseRows(before);
        throw new PrivateVaultRotationEvidenceError("conflict");
      }
      const expectedPhase =
        input.kind === "hosted_receipt"
          ? "awaiting_hosted_receipt"
          : "awaiting_completion";
      if (ceremony.phase !== expectedPhase)
        throw new PrivateVaultRotationEvidenceError("conflict");
      const at = now();
      if (!Number.isFinite(at.getTime()))
        throw new PrivateVaultRotationEvidenceError("unavailable");
      await tx
        .insert(schema.contentEncryptedVaultRotationEvidenceArtifacts)
        .values({
          id: rowId(scope, ceremonyId, input.kind, "singleton"),
          ...scope,
          ceremonyId,
          artifactKind: input.kind,
          artifactKey: "singleton",
          evidenceBytesBase64url: encode(evidence),
          updatedAt: at.toISOString(),
        });
      const completed = input.kind === "completion_attestation";
      const terminalAt = completed ? at.toISOString() : null;
      const purgeEligibleAt = completed
        ? new Date(at.getTime() + TERMINAL_RETENTION_MILLISECONDS).toISOString()
        : null;
      const [updated] = await tx
        .update(schema.contentEncryptedVaultRotationEvidenceArtifacts)
        .set({
          phase: completed ? "completed" : "awaiting_completion",
          terminalAt,
          purgeEligibleAt,
          updatedAt: at.toISOString(),
        })
        .where(
          and(
            eq(
              schema.contentEncryptedVaultRotationEvidenceArtifacts.id,
              ceremony.id,
            ),
            eq(
              schema.contentEncryptedVaultRotationEvidenceArtifacts.phase,
              expectedPhase,
            ),
          ),
        )
        .returning({
          id: schema.contentEncryptedVaultRotationEvidenceArtifacts.id,
        });
      if (!updated) throw new PrivateVaultRotationEvidenceError("conflict");
      return parseRows(await rowsFor(tx, scope, ceremonyId));
    });
  }

  return {
    read,
    readControlBundle,
    async assertAuthoritativeControlBundle(inputValue: {
      ownerEmail: string;
      orgId: string;
      vaultId: string;
      signedEntry: Uint8Array;
      recoveryWrap: Uint8Array;
      bundleSha256: string;
    }) {
      const signedEntry = bounded(
        inputValue.signedEntry,
        ANC_V1_CONTROL_LOG_APPEND_SIGNED_ENTRY_MAX_BYTES,
      );
      const recoveryWrap = bounded(
        inputValue.recoveryWrap,
        ANC_V1_CONTROL_LOG_APPEND_RECOVERY_WRAP_MAX_BYTES,
      );
      const encodedBundle = encodeAncV1ControlLogRotationAppendRequest({
        version: 1,
        suite: "anc/v1",
        type: "control-log-rotation-append-request",
        signedEntry: Uint8Array.from(signedEntry),
        recoveryWrap: Uint8Array.from(recoveryWrap),
      });
      if (!/^[0-9a-f]{64}$/.test(inputValue.bundleSha256))
        throw new PrivateVaultRotationEvidenceError("invalid_request");
      if (sha256(encodedBundle) !== inputValue.bundleSha256)
        throw new PrivateVaultRotationEvidenceError("conflict");
      const table = schema.contentEncryptedVaultRotationEvidenceArtifacts;
      const activeCeremonies = await getDb()
        .select({ ceremonyId: table.ceremonyId })
        .from(table)
        .where(
          and(
            eq(table.ownerEmail, inputValue.ownerEmail.toLowerCase()),
            eq(table.orgId, inputValue.orgId),
            eq(table.vaultId, inputValue.vaultId),
            eq(table.artifactKind, "ceremony"),
            ne(table.phase, "completed"),
          ),
        )
        .limit(2);
      if (activeCeremonies.length === 0)
        throw new PrivateVaultRotationEvidenceError("conflict");
      if (activeCeremonies.length !== 1)
        throw new PrivateVaultRotationEvidenceError("unavailable");
      const rows = await getDb()
        .select()
        .from(table)
        .where(
          and(
            eq(table.ownerEmail, inputValue.ownerEmail.toLowerCase()),
            eq(table.orgId, inputValue.orgId),
            eq(table.vaultId, inputValue.vaultId),
            eq(table.artifactKind, "control_bundle"),
            inArray(
              table.ceremonyId,
              activeCeremonies.map((value) => value.ceremonyId),
            ),
          ),
        )
        .limit(2);
      if (rows.length === 0)
        throw new PrivateVaultRotationEvidenceError("conflict");
      if (rows.length !== 1)
        throw new PrivateVaultRotationEvidenceError("unavailable");
      const row = rows[0]!;
      const bundle = await readControlBundle(
        {
          ownerEmail: row.ownerEmail,
          accountId: row.accountId,
          orgId: row.orgId,
          workspaceId: row.workspaceId,
          vaultId: row.vaultId,
        },
        row.ceremonyId,
      );
      if (
        bundle.bundleSha256 !== inputValue.bundleSha256 ||
        !exact(bundle.signedEntry, signedEntry) ||
        !exact(bundle.recoveryWrap, recoveryWrap)
      )
        throw new PrivateVaultRotationEvidenceError("conflict");
      return true;
    },
    async putControlBundle(
      scopeInput: PrivateVaultRotationEvidenceScope,
      inputValue: {
        ceremonyId: string;
        signedEntry: Uint8Array;
        recoveryWrap: Uint8Array;
        bundleSha256: string;
      },
    ) {
      const scope = normalizeScope(scopeInput);
      const ceremonyId = opaqueId(inputValue.ceremonyId);
      const signedEntry = bounded(
        inputValue.signedEntry,
        ANC_V1_CONTROL_LOG_APPEND_SIGNED_ENTRY_MAX_BYTES,
      );
      const recoveryWrap = bounded(
        inputValue.recoveryWrap,
        ANC_V1_CONTROL_LOG_APPEND_RECOVERY_WRAP_MAX_BYTES,
      );
      const encodedBundle = encodeAncV1ControlLogRotationAppendRequest({
        version: 1,
        suite: "anc/v1",
        type: "control-log-rotation-append-request",
        signedEntry: Uint8Array.from(signedEntry),
        recoveryWrap: Uint8Array.from(recoveryWrap),
      });
      if (!/^[0-9a-f]{64}$/.test(inputValue.bundleSha256))
        throw new PrivateVaultRotationEvidenceError("invalid_request");
      if (sha256(encodedBundle) !== inputValue.bundleSha256)
        throw new PrivateVaultRotationEvidenceError("conflict");
      const prior = await read(scope, ceremonyId);
      if (prior.controlBundle) {
        const exactPrior = await readControlBundle(scope, ceremonyId);
        if (
          exact(exactPrior.signedEntry, signedEntry) &&
          exact(exactPrior.recoveryWrap, recoveryWrap) &&
          exactPrior.bundleSha256 === inputValue.bundleSha256
        )
          return prior;
        throw new PrivateVaultRotationEvidenceError("conflict");
      }
      if (
        prior.phase !== "awaiting_acknowledgements" ||
        prior.recipients.some((recipient) => recipient.acknowledgement !== null)
      )
        throw new PrivateVaultRotationEvidenceError("conflict");
      let handle: PrivateBlobHandle | null;
      try {
        handle = await blobs.put({
          data: encodedBundle,
          filename: "rotation-control-bundle.bin",
          mimeType: "application/octet-stream",
          ownerEmail: scope.ownerEmail,
          metadata: { ceremonyId, vaultId: scope.vaultId },
        });
      } catch {
        throw new PrivateVaultRotationEvidenceError("unavailable");
      }
      if (!handle) throw new PrivateVaultRotationEvidenceError("unavailable");
      if (!parseBlobHandle(JSON.stringify(handle))) {
        await blobs.delete(handle).catch(() => undefined);
        throw new PrivateVaultRotationEvidenceError("unavailable");
      }
      try {
        await getDb().transaction(async (tx) => {
          const current = parseRows(await rowsFor(tx, scope, ceremonyId));
          if (
            current.controlBundle ||
            current.phase !== "awaiting_acknowledgements" ||
            current.recipients.some(
              (recipient) => recipient.acknowledgement !== null,
            )
          )
            throw new PrivateVaultRotationEvidenceError("conflict");
          const at = now();
          if (!Number.isFinite(at.getTime()))
            throw new PrivateVaultRotationEvidenceError("unavailable");
          await tx
            .insert(schema.contentEncryptedVaultRotationEvidenceArtifacts)
            .values({
              id: rowId(scope, ceremonyId, "control_bundle", "singleton"),
              ...scope,
              ceremonyId,
              artifactKind: "control_bundle",
              artifactKey: "singleton",
              privateBlobHandleJson: JSON.stringify(handle),
              privateBlobSha256: inputValue.bundleSha256,
              privateBlobByteLength: encodedBundle.byteLength,
              bundleSha256: inputValue.bundleSha256,
              signedEntrySha256: sha256(signedEntry),
              signedEntryByteLength: signedEntry.byteLength,
              recoveryWrapSha256: sha256(recoveryWrap),
              recoveryWrapByteLength: recoveryWrap.byteLength,
              updatedAt: at.toISOString(),
            });
        });
      } catch (error) {
        await blobs.delete(handle).catch(() => undefined);
        if (error instanceof PrivateVaultRotationEvidenceError) throw error;
        throw new PrivateVaultRotationEvidenceError("conflict");
      }
      return read(scope, ceremonyId);
    },
    async establish(
      scopeInput: PrivateVaultRotationEvidenceScope,
      inputValue: {
        ceremonyId: string;
        expectedRecipientCount: number;
        checkpoint: Uint8Array;
      },
    ) {
      const scope = normalizeScope(scopeInput);
      let input: {
        ceremonyId: string;
        expectedRecipientCount: number;
        checkpoint: Uint8Array;
      };
      try {
        input = z
          .object({
            ceremonyId: opaqueIdSchema,
            expectedRecipientCount: z.number().int().min(1).max(MAX_RECIPIENTS),
            checkpoint: z.instanceof(Uint8Array),
          })
          .strict()
          .parse(inputValue);
      } catch {
        throw new PrivateVaultRotationEvidenceError("invalid_request");
      }
      const checkpoint = bounded(input.checkpoint, EVIDENCE_MAX_BYTES);
      return getDb().transaction(async (tx) => {
        await requireVaultScope(tx, scope);
        const existing = await rowsFor(tx, scope, input.ceremonyId);
        if (existing.length > 0) {
          const status = parseRows(existing);
          if (
            status.expectedRecipientCount === input.expectedRecipientCount &&
            exact(status.checkpoint, checkpoint)
          )
            return status;
          throw new PrivateVaultRotationEvidenceError("conflict");
        }
        const at = now();
        if (!Number.isFinite(at.getTime()))
          throw new PrivateVaultRotationEvidenceError("unavailable");
        await tx
          .insert(schema.contentEncryptedVaultRotationEvidenceArtifacts)
          .values([
            {
              id: rowId(scope, input.ceremonyId, "ceremony", "ceremony"),
              ...scope,
              ceremonyId: input.ceremonyId,
              artifactKind: "ceremony",
              artifactKey: "ceremony",
              expectedRecipientCount: input.expectedRecipientCount,
              phase: "collecting_offers",
              updatedAt: at.toISOString(),
            },
            {
              id: rowId(scope, input.ceremonyId, "checkpoint", "singleton"),
              ...scope,
              ceremonyId: input.ceremonyId,
              artifactKind: "checkpoint",
              artifactKey: "singleton",
              evidenceBytesBase64url: encode(checkpoint),
              updatedAt: at.toISOString(),
            },
          ]);
        return parseRows(await rowsFor(tx, scope, input.ceremonyId));
      });
    },
    putRecipientOffer(
      scope: PrivateVaultRotationEvidenceScope,
      input: {
        ceremonyId: string;
        recipientEndpointId: string;
        offer: Uint8Array;
        eekWrap: Uint8Array;
      },
    ) {
      return putRecipientArtifact({
        scope,
        ceremonyId: input.ceremonyId,
        recipientEndpointId: input.recipientEndpointId,
        kind: "recipient_offer",
        evidence: input.offer,
        eekWrap: input.eekWrap,
      });
    },
    putRecipientAcknowledgement(
      scope: PrivateVaultRotationEvidenceScope,
      input: {
        ceremonyId: string;
        recipientEndpointId: string;
        acknowledgement: Uint8Array;
      },
    ) {
      return putRecipientArtifact({
        scope,
        ceremonyId: input.ceremonyId,
        recipientEndpointId: input.recipientEndpointId,
        kind: "recipient_acknowledgement",
        evidence: input.acknowledgement,
      });
    },
    putDestructionAttestation(
      scope: PrivateVaultRotationEvidenceScope,
      input: {
        ceremonyId: string;
        recipientEndpointId: string;
        destructionAttestation: Uint8Array;
      },
    ) {
      return putRecipientArtifact({
        scope,
        ceremonyId: input.ceremonyId,
        recipientEndpointId: input.recipientEndpointId,
        kind: "destruction_attestation",
        evidence: input.destructionAttestation,
      });
    },
    putHostedReceipt(
      scope: PrivateVaultRotationEvidenceScope,
      input: { ceremonyId: string; hostedReceipt: Uint8Array },
    ) {
      return putSingletonArtifact({
        scope,
        ceremonyId: input.ceremonyId,
        kind: "hosted_receipt",
        evidence: input.hostedReceipt,
      });
    },
    putCompletionAttestation(
      scope: PrivateVaultRotationEvidenceScope,
      input: { ceremonyId: string; completionAttestation: Uint8Array },
    ) {
      return putSingletonArtifact({
        scope,
        ceremonyId: input.ceremonyId,
        kind: "completion_attestation",
        evidence: input.completionAttestation,
      });
    },
    async purgeEligibleTerminalEvidence(
      scopeInput: PrivateVaultRotationEvidenceScope,
      inputValue?: { at?: Date; limit?: number },
    ) {
      const scope = normalizeScope(scopeInput);
      const at = inputValue?.at ?? now();
      const limit = inputValue?.limit ?? 100;
      if (
        !Number.isFinite(at.getTime()) ||
        !Number.isSafeInteger(limit) ||
        limit < 1 ||
        limit > 1_000
      )
        throw new PrivateVaultRotationEvidenceError("invalid_request");
      const purged = await getDb().transaction(async (tx) => {
        const table = schema.contentEncryptedVaultRotationEvidenceArtifacts;
        const candidates = await tx
          .select({ ceremonyId: table.ceremonyId })
          .from(table)
          .where(
            and(
              scopeWhere(table, scope),
              eq(table.artifactKind, "ceremony"),
              eq(table.phase, "completed"),
              lte(table.purgeEligibleAt, at.toISOString()),
            ),
          )
          .orderBy(asc(table.purgeEligibleAt))
          .limit(limit);
        let artifactsDeleted = 0;
        const blobHandles: PrivateBlobHandle[] = [];
        for (const candidate of candidates) {
          const ceremonyRows = await rowsFor(tx, scope, candidate.ceremonyId);
          const blobRows = ceremonyRows.filter(
            (row) => row.artifactKind === "control_bundle",
          );
          for (const blobRow of blobRows) {
            const handle = parseBlobHandle(blobRow.privateBlobHandleJson);
            if (!handle)
              throw new PrivateVaultRotationEvidenceError("unavailable");
            blobHandles.push(handle);
          }
          const deleted = await tx
            .delete(table)
            .where(ceremonyWhere(scope, candidate.ceremonyId))
            .returning({ id: table.id });
          artifactsDeleted += deleted.length;
        }
        return {
          ceremoniesDeleted: candidates.length,
          artifactsDeleted,
          blobHandles,
        };
      });
      // SQL commits first so a provider failure or process interruption can
      // leave only an unreachable encrypted orphan, never a live row pointing
      // at bytes that were already deleted.
      for (const handle of purged.blobHandles)
        await blobs.delete(handle).catch(() => undefined);
      return Object.freeze({
        ceremoniesDeleted: purged.ceremoniesDeleted,
        artifactsDeleted: purged.artifactsDeleted,
      });
    },
  };
}

export const privateVaultRotationEvidenceStore =
  createPrivateVaultRotationEvidenceStore();

export const privateVaultRotationEvidenceLimits = Object.freeze({
  evidenceBytes: EVIDENCE_MAX_BYTES,
  eekWrapBytes: EEK_WRAP_MAX_BYTES,
  recipients: MAX_RECIPIENTS,
  terminalRetentionDays: 90,
});
