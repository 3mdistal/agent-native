import { and, asc, eq, inArray, isNull, lte, or } from "drizzle-orm";

import { getDb, schema } from "../db/index.js";
import { privateVaultRotationEvidenceStore } from "./private-vault-rotation-evidence.js";

const DAY_MS = 24 * 60 * 60 * 1_000;
export const PRIVATE_VAULT_REPLACEMENT_RETENTION_MS = 90 * DAY_MS;
export const PRIVATE_VAULT_REPLACEMENT_PURGE_MAX_DELAY_MS = 7 * DAY_MS;

const TERMINAL_TRANSCRIPT_PHASES = [
  "activated",
  "rejected",
  "expired",
  "aborted",
] as const;
const TERMINAL_DRAIN_PHASES = ["committed", "aborted"] as const;

type Candidate = {
  id: string;
  transcriptId: string;
  ownerEmail: string;
  accountId: string;
  orgId: string;
  workspaceId: string;
  vaultId: string;
  phase: string;
  drainId: string | null;
  terminalAt: string;
};

function terminalTimestamp(row: {
  phase: string;
  activatedAt: string | null;
  terminatedAt: string | null;
}) {
  return row.phase === "activated" ? row.activatedAt : row.terminatedAt;
}

export function createPrivateVaultReplacementRetentionService(
  options: { now?: () => Date; batchSize?: number } = {},
) {
  const now = options.now ?? (() => new Date());
  const batchSize = options.batchSize ?? 100;
  if (!Number.isSafeInteger(batchSize) || batchSize < 1 || batchSize > 1_000) {
    throw new Error("Invalid Private Vault replacement retention batch size");
  }

  return {
    async sweep() {
      const at = now();
      if (!Number.isFinite(at.getTime())) throw new Error("Invalid sweep time");
      const cutoff = new Date(
        at.getTime() - PRIVATE_VAULT_REPLACEMENT_RETENTION_MS,
      ).toISOString();
      const transcript =
        schema.contentEncryptedVaultBrokerReplacementTranscripts;
      const candidates = await getDb()
        .select({
          id: transcript.id,
          transcriptId: transcript.transcriptId,
          ownerEmail: transcript.ownerEmail,
          accountId: transcript.accountId,
          orgId: transcript.orgId,
          workspaceId: transcript.workspaceId,
          vaultId: transcript.vaultId,
          phase: transcript.phase,
          drainId: transcript.drainId,
          activatedAt: transcript.activatedAt,
          terminatedAt: transcript.terminatedAt,
        })
        .from(transcript)
        .where(
          and(
            inArray(transcript.phase, [...TERMINAL_TRANSCRIPT_PHASES]),
            isNull(transcript.activeKey),
            or(
              and(
                eq(transcript.phase, "activated"),
                lte(transcript.activatedAt, cutoff),
              ),
              and(
                inArray(transcript.phase, ["rejected", "expired", "aborted"]),
                lte(transcript.terminatedAt, cutoff),
              ),
            ),
          ),
        )
        .orderBy(asc(transcript.activatedAt), asc(transcript.terminatedAt))
        .limit(batchSize);

      let transcriptsDeleted = 0;
      let drainsDeleted = 0;
      let drainJobsDeleted = 0;
      for (const row of candidates) {
        const candidate: Candidate | null = terminalTimestamp(row)
          ? { ...row, terminalAt: terminalTimestamp(row)! }
          : null;
        if (!candidate) continue;
        const deleted = await getDb().transaction(async (tx) => {
          const [current] = await tx
            .select()
            .from(transcript)
            .where(
              and(
                eq(transcript.id, candidate.id),
                eq(transcript.transcriptId, candidate.transcriptId),
                eq(transcript.ownerEmail, candidate.ownerEmail),
                eq(transcript.accountId, candidate.accountId),
                eq(transcript.orgId, candidate.orgId),
                eq(transcript.workspaceId, candidate.workspaceId),
                eq(transcript.vaultId, candidate.vaultId),
              ),
            )
            .limit(1);
          if (
            !current ||
            !TERMINAL_TRANSCRIPT_PHASES.includes(
              current.phase as (typeof TERMINAL_TRANSCRIPT_PHASES)[number],
            ) ||
            current.activeKey !== null ||
            terminalTimestamp(current) !== candidate.terminalAt ||
            Date.parse(candidate.terminalAt) > Date.parse(cutoff)
          ) {
            return { transcripts: 0, drains: 0, jobs: 0 };
          }

          let drains = 0;
          let jobs = 0;
          if (current.drainId) {
            const drain = schema.contentEncryptedVaultBrokerReplacementDrains;
            const [currentDrain] = await tx
              .select()
              .from(drain)
              .where(
                and(
                  eq(drain.drainId, current.drainId),
                  eq(drain.ownerEmail, candidate.ownerEmail),
                  eq(drain.orgId, candidate.orgId),
                  eq(drain.vaultId, candidate.vaultId),
                ),
              )
              .limit(1);
            if (
              !currentDrain ||
              !TERMINAL_DRAIN_PHASES.includes(
                currentDrain.phase as (typeof TERMINAL_DRAIN_PHASES)[number],
              ) ||
              currentDrain.activeKey !== null
            ) {
              return { transcripts: 0, drains: 0, jobs: 0 };
            }
            const deletedJobs = await tx
              .delete(schema.contentEncryptedVaultBrokerReplacementDrainJobs)
              .where(
                and(
                  eq(
                    schema.contentEncryptedVaultBrokerReplacementDrainJobs
                      .drainId,
                    current.drainId,
                  ),
                  eq(
                    schema.contentEncryptedVaultBrokerReplacementDrainJobs
                      .ownerEmail,
                    candidate.ownerEmail,
                  ),
                  eq(
                    schema.contentEncryptedVaultBrokerReplacementDrainJobs
                      .orgId,
                    candidate.orgId,
                  ),
                  eq(
                    schema.contentEncryptedVaultBrokerReplacementDrainJobs
                      .vaultId,
                    candidate.vaultId,
                  ),
                  eq(
                    schema.contentEncryptedVaultBrokerReplacementDrainJobs
                      .drainGeneration,
                    currentDrain.drainGeneration,
                  ),
                ),
              )
              .returning({
                id: schema.contentEncryptedVaultBrokerReplacementDrainJobs.id,
              });
            jobs = deletedJobs.length;
            const deletedDrain = await tx
              .delete(drain)
              .where(
                and(
                  eq(drain.drainId, currentDrain.drainId),
                  eq(drain.ownerEmail, candidate.ownerEmail),
                  eq(drain.orgId, candidate.orgId),
                  eq(drain.vaultId, candidate.vaultId),
                  eq(drain.phase, currentDrain.phase),
                  isNull(drain.activeKey),
                  eq(drain.drainGeneration, currentDrain.drainGeneration),
                ),
              )
              .returning({ drainId: drain.drainId });
            if (deletedDrain.length !== 1) throw new Error("Drain changed");
            drains = 1;
          }
          const deletedTranscript = await tx
            .delete(transcript)
            .where(
              and(
                eq(transcript.id, current.id),
                eq(transcript.phase, current.phase),
                isNull(transcript.activeKey),
                current.phase === "activated"
                  ? eq(transcript.activatedAt, candidate.terminalAt)
                  : eq(transcript.terminatedAt, candidate.terminalAt),
              ),
            )
            .returning({ id: transcript.id });
          if (deletedTranscript.length !== 1)
            throw new Error("Transcript changed");
          return { transcripts: 1, drains, jobs };
        });
        transcriptsDeleted += deleted.transcripts;
        drainsDeleted += deleted.drains;
        drainJobsDeleted += deleted.jobs;
      }

      const evidenceTable =
        schema.contentEncryptedVaultRotationEvidenceArtifacts;
      const evidenceScopes = await getDb()
        .selectDistinct({
          ownerEmail: evidenceTable.ownerEmail,
          accountId: evidenceTable.accountId,
          orgId: evidenceTable.orgId,
          workspaceId: evidenceTable.workspaceId,
          vaultId: evidenceTable.vaultId,
        })
        .from(evidenceTable)
        .where(
          and(
            eq(evidenceTable.artifactKind, "ceremony"),
            eq(evidenceTable.phase, "completed"),
            lte(evidenceTable.purgeEligibleAt, at.toISOString()),
          ),
        )
        .limit(batchSize);
      let evidenceCeremoniesDeleted = 0;
      let evidenceArtifactsDeleted = 0;
      let remaining = batchSize;
      for (const scope of evidenceScopes) {
        if (remaining < 1) break;
        const purged =
          await privateVaultRotationEvidenceStore.purgeEligibleTerminalEvidence(
            scope,
            { at, limit: remaining },
          );
        evidenceCeremoniesDeleted += purged.ceremoniesDeleted;
        evidenceArtifactsDeleted += purged.artifactsDeleted;
        remaining -= purged.ceremoniesDeleted;
      }

      return Object.freeze({
        transcriptsDeleted,
        drainsDeleted,
        drainJobsDeleted,
        evidenceCeremoniesDeleted,
        evidenceArtifactsDeleted,
      });
    },
  };
}

export const privateVaultReplacementRetentionService =
  createPrivateVaultReplacementRetentionService();
