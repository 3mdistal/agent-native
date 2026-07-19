import { controlLogStateSchema } from "@agent-native/core/e2ee";
import { and, eq } from "drizzle-orm";

import { getDb, schema } from "../db/index.js";
import { privateVaultControlLogService } from "./private-vault-control-log-runtime.js";
import { createPrivateVaultRotationEvidenceIngress } from "./private-vault-rotation-evidence-ingress.js";
import { privateVaultRotationEvidenceStore } from "./private-vault-rotation-evidence.js";

export const privateVaultRotationEvidenceIngress =
  createPrivateVaultRotationEvidenceIngress({
    store: privateVaultRotationEvidenceStore,
    async loadState(principal) {
      const state = await privateVaultControlLogService.loadVerifiedState({
        ownerEmail: principal.ownerEmail,
        orgId: principal.orgId,
        vaultId: principal.vaultId,
      });
      return state ? controlLogStateSchema.parse(state) : null;
    },
    async resolveScope(principal) {
      const table = schema.contentEncryptedVaults;
      const [vault] = await getDb()
        .select({
          ownerEmail: table.ownerEmail,
          accountId: table.accountId,
          orgId: table.orgId,
          workspaceId: table.workspaceId,
          vaultId: table.vaultId,
        })
        .from(table)
        .where(
          and(
            eq(table.ownerEmail, principal.ownerEmail.toLowerCase()),
            eq(table.orgId, principal.orgId),
            eq(table.vaultId, principal.vaultId),
            eq(table.vaultState, "active"),
          ),
        )
        .limit(1);
      return vault ?? null;
    },
  });
