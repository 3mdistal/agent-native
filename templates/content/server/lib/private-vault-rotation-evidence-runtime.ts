import {
  ancV1HexToBytes,
  assertFreshControlLogHead,
  controlLogStateSchema,
  verifyEndpointRequestProofWithIdentity,
} from "@agent-native/core/e2ee";
import { and, eq } from "drizzle-orm";

import { getDb, schema } from "../db/index.js";
import {
  privateVaultControlLogService,
  resolveActivePrivateVaultControlScope,
} from "./private-vault-control-log-runtime.js";
import { sqlPrivateVaultEndpointRequestNonceStore } from "./private-vault-endpoint-request-nonces.js";
import { createPrivateVaultRotationEvidenceIngress } from "./private-vault-rotation-evidence-ingress.js";
import { privateVaultRotationEvidenceStore } from "./private-vault-rotation-evidence.js";

export async function authenticatePrivateVaultRotationEvidenceRecipient(input: {
  proof: unknown;
  path: string;
  body: Uint8Array;
  now?: Date;
}) {
  const at = input.now ?? new Date();
  const resolved: {
    principal: {
      ownerEmail: string;
      orgId: string;
      vaultId: string;
      endpointId: string;
    } | null;
  } = { principal: null };
  try {
    const authenticated = await verifyEndpointRequestProofWithIdentity({
      proof: input.proof,
      expectedMethod: "POST",
      expectedPath: input.path,
      body: input.body,
      now: at,
      resolveAuthorizedEndpoint: async ({ vaultId, endpointId }) => {
        const scope = await resolveActivePrivateVaultControlScope(vaultId);
        if (!scope) return null;
        const raw =
          await privateVaultControlLogService.loadVerifiedState(scope);
        if (!raw) return null;
        const state = assertFreshControlLogHead(
          controlLogStateSchema.parse(raw),
          at,
        );
        const member = state.activeMembers.find(
          (candidate) => candidate.endpointId === endpointId,
        );
        if (
          !member ||
          !(
            (member.role === "endpoint" && !member.unattended) ||
            (member.role === "broker" && member.unattended)
          )
        )
          return null;
        resolved.principal = { ...scope, endpointId };
        return {
          vaultId,
          endpointId,
          state: "active" as const,
          signingPublicKey: Uint8Array.from(
            ancV1HexToBytes(member.signingPublicKey),
          ),
        };
      },
      claimNonce: async ({ vaultId, endpointId, nonce, expiresAt }) => {
        if (
          !resolved.principal ||
          resolved.principal.vaultId !== vaultId ||
          resolved.principal.endpointId !== endpointId
        )
          return false;
        return sqlPrivateVaultEndpointRequestNonceStore.claimAuthorizedControlRequest(
          { ...resolved.principal, nonce, expiresAt },
        );
      },
    });
    if (
      !resolved.principal ||
      authenticated.vaultId !== resolved.principal.vaultId ||
      authenticated.endpointId !== resolved.principal.endpointId
    )
      throw new Error();
    return resolved.principal;
  } catch {
    throw new Error("Private Vault rotation evidence authentication failed");
  }
}

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
