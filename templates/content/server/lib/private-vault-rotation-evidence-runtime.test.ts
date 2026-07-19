import { beforeEach, describe, expect, it, vi } from "vitest";

const verifyProof = vi.hoisted(() => vi.fn());
const assertFresh = vi.hoisted(() => vi.fn((state, _now?: unknown) => state));
const resolveScope = vi.hoisted(() => vi.fn());
const loadState = vi.hoisted(() => vi.fn());
const claimNonce = vi.hoisted(() => vi.fn());

vi.mock("@agent-native/core/e2ee", async (importOriginal) => {
  const actual =
    await importOriginal<typeof import("@agent-native/core/e2ee")>();
  return {
    ...actual,
    assertFreshControlLogHead: (state: unknown, now: unknown) =>
      assertFresh(state, now),
    verifyEndpointRequestProofWithIdentity: (...args: unknown[]) =>
      verifyProof(...args),
  };
});
vi.mock("./private-vault-control-log-runtime.js", () => ({
  resolveActivePrivateVaultControlScope: (...args: unknown[]) =>
    resolveScope(...args),
  privateVaultControlLogService: {
    loadVerifiedState: (...args: unknown[]) => loadState(...args),
  },
}));
vi.mock("./private-vault-endpoint-request-nonces.js", () => ({
  sqlPrivateVaultEndpointRequestNonceStore: {
    claimAuthorizedControlRequest: (...args: unknown[]) => claimNonce(...args),
  },
}));
vi.mock("./private-vault-rotation-evidence.js", () => ({
  privateVaultRotationEvidenceStore: {},
}));

import { authenticatePrivateVaultRotationEvidenceRecipient } from "./private-vault-rotation-evidence-runtime.js";

const vaultId = "11".repeat(16);
const endpointId = "22".repeat(16);
const scope = {
  ownerEmail: "owner@example.test",
  orgId: "org:test",
  vaultId,
};

function state(role: "endpoint" | "broker", unattended: boolean) {
  return {
    vaultId,
    sequence: 1,
    headHash: "33".repeat(32),
    membershipHash: "44".repeat(32),
    signedAt: new Date().toISOString(),
    epoch: 1,
    activeMembers: [
      {
        endpointId,
        role,
        unattended,
        signingPublicKey: "55".repeat(32),
        keyAgreementPublicKey: "66".repeat(32),
        enrollmentRef: "77".repeat(16),
      },
    ],
    removedEndpointIds: [],
    freshnessMode: "endpoint_witnessed",
    recoveryGeneration: 1,
    recoveryId: "88".repeat(16),
    recoverySigningPublicKey: "99".repeat(32),
    recoveryKeyAgreementPublicKey: "aa".repeat(32),
    recoveryWrapHash: "bb".repeat(32),
  };
}

beforeEach(() => {
  vi.clearAllMocks();
  resolveScope.mockResolvedValue(scope);
  loadState.mockResolvedValue(state("broker", true));
  claimNonce.mockResolvedValue(true);
  verifyProof.mockImplementation(async (input) => {
    const identity = await input.resolveAuthorizedEndpoint({
      vaultId,
      endpointId,
      now: new Date(),
    });
    if (!identity) throw new Error();
    const claimed = await input.claimNonce({
      vaultId,
      endpointId,
      nonce: "nonce:test",
      expiresAt: new Date(Date.now() + 60_000).toISOString(),
    });
    if (!claimed) throw new Error();
    return { vaultId, endpointId };
  });
});

describe("Private Vault rotation evidence recipient authentication", () => {
  it("accepts a current active broker and binds the exact route/body", async () => {
    const body = Uint8Array.of(1, 2, 3);
    await expect(
      authenticatePrivateVaultRotationEvidenceRecipient({
        proof: { signed: true },
        path: "/api/private-vault/rotation-evidence/test",
        body,
      }),
    ).resolves.toEqual({ ...scope, endpointId });
    expect(verifyProof).toHaveBeenCalledWith(
      expect.objectContaining({
        expectedMethod: "POST",
        expectedPath: "/api/private-vault/rotation-evidence/test",
        body,
      }),
    );
  });

  it("fails closed on nonce replay, removed identity, and role confusion", async () => {
    claimNonce.mockResolvedValueOnce(false);
    await expect(
      authenticatePrivateVaultRotationEvidenceRecipient({
        proof: {},
        path: "/test",
        body: new Uint8Array(),
      }),
    ).rejects.toBeDefined();

    loadState.mockResolvedValueOnce({
      ...state("broker", true),
      activeMembers: [],
      removedEndpointIds: [endpointId],
    });
    await expect(
      authenticatePrivateVaultRotationEvidenceRecipient({
        proof: {},
        path: "/test",
        body: new Uint8Array(),
      }),
    ).rejects.toBeDefined();

    loadState.mockResolvedValueOnce(state("endpoint", true));
    await expect(
      authenticatePrivateVaultRotationEvidenceRecipient({
        proof: {},
        path: "/test",
        body: new Uint8Array(),
      }),
    ).rejects.toBeDefined();
  });
});
