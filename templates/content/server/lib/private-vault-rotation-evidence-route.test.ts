import { beforeEach, describe, expect, it, vi } from "vitest";

const setResponseHeader = vi.hoisted(() => vi.fn());
const setResponseStatus = vi.hoisted(() => vi.fn());
const readBody = vi.hoisted(() => vi.fn());
const decodeProof = vi.hoisted(() => vi.fn());
const authenticate = vi.hoisted(() => vi.fn());
const appendCheckpoint = vi.hoisted(() => vi.fn());
const appendOffer = vi.hoisted(() => vi.fn());
const authenticateRecipient = vi.hoisted(() => vi.fn());
const fetchRecipientEvidence = vi.hoisted(() => vi.fn());
const appendAcknowledgement = vi.hoisted(() => vi.fn());
const appendDestruction = vi.hoisted(() => vi.fn());
const readForInitiator = vi.hoisted(() => vi.fn());
const appendHostedReceipt = vi.hoisted(() => vi.fn());
const appendCompletionAttestation = vi.hoisted(() => vi.fn());

vi.mock("h3", () => ({
  getHeader: (event: TestEvent, name: string) => event.headers[name],
  setResponseHeader: (...args: unknown[]) => setResponseHeader(...args),
  setResponseStatus: (...args: unknown[]) => setResponseStatus(...args),
}));
vi.mock("./private-vault-bounded-body.js", () => ({
  readPrivateVaultBoundedBody: (...args: unknown[]) => readBody(...args),
}));
vi.mock("./private-vault-endpoint-auth.js", () => ({
  decodePrivateVaultEndpointProofHeader: (...args: unknown[]) =>
    decodeProof(...args),
  authenticatePrivateVaultAttendedEndpoint: (...args: unknown[]) =>
    authenticate(...args),
}));
vi.mock("./private-vault-rotation-evidence-runtime.js", () => ({
  authenticatePrivateVaultRotationEvidenceRecipient: (...args: unknown[]) =>
    authenticateRecipient(...args),
  privateVaultRotationEvidenceIngress: {
    appendCheckpoint,
    appendOffer,
    fetchRecipientEvidence,
    appendAcknowledgement,
    appendDestruction,
    readForInitiator,
    appendHostedReceipt,
    appendCompletionAttestation,
  },
}));

import {
  handlePrivateVaultRotationEvidence,
  handlePrivateVaultRotationEvidenceExchange,
} from "./private-vault-rotation-evidence-route.js";

interface TestEvent {
  headers: Record<string, string>;
  body: Uint8Array;
}

const ceremonyId = "11".repeat(16);
const principal = {
  ownerEmail: "owner@example.test",
  orgId: "org-test",
  vaultId: "22".repeat(16),
  endpointId: "33".repeat(16),
};

function event(body: Uint8Array): TestEvent {
  return {
    body,
    headers: {
      "content-length": String(body.byteLength),
      "content-type": "application/octet-stream",
      "x-anc-endpoint-proof": "proof",
    },
  };
}

beforeEach(() => {
  vi.clearAllMocks();
  readBody.mockImplementation((input: TestEvent) =>
    Promise.resolve(input.body),
  );
  decodeProof.mockReturnValue({ proof: true });
  authenticate.mockResolvedValue(principal);
  const status = {
    ceremonyId,
    phase: "collecting_offers",
    expectedRecipientCount: 1,
  };
  appendCheckpoint.mockResolvedValue(status);
  appendOffer.mockResolvedValue({
    ...status,
    phase: "awaiting_acknowledgements",
  });
  authenticateRecipient.mockResolvedValue(principal);
  fetchRecipientEvidence.mockResolvedValue({
    ceremonyId,
    recipientEndpointId: principal.endpointId,
    offer: Uint8Array.of(7),
    eekWrap: Uint8Array.of(8),
  });
  appendAcknowledgement.mockResolvedValue({
    ...status,
    phase: "awaiting_destructions",
  });
  appendDestruction.mockResolvedValue({
    ...status,
    phase: "awaiting_hosted_receipt",
  });
  readForInitiator.mockResolvedValue({
    ...status,
    recipients: [
      {
        recipientEndpointId: principal.endpointId,
        acknowledgement: Uint8Array.of(9),
        destructionAttestation: Uint8Array.of(10),
      },
    ],
  });
  appendHostedReceipt.mockResolvedValue({
    ...status,
    phase: "awaiting_completion",
  });
  appendCompletionAttestation.mockResolvedValue({
    ...status,
    phase: "completed",
  });
});

describe("Private Vault rotation evidence routes", () => {
  it("authenticates a bounded checkpoint on its exact proof path", async () => {
    const body = Uint8Array.of(1, 2, 3);
    await expect(
      handlePrivateVaultRotationEvidence(event(body) as never, "checkpoint"),
    ).resolves.toEqual({
      state: "stored",
      ceremonyId,
      phase: "collecting_offers",
      expectedRecipientCount: 1,
    });
    expect(authenticate).toHaveBeenCalledWith(
      expect.objectContaining({
        path: "/api/private-vault/rotation-evidence/checkpoint",
        body,
      }),
    );
    expect(appendCheckpoint).toHaveBeenCalledWith(principal, body);
    expect(body.every((byte) => byte === 0)).toBe(true);
  });

  it("decodes a canonical hash-bound EEK wrap only for the offer route", async () => {
    const body = Uint8Array.of(4, 5, 6);
    const wrap = Uint8Array.of(7, 8, 9);
    const request = event(body);
    request.headers["x-anc-eek-wrap"] = Buffer.from(wrap).toString("base64url");
    await expect(
      handlePrivateVaultRotationEvidence(request as never, "offer"),
    ).resolves.toMatchObject({ phase: "awaiting_acknowledgements" });
    expect(authenticate).toHaveBeenCalledWith(
      expect.objectContaining({
        path: "/api/private-vault/rotation-evidence/offer",
      }),
    );
    expect(appendOffer).toHaveBeenCalledWith(
      principal,
      body,
      expect.objectContaining({ byteLength: wrap.byteLength }),
    );
  });

  it("returns the same opaque failure for malformed offer framing", async () => {
    const request = event(Uint8Array.of(1));
    await expect(
      handlePrivateVaultRotationEvidence(request as never, "offer"),
    ).resolves.toEqual({ error: "Not found" });
    expect(appendOffer).not.toHaveBeenCalled();
    expect(setResponseStatus).toHaveBeenCalledWith(expect.anything(), 404);
    expect(setResponseHeader).toHaveBeenCalledWith(
      expect.anything(),
      "Cache-Control",
      "no-store",
    );
  });

  it("binds recipient fetch and ACK to their exact ceremony route", async () => {
    const fetch = event(new Uint8Array());
    fetch.headers["content-length"] = "0";
    await expect(
      handlePrivateVaultRotationEvidenceExchange(
        fetch as never,
        "recipient",
        ceremonyId,
        principal.endpointId,
      ),
    ).resolves.toMatchObject({
      ceremonyId,
      recipientEndpointId: principal.endpointId,
      offer: "Bw",
      eekWrap: "CA",
    });
    expect(authenticateRecipient).toHaveBeenCalledWith(
      expect.objectContaining({
        path: `/api/private-vault/rotation-evidence/${ceremonyId}/recipients/${principal.endpointId}/recipient`,
        body: expect.objectContaining({ byteLength: 0 }),
      }),
    );

    const acknowledgement = event(Uint8Array.of(11, 12));
    await expect(
      handlePrivateVaultRotationEvidenceExchange(
        acknowledgement as never,
        "acknowledgement",
        ceremonyId,
        principal.endpointId,
      ),
    ).resolves.toMatchObject({ phase: "awaiting_destructions" });
    expect(appendAcknowledgement).toHaveBeenCalledWith(
      principal,
      ceremonyId,
      principal.endpointId,
      expect.objectContaining({ byteLength: 2 }),
    );
  });

  it("returns exact collected bytes only to the proof-authenticated initiator", async () => {
    const request = event(new Uint8Array());
    request.headers["content-length"] = "0";
    await expect(
      handlePrivateVaultRotationEvidenceExchange(
        request as never,
        "status",
        ceremonyId,
      ),
    ).resolves.toMatchObject({
      recipients: [
        {
          recipientEndpointId: principal.endpointId,
          acknowledgement: "CQ",
          destructionAttestation: "Cg",
        },
      ],
    });
    expect(readForInitiator).toHaveBeenCalledWith(principal, ceremonyId);
  });

  it("rejects extra framing and malformed recipient coordinates opaquely", async () => {
    const extra = event(Uint8Array.of(1));
    extra.headers["content-length"] = "1";
    await expect(
      handlePrivateVaultRotationEvidenceExchange(
        extra as never,
        "recipient",
        ceremonyId,
        principal.endpointId,
      ),
    ).resolves.toEqual({ error: "Not found" });
    await expect(
      handlePrivateVaultRotationEvidenceExchange(
        event(Uint8Array.of(1)) as never,
        "destruction",
        "not-a-ceremony",
        principal.endpointId,
      ),
    ).resolves.toEqual({ error: "Not found" });
  });

  it("binds post-commit receipt and completion bytes to initiator-only paths", async () => {
    const receipt = event(Uint8Array.of(21, 22));
    await expect(
      handlePrivateVaultRotationEvidenceExchange(
        receipt as never,
        "hostedReceipt",
        ceremonyId,
      ),
    ).resolves.toMatchObject({ phase: "awaiting_completion" });
    expect(authenticateRecipient).toHaveBeenCalledWith(
      expect.objectContaining({
        path: `/api/private-vault/rotation-evidence/${ceremonyId}/hosted-receipt`,
        body: expect.objectContaining({ byteLength: 2 }),
      }),
    );
    expect(appendHostedReceipt).toHaveBeenCalledWith(
      principal,
      ceremonyId,
      expect.objectContaining({ byteLength: 2 }),
    );

    const completion = event(Uint8Array.of(23));
    await expect(
      handlePrivateVaultRotationEvidenceExchange(
        completion as never,
        "completionAttestation",
        ceremonyId,
      ),
    ).resolves.toMatchObject({ phase: "completed" });
    expect(authenticateRecipient).toHaveBeenCalledWith(
      expect.objectContaining({
        path: `/api/private-vault/rotation-evidence/${ceremonyId}/completion-attestation`,
      }),
    );
  });
});
