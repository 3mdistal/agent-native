import { describe, expect, it, vi } from "vitest";

import {
  PrivateVaultContentRotationEvidenceTransport,
  PrivateVaultRotationEvidenceTransportError,
} from "./content-rotation-evidence-transport.js";

const vaultId = "11".repeat(16);
const ceremonyId = "22".repeat(16);
const recipientEndpointId = "33".repeat(16);
const endpointId = "44".repeat(16);

function json(value: unknown, url: string, override?: Partial<Response>) {
  const body = new TextEncoder().encode(JSON.stringify(value));
  return {
    status: 200,
    url,
    redirected: false,
    headers: new Headers({ "content-type": "application/json" }),
    arrayBuffer: async () => body.slice().buffer,
    ...override,
  } as Response;
}

function fixture(input?: {
  role?: "endpoint" | "broker";
  unattended?: boolean;
  response?: (url: string, init: RequestInit) => Response | Promise<Response>;
}) {
  const role = input?.role ?? "endpoint";
  const capturedBodies: Uint8Array[] = [];
  const fetch = vi.fn(async (url: string, init: RequestInit) => {
    capturedBodies.push(Uint8Array.from(init.body as Uint8Array));
    if (input?.response) return input.response(url, init);
    return json(
      {
        state: "stored",
        ceremonyId,
        phase: "collecting_offers",
        expectedRecipientCount: 2,
      },
      url,
    );
  });
  const native = {
    listVaultMembers: vi.fn(async () => ({
      members: [
        {
          endpointId,
          role,
          unattended: input?.unattended ?? role === "broker",
          current: true,
        },
      ],
    })),
    signEndpointRequest: vi.fn(async () => ({
      signature: Uint8Array.from({ length: 64 }, () => 0x77),
    })),
  };
  return {
    fetch,
    capturedBodies,
    native,
    transport: new PrivateVaultContentRotationEvidenceTransport({
      origin: "https://content.example.test",
      session: { fetch },
      native: native as never,
      now: () => new Date("2026-07-19T10:00:00.000Z"),
      nonce: () => "55".repeat(32),
    }),
  };
}

function proof(
  call: ReturnType<typeof fixture>["fetch"]["mock"]["calls"][number],
) {
  const headers = call[1]!.headers as Record<string, string>;
  return JSON.parse(
    Buffer.from(headers["X-Anc-Endpoint-Proof"]!, "base64url").toString("utf8"),
  ) as Record<string, unknown>;
}

describe("signed Desktop rotation evidence transport", () => {
  it("binds checkpoint and offer uploads to exact endpoint-signed bytes", async () => {
    const source = fixture();
    const checkpoint = Uint8Array.of(1, 2, 3);
    await expect(
      source.transport.appendCheckpoint(vaultId, checkpoint),
    ).resolves.toMatchObject({ state: "stored", ceremonyId });
    expect(checkpoint).toEqual(Uint8Array.of(1, 2, 3));
    expect(proof(source.fetch.mock.calls[0]!).path).toBe(
      "/api/private-vault/rotation-evidence/checkpoint",
    );
    expect(source.capturedBodies[0]).toEqual(checkpoint);

    await source.transport.appendOffer(
      vaultId,
      Uint8Array.of(4, 5),
      Uint8Array.of(6, 7),
    );
    const offerHeaders = source.fetch.mock.calls[1]![1]!.headers as Record<
      string,
      string
    >;
    expect(offerHeaders["X-Anc-Eek-Wrap"]).toBe("Bgc");
    expect(proof(source.fetch.mock.calls[1]!).path).toBe(
      "/api/private-vault/rotation-evidence/offer",
    );
  });

  it("fetches recipient evidence for an active unattended broker", async () => {
    const offer = Uint8Array.of(1, 2);
    const eekWrap = Uint8Array.of(3, 4);
    const source = fixture({
      role: "broker",
      response: (url) =>
        json(
          {
            ceremonyId,
            recipientEndpointId,
            offer: Buffer.from(offer).toString("base64url"),
            eekWrap: Buffer.from(eekWrap).toString("base64url"),
          },
          url,
        ),
    });
    await expect(
      source.transport.fetchRecipient(vaultId, ceremonyId, recipientEndpointId),
    ).resolves.toEqual({ ceremonyId, recipientEndpointId, offer, eekWrap });
    expect(proof(source.fetch.mock.calls[0]!).path).toContain(
      `/${ceremonyId}/recipients/${recipientEndpointId}/recipient`,
    );
    expect(source.fetch.mock.calls[0]![1]!.body).toHaveLength(0);
  });

  it("collects bounded unique acknowledgement and destruction evidence", async () => {
    const source = fixture({
      response: (url) =>
        json(
          {
            ceremonyId,
            phase: "awaiting_hosted_receipt",
            expectedRecipientCount: 1,
            recipients: [
              {
                recipientEndpointId,
                acknowledgement: Buffer.from([1]).toString("base64url"),
                destructionAttestation: Buffer.from([2]).toString("base64url"),
              },
            ],
          },
          url,
        ),
    });
    await expect(
      source.transport.readStatus(vaultId, ceremonyId),
    ).resolves.toMatchObject({
      ceremonyId,
      phase: "awaiting_hosted_receipt",
      recipients: [
        {
          recipientEndpointId,
          acknowledgement: Uint8Array.of(1),
          destructionAttestation: Uint8Array.of(2),
        },
      ],
    });
  });

  it("rejects role confusion, duplicate recipients, and redirected responses", async () => {
    const attendedBroker = fixture({ role: "broker", unattended: false });
    await expect(
      attendedBroker.transport.appendCheckpoint(vaultId, Uint8Array.of(1)),
    ).rejects.toBeInstanceOf(PrivateVaultRotationEvidenceTransportError);

    const duplicate = fixture({
      response: (url) =>
        json(
          {
            ceremonyId,
            phase: "awaiting_acknowledgements",
            expectedRecipientCount: 2,
            recipients: [
              {
                recipientEndpointId,
                acknowledgement: null,
                destructionAttestation: null,
              },
              {
                recipientEndpointId,
                acknowledgement: null,
                destructionAttestation: null,
              },
            ],
          },
          url,
        ),
    });
    await expect(
      duplicate.transport.readStatus(vaultId, ceremonyId),
    ).rejects.toBeInstanceOf(PrivateVaultRotationEvidenceTransportError);

    const redirected = fixture({
      response: (url) =>
        json(
          {
            state: "stored",
            ceremonyId,
            phase: "collecting_offers",
            expectedRecipientCount: 1,
          },
          url,
          { redirected: true },
        ),
    });
    await expect(
      redirected.transport.appendCheckpoint(vaultId, Uint8Array.of(1)),
    ).rejects.toBeInstanceOf(PrivateVaultRotationEvidenceTransportError);
  });
});
