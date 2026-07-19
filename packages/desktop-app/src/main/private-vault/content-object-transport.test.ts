import {
  ancV1BytesToHex,
  ancV1Hash,
  encodeEndpointRequestUnsignedProof,
} from "@agent-native/core/e2ee";
import { describe, expect, it, vi } from "vitest";

import {
  PrivateVaultContentObjectTransport,
  PrivateVaultContentObjectTransportError,
} from "./content-object-transport.js";

const coordinate = {
  vaultId: "10".repeat(16),
  objectId: "20".repeat(16),
  revisionId: "30".repeat(32),
};

function response(
  url: string,
  body: Uint8Array | string,
  headers: Record<string, string>,
) {
  const bytes =
    typeof body === "string" ? Buffer.from(body) : Buffer.from(body);
  const value = new Response(bytes, {
    status: 200,
    headers: { "Content-Length": String(bytes.byteLength), ...headers },
  });
  Object.defineProperties(value, {
    url: { value: url },
    redirected: { value: false },
  });
  return value;
}

describe("Private Vault Content object transport", () => {
  it("authorizes a manifest CAS over the exact hosted body and prior head", async () => {
    const url = "https://content.example/api/private-vault/objects";
    const endpointId = "40".repeat(16);
    const ciphertext = Uint8Array.of(1, 2, 3, 4);
    const priorManifestHead = {
      objectId: coordinate.objectId,
      revisionId: "50".repeat(32),
      generation: 2,
    };
    const metadata = {
      ...coordinate,
      objectType: "vault-manifest",
      algorithmId: "anc/v1",
      revision: 3,
      epoch: 7,
      parentRevisionIds: [priorManifestHead.revisionId],
      ciphertextByteLength: 4,
    };
    const signEndpointRequest = vi.fn(async () => ({
      version: 1 as const,
      suite: "anc/v1" as const,
      operation: "signEndpointRequest" as const,
      state: "signed" as const,
      signature: Uint8Array.from({ length: 64 }, () => 0x77),
    }));
    const fetch = vi.fn(async (_url: string, init: RequestInit) => {
      const headers = init.headers as Record<string, string>;
      expect(headers["X-ANC-Prior-Manifest-Generation"]).toBe("2");
      expect(headers["X-ANC-Prior-Manifest-Object-Id"]).toBe(
        priorManifestHead.objectId,
      );
      expect(headers["X-ANC-Prior-Manifest-Revision-Id"]).toBe(
        priorManifestHead.revisionId,
      );
      const proof = JSON.parse(
        Buffer.from(headers["X-Anc-Endpoint-Proof"]!, "base64url").toString(
          "utf8",
        ),
      );
      expect(proof).toMatchObject({
        vaultId: coordinate.vaultId,
        endpointId,
        method: "POST",
        path: "/api/private-vault/objects",
        issuedAt: "2026-07-19T12:00:00.000Z",
        nonce: "60".repeat(16),
      });
      return response(url, JSON.stringify(metadata), {
        "Content-Type": "application/json",
      });
    });
    const transport = new PrivateVaultContentObjectTransport({
      session: { fetch },
      origin: "https://content.example",
      native: {
        listVaultMembers: vi.fn(async () => ({
          version: 1 as const,
          suite: "anc/v1" as const,
          operation: "list_members" as const,
          state: "listed" as const,
          vaultId: coordinate.vaultId,
          members: [
            {
              endpointId,
              role: "endpoint" as const,
              unattended: false,
              current: true,
            },
          ],
        })),
        signEndpointRequest,
      },
      now: () => new Date("2026-07-19T12:00:00.000Z"),
      nonce: () => "60".repeat(16),
    });
    await expect(
      transport.put({
        coordinate,
        objectType: "vault-manifest",
        revision: 3,
        epoch: 7,
        parentRevisionIds: [priorManifestHead.revisionId],
        ciphertext,
        priorManifestHead,
      }),
    ).resolves.toEqual(metadata);

    const authorizationBody = Uint8Array.from(
      Buffer.from(
        JSON.stringify([
          "anc/v1/private-vault-manifest-write",
          coordinate.vaultId,
          coordinate.objectId,
          coordinate.revisionId,
          3,
          "vault-manifest",
          "anc/v1",
          7,
          [priorManifestHead.revisionId],
          4,
          priorManifestHead.objectId,
          priorManifestHead.revisionId,
          2,
          "9f64a747e1b97f131fabb6b447296c9b6f0201e79fb3c5356e6c77e89b6a806a",
        ]),
      ),
    );
    expect(signEndpointRequest).toHaveBeenCalledWith({
      version: 1,
      suite: "anc/v1",
      operation: "signEndpointRequest",
      unsignedProof: encodeEndpointRequestUnsignedProof({
        version: 1,
        suite: "anc/v1",
        type: "endpoint_request",
        vaultId: coordinate.vaultId,
        endpointId,
        method: "POST",
        path: "/api/private-vault/objects",
        bodyHash: ancV1BytesToHex(
          await ancV1Hash("endpoint-request-body", authorizationBody),
        ),
        issuedAt: "2026-07-19T12:00:00.000Z",
        nonce: "60".repeat(16),
      }),
    });
  });

  it("fails manifest writes closed without an exact prior head and native signer", async () => {
    const base = {
      coordinate,
      objectType: "vault-manifest" as const,
      revision: 1,
      epoch: 1,
      ciphertext: Uint8Array.of(1),
    };
    const unsigned = new PrivateVaultContentObjectTransport({
      session: { fetch: vi.fn() },
      origin: "https://content.example",
    });
    await expect(
      unsigned.put({ ...base, priorManifestHead: null }),
    ).rejects.toBeInstanceOf(PrivateVaultContentObjectTransportError);
    await expect(unsigned.put(base)).rejects.toBeInstanceOf(
      PrivateVaultContentObjectTransportError,
    );
  });

  it("surfaces a hosted stale-prior conflict without retrying another head", async () => {
    const fetch = vi.fn(async () => {
      const value = new Response("conflict", { status: 409 });
      Object.defineProperties(value, {
        url: {
          value: "https://content.example/api/private-vault/objects",
        },
        redirected: { value: false },
      });
      return value;
    });
    const transport = new PrivateVaultContentObjectTransport({
      session: { fetch },
      origin: "https://content.example",
      native: {
        listVaultMembers: vi.fn(async () => ({
          version: 1 as const,
          suite: "anc/v1" as const,
          operation: "list_members" as const,
          state: "listed" as const,
          vaultId: coordinate.vaultId,
          members: [
            {
              endpointId: "40".repeat(16),
              role: "endpoint" as const,
              unattended: false,
              current: true,
            },
          ],
        })),
        signEndpointRequest: vi.fn(async () => ({
          version: 1 as const,
          suite: "anc/v1" as const,
          operation: "signEndpointRequest" as const,
          state: "signed" as const,
          signature: Uint8Array.from({ length: 64 }, () => 0x77),
        })),
      },
      now: () => new Date("2026-07-19T12:00:00.000Z"),
      nonce: () => "60".repeat(16),
    });
    await expect(
      transport.put({
        coordinate,
        objectType: "vault-manifest",
        revision: 3,
        epoch: 7,
        parentRevisionIds: ["50".repeat(32)],
        ciphertext: Uint8Array.of(1),
        priorManifestHead: {
          objectId: coordinate.objectId,
          revisionId: "50".repeat(32),
          generation: 2,
        },
      }),
    ).rejects.toBeInstanceOf(PrivateVaultContentObjectTransportError);
    expect(fetch).toHaveBeenCalledOnce();
  });

  it("uploads only one bounded opaque revision through the authenticated session", async () => {
    const url = "https://content.example/api/private-vault/objects";
    const metadata = {
      ...coordinate,
      objectType: "document",
      algorithmId: "anc/v1",
      revision: 3,
      epoch: 7,
      parentRevisionIds: [],
      ciphertextByteLength: 4,
      serverReceivedAt: "2026-07-18T20:00:00.000Z",
    };
    let transferred: Buffer | undefined;
    const fetch = vi.fn(async (_url: string, init: RequestInit) => {
      transferred = init.body as Buffer;
      return response(url, JSON.stringify(metadata), {
        "Content-Type": "application/json",
      });
    });
    const transport = new PrivateVaultContentObjectTransport({
      session: { fetch },
      origin: "https://content.example",
    });
    const source = Uint8Array.of(1, 2, 3, 4);
    await expect(
      transport.put({
        coordinate,
        objectType: "document",
        revision: 3,
        epoch: 7,
        ciphertext: source,
      }),
    ).resolves.toEqual(metadata);
    expect(fetch).toHaveBeenCalledWith(
      url,
      expect.objectContaining({
        method: "POST",
        credentials: "include",
        redirect: "error",
        headers: expect.objectContaining({
          "X-ANC-Vault-Id": coordinate.vaultId,
          "X-ANC-Object-Id": coordinate.objectId,
          "X-ANC-Revision-Id": coordinate.revisionId,
          "X-ANC-Revision": "3",
          "X-ANC-Epoch": "7",
        }),
      }),
    );
    expect(transferred).toEqual(Buffer.alloc(4));
    expect(source).toEqual(Uint8Array.of(1, 2, 3, 4));
  });

  it("downloads an exact bounded ciphertext revision and rejects metadata substitution", async () => {
    const url = `https://content.example/api/private-vault/objects/${coordinate.objectId}/${coordinate.revisionId}`;
    const ciphertext = Uint8Array.of(0xa4, 1, 2, 3);
    const validHeaders = {
      "Content-Type": "application/octet-stream",
      "X-ANC-Ciphertext-Byte-Length": "4",
      "X-ANC-Revision": "3",
      "X-ANC-Epoch": "7",
      "X-ANC-Object-Type": "document",
      "X-ANC-Algorithm-Id": "anc/v1",
      "X-ANC-Parent-Revision-Ids": Buffer.from("[]").toString("base64url"),
    };
    const fetch = vi.fn(async () => response(url, ciphertext, validHeaders));
    const transport = new PrivateVaultContentObjectTransport({
      session: { fetch },
      origin: "https://content.example",
    });
    await expect(transport.get(coordinate)).resolves.toEqual({
      ciphertext,
      metadata: {
        objectType: "document",
        algorithmId: "anc/v1",
        revision: 3,
        epoch: 7,
        parentRevisionIds: [],
        ciphertextByteLength: 4,
      },
    });

    for (const headers of [
      { ...validHeaders, "X-ANC-Epoch": "0" },
      { ...validHeaders, "X-ANC-Object-Type": "page" },
      { ...validHeaders, "Content-Length": "3" },
    ]) {
      const hostile = new PrivateVaultContentObjectTransport({
        session: { fetch: async () => response(url, ciphertext, headers) },
        origin: "https://content.example",
      });
      await expect(hostile.get(coordinate)).rejects.toBeInstanceOf(
        PrivateVaultContentObjectTransportError,
      );
    }
  });

  it("lists only strictly bound content-free object coordinates", async () => {
    const url = "https://content.example/api/private-vault/objects";
    const latestRevision = {
      ...coordinate,
      objectType: "document",
      algorithmId: "anc/v1",
      revision: 3,
      epoch: 7,
      parentRevisionIds: [],
      ciphertextByteLength: 400,
      serverReceivedAt: "2026-07-18T20:00:00.000Z",
    };
    const payload = {
      objects: [
        {
          objectId: coordinate.objectId,
          objectType: "document",
          latestRevision,
        },
      ],
    };
    const fetch = vi.fn(async () =>
      response(url, JSON.stringify(payload), {
        "Content-Type": "application/json",
      }),
    );
    const transport = new PrivateVaultContentObjectTransport({
      session: { fetch },
      origin: "https://content.example",
    });
    await expect(transport.list(coordinate.vaultId)).resolves.toEqual(
      payload.objects,
    );
    expect(fetch).toHaveBeenCalledWith(
      url,
      expect.objectContaining({
        method: "GET",
        headers: expect.objectContaining({
          "X-ANC-Vault-Id": coordinate.vaultId,
        }),
      }),
    );

    const hostile = new PrivateVaultContentObjectTransport({
      session: {
        fetch: async () =>
          response(
            url,
            JSON.stringify({
              objects: [
                {
                  ...payload.objects[0],
                  latestRevision: {
                    ...latestRevision,
                    objectId: "40".repeat(16),
                  },
                },
              ],
            }),
            { "Content-Type": "application/json" },
          ),
      },
      origin: "https://content.example",
    });
    await expect(hostile.list(coordinate.vaultId)).rejects.toBeInstanceOf(
      PrivateVaultContentObjectTransportError,
    );
  });

  it("fails closed on non-HTTPS origins and malformed coordinates", async () => {
    expect(
      () =>
        new PrivateVaultContentObjectTransport({
          session: { fetch: vi.fn() },
          origin: "http://content.example",
        }),
    ).toThrow(PrivateVaultContentObjectTransportError);
    const transport = new PrivateVaultContentObjectTransport({
      session: { fetch: vi.fn() },
      origin: "https://content.example",
    });
    await expect(
      transport.get({
        ...coordinate,
        objectId: coordinate.objectId.toUpperCase(),
      }),
    ).rejects.toBeInstanceOf(PrivateVaultContentObjectTransportError);
  });
});
