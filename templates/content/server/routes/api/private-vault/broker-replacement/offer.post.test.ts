import { beforeEach, describe, expect, it, vi } from "vitest";

const {
  getHeader,
  offer,
  readBody,
  resolveScope,
  setResponseHeader,
  setResponseStatus,
} = vi.hoisted(() => ({
  getHeader: vi.fn(),
  offer: vi.fn(),
  readBody: vi.fn(),
  resolveScope: vi.fn(),
  setResponseHeader: vi.fn(),
  setResponseStatus: vi.fn(),
}));

vi.mock("h3", () => ({
  defineEventHandler: (handler: unknown) => handler,
  getHeader: (...args: unknown[]) => getHeader(...args),
  setResponseHeader: (...args: unknown[]) => setResponseHeader(...args),
  setResponseStatus: (...args: unknown[]) => setResponseStatus(...args),
}));
vi.mock("../../../../lib/private-vault-bounded-body.js", () => ({
  readPrivateVaultBoundedBody: readBody,
}));
vi.mock(
  "../../../../lib/private-vault-broker-replacement-http.js",
  async (original) => {
    const actual =
      await original<
        typeof import("../../../../lib/private-vault-broker-replacement-http.js")
      >();
    return {
      ...actual,
      serializePrivateVaultBrokerReplacementStatus: vi
        .fn()
        .mockReturnValue({ phase: "offer" }),
    };
  },
);
vi.mock(
  "../../../../lib/private-vault-broker-replacement-orchestration.js",
  async (original) => {
    const actual =
      await original<
        typeof import("../../../../lib/private-vault-broker-replacement-orchestration.js")
      >();
    return {
      ...actual,
      privateVaultBrokerReplacementOfferVaultId: vi
        .fn()
        .mockReturnValue("11".repeat(16)),
      privateVaultBrokerReplacementOrchestration: { offer },
      withAuthenticatedPrivateVaultBrokerReplacementScope: resolveScope,
    };
  },
);

import handler from "./offer.post.js";

describe("POST /api/private-vault/broker-replacement/offer", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    getHeader.mockImplementation((_event, name: string) => {
      if (name === "x-agent-native-csrf") return "1";
      if (name === "content-type") {
        return "application/vnd.agent-native.private-vault-broker-replacement+cbor";
      }
      if (name === "content-length") return "3";
      return undefined;
    });
    readBody.mockResolvedValue(Uint8Array.of(1, 2, 3));
    offer.mockResolvedValue({});
    resolveScope.mockImplementation(
      async (_event, _vaultId, operation: (scope: object) => Promise<object>) =>
        operation({
          ownerEmail: "owner@example.test",
          accountId: "account:test",
          orgId: "org:test",
          workspaceId: "workspace:test",
          vaultId: "11".repeat(16),
        }),
    );
  });

  it("requires exact binary framing and authenticated scoped resolution", async () => {
    await handler({} as never);
    expect(resolveScope).toHaveBeenCalledWith(
      expect.anything(),
      "11".repeat(16),
      expect.any(Function),
    );
    expect(setResponseHeader).toHaveBeenCalledWith(
      expect.anything(),
      "Cache-Control",
      "no-store",
    );
  });

  it("rejects cross-site, missing-length, and absent-scope requests before ceremony work", async () => {
    getHeader.mockReturnValue(undefined);
    await expect(handler({} as never)).resolves.toEqual({
      error: "Request unavailable",
    });
    expect(offer).not.toHaveBeenCalled();

    getHeader.mockImplementation((_event, name: string) => {
      if (name === "x-agent-native-csrf") return "1";
      if (name === "content-type") {
        return "application/vnd.agent-native.private-vault-broker-replacement+cbor";
      }
      return undefined;
    });
    await expect(handler({} as never)).resolves.toEqual({
      error: "Request unavailable",
    });
    expect(readBody).not.toHaveBeenCalled();

    getHeader.mockImplementation((_event, name: string) => {
      if (name === "x-agent-native-csrf") return "1";
      if (name === "content-type") {
        return "application/vnd.agent-native.private-vault-broker-replacement+cbor";
      }
      if (name === "content-length") return "3";
      return undefined;
    });
    resolveScope.mockResolvedValueOnce(null);
    await expect(handler({} as never)).resolves.toEqual({ error: "Not found" });
    expect(offer).not.toHaveBeenCalled();
  });
});
