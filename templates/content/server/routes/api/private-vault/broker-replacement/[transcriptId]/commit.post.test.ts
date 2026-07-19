import { beforeEach, describe, expect, it, vi } from "vitest";

const {
  commitRotation,
  endpointProof,
  getRouterParam,
  readBody,
  resolveScope,
  setResponseHeader,
} = vi.hoisted(() => ({
  commitRotation: vi.fn(),
  endpointProof: vi.fn(),
  getRouterParam: vi.fn(),
  readBody: vi.fn(),
  resolveScope: vi.fn(),
  setResponseHeader: vi.fn(),
}));

vi.mock("h3", () => ({
  defineEventHandler: (handler: unknown) => handler,
  getHeader: vi.fn((_event, name: string) => {
    if (name === "x-agent-native-csrf") return "1";
    if (name === "content-type") {
      return "application/vnd.agent-native.private-vault-broker-replacement+cbor";
    }
    if (name === "content-length") return "3";
    return undefined;
  }),
  getRouterParam: (...args: unknown[]) => getRouterParam(...args),
  setResponseHeader: (...args: unknown[]) => setResponseHeader(...args),
  setResponseStatus: vi.fn(),
}));
vi.mock("../../../../../lib/private-vault-bounded-body.js", () => ({
  readPrivateVaultBoundedBody: readBody,
}));
vi.mock(
  "../../../../../lib/private-vault-broker-replacement-http.js",
  async (original) => {
    const actual =
      await original<
        typeof import("../../../../../lib/private-vault-broker-replacement-http.js")
      >();
    return {
      ...actual,
      privateVaultBrokerReplacementEndpointProof: endpointProof,
      serializePrivateVaultBrokerReplacementStatus: vi
        .fn()
        .mockReturnValue({ phase: "rotation_committed" }),
    };
  },
);
vi.mock(
  "../../../../../lib/private-vault-broker-replacement-orchestration.js",
  async (original) => {
    const actual =
      await original<
        typeof import("../../../../../lib/private-vault-broker-replacement-orchestration.js")
      >();
    return {
      ...actual,
      privateVaultBrokerReplacementOrchestration: { commitRotation },
      withAuthenticatedPrivateVaultBrokerReplacementScope: resolveScope,
    };
  },
);

import handler from "./commit.post.js";

describe("POST /api/private-vault/broker-replacement/:transcriptId/commit", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    getRouterParam.mockReturnValue("ab".repeat(32));
    endpointProof.mockReturnValue({ version: 1 });
    readBody.mockResolvedValue(Uint8Array.of(1, 2, 3));
    commitRotation.mockResolvedValue({});
    resolveScope.mockImplementation(
      async (
        _event,
        vaultId,
        operation: (scope: object) => Promise<object>,
      ) => {
        expect(vaultId).toBeUndefined();
        return operation({ vaultId: "11".repeat(16) });
      },
    );
  });

  it("commits only through authenticated scope with the endpoint proof", async () => {
    await expect(handler({} as never)).resolves.toEqual({
      phase: "rotation_committed",
    });
    expect(commitRotation).toHaveBeenCalledWith(
      { vaultId: "11".repeat(16) },
      "ab".repeat(32),
      Uint8Array.of(1, 2, 3),
      { version: 1 },
    );
    expect(setResponseHeader).toHaveBeenCalledWith(
      expect.anything(),
      "Cache-Control",
      "no-store",
    );
  });

  it("rejects malformed transcript and missing proof before reading bytes", async () => {
    getRouterParam.mockReturnValue("attacker-scope");
    await expect(handler({} as never)).resolves.toEqual({ error: "Not found" });
    expect(readBody).not.toHaveBeenCalled();
    expect(resolveScope).not.toHaveBeenCalled();

    getRouterParam.mockReturnValue("ab".repeat(32));
    endpointProof.mockReturnValue(null);
    await expect(handler({} as never)).resolves.toEqual({ error: "Not found" });
    expect(readBody).not.toHaveBeenCalled();
    expect(resolveScope).not.toHaveBeenCalled();
  });
});
