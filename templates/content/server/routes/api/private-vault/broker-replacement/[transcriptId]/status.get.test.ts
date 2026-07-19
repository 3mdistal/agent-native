import { beforeEach, describe, expect, it, vi } from "vitest";

const { getRouterParam, resolveScope, setResponseHeader, status } = vi.hoisted(
  () => ({
    getRouterParam: vi.fn(),
    resolveScope: vi.fn(),
    setResponseHeader: vi.fn(),
    status: vi.fn(),
  }),
);

vi.mock("h3", () => ({
  defineEventHandler: (handler: unknown) => handler,
  getHeader: vi.fn(),
  getRouterParam: (...args: unknown[]) => getRouterParam(...args),
  setResponseHeader: (...args: unknown[]) => setResponseHeader(...args),
  setResponseStatus: vi.fn(),
}));
vi.mock(
  "../../../../../lib/private-vault-broker-replacement-orchestration.js",
  async (original) => {
    const actual =
      await original<
        typeof import("../../../../../lib/private-vault-broker-replacement-orchestration.js")
      >();
    return {
      ...actual,
      privateVaultBrokerReplacementOrchestration: { status },
      withAuthenticatedPrivateVaultBrokerReplacementScope: resolveScope,
    };
  },
);

import handler from "./status.get.js";

describe("GET /api/private-vault/broker-replacement/:transcriptId/status", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    getRouterParam.mockReturnValue("ab".repeat(32));
    resolveScope.mockResolvedValue(null);
  });

  it("does not accept tenant coordinates and fails closed without scoped auth", async () => {
    await expect(handler({} as never)).resolves.toEqual({ error: "Not found" });
    expect(resolveScope).toHaveBeenCalledWith(
      expect.anything(),
      undefined,
      expect.any(Function),
    );
    expect(status).not.toHaveBeenCalled();
    expect(setResponseHeader).toHaveBeenCalledWith(
      expect.anything(),
      "Cache-Control",
      "no-store",
    );
  });

  it("rejects malformed transcript ids before scope or storage access", async () => {
    getRouterParam.mockReturnValue("attacker-supplied-scope");
    await expect(handler({} as never)).resolves.toEqual({ error: "Not found" });
    expect(resolveScope).not.toHaveBeenCalled();
  });
});
