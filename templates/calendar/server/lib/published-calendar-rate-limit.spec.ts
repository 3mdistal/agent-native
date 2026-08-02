import { beforeEach, describe, expect, it, vi } from "vitest";

const executeMock = vi.hoisted(() => vi.fn());

vi.mock("@agent-native/core/db", () => ({
  getDbExec: () => ({ execute: executeMock }),
}));

import { consumePublishedCalendarFeedRequest } from "./published-calendar-rate-limit.js";

describe("published calendar feed rate limit", () => {
  beforeEach(() => executeMock.mockReset());

  it("records an allowed request and prunes expired rows", async () => {
    executeMock
      .mockResolvedValueOnce({ rows: [{ request_count: 1 }] })
      .mockResolvedValueOnce({ rows: [] });

    await consumePublishedCalendarFeedRequest(
      "a".repeat(64),
      new Date("2026-07-29T12:00:00Z"),
    );

    expect(executeMock).toHaveBeenCalledTimes(2);
    expect(executeMock.mock.calls[0]?.[0].args[0]).toBe("a".repeat(64));
    expect(executeMock.mock.calls[0]?.[0].sql).toContain(
      "ON CONFLICT (token_hash, window_start) DO UPDATE",
    );
  });

  it("rejects requests over the token window with Retry-After", async () => {
    executeMock.mockResolvedValueOnce({ rows: [] });

    await expect(
      consumePublishedCalendarFeedRequest(
        "b".repeat(64),
        new Date("2026-07-29T12:00:00Z"),
      ),
    ).rejects.toMatchObject({
      statusCode: 429,
      retryAfterSeconds: 300,
    });
    expect(executeMock).toHaveBeenCalledTimes(1);
  });

  it("fails closed when durable limiter state is unavailable", async () => {
    executeMock.mockRejectedValueOnce(new Error("database unavailable"));
    await expect(
      consumePublishedCalendarFeedRequest("c".repeat(64)),
    ).rejects.toThrow("Unable to enforce");
  });
});
