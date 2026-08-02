import { describe, expect, it, vi } from "vitest";

const isFeatureFlagEnabledMock = vi.hoisted(() => vi.fn());

vi.mock("@agent-native/core/feature-flags", () => ({
  isFeatureFlagEnabled: isFeatureFlagEnabledMock,
}));

import { requirePublishedCalendarFeedsEnabled } from "./published-calendar-feature.js";

describe("requirePublishedCalendarFeedsEnabled", () => {
  it("fails closed when the registered flag is off", async () => {
    isFeatureFlagEnabledMock.mockResolvedValue(false);
    await expect(
      requirePublishedCalendarFeedsEnabled({
        userEmail: "owner@example.com",
      }),
    ).rejects.toThrow("not enabled");
  });

  it("allows the exact evaluated owner scope when enabled", async () => {
    isFeatureFlagEnabledMock.mockResolvedValue(true);
    await requirePublishedCalendarFeedsEnabled({
      userEmail: "owner@example.com",
      orgId: "org-example",
    });
    expect(isFeatureFlagEnabledMock).toHaveBeenCalledWith(
      expect.objectContaining({ key: "calendar.published-feeds" }),
      { userEmail: "owner@example.com", orgId: "org-example" },
    );
  });
});
