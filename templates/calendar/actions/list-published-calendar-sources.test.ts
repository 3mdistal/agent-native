import { describe, expect, it, vi } from "vitest";

const getRequestUserEmailMock = vi.hoisted(() => vi.fn());
const listPublishedCalendarSourcesMock = vi.hoisted(() => vi.fn());
const isFeatureFlagEnabledMock = vi.hoisted(() => vi.fn());

vi.mock("@agent-native/core", () => ({
  defineAction: (action: unknown) => action,
}));
vi.mock("@agent-native/core/feature-flags", () => ({
  isFeatureFlagEnabled: isFeatureFlagEnabledMock,
}));
vi.mock("@agent-native/core/server", () => ({
  getRequestUserEmail: getRequestUserEmailMock,
}));
vi.mock("../server/lib/google-calendar.js", () => ({
  listPublishedCalendarSources: listPublishedCalendarSourcesMock,
}));

import action from "./list-published-calendar-sources.js";

describe("list-published-calendar-sources action", () => {
  it("fails closed before provider access when the feature is off", async () => {
    isFeatureFlagEnabledMock.mockResolvedValueOnce(false);
    getRequestUserEmailMock.mockReturnValue("owner@example.com");
    await expect(action.run({})).rejects.toThrow("not enabled");
    expect(listPublishedCalendarSourcesMock).not.toHaveBeenCalled();
  });

  it("uses the request owner rather than an ambient identity", async () => {
    isFeatureFlagEnabledMock.mockResolvedValueOnce(true);
    getRequestUserEmailMock.mockReturnValue("owner@example.com");
    listPublishedCalendarSourcesMock.mockResolvedValue({
      sources: [],
      errors: [],
    });
    await action.run({});
    expect(listPublishedCalendarSourcesMock).toHaveBeenCalledWith(
      "owner@example.com",
    );
  });

  it("fails closed without an authenticated owner", async () => {
    isFeatureFlagEnabledMock.mockResolvedValueOnce(true);
    getRequestUserEmailMock.mockReturnValue(undefined);
    await expect(action.run({})).rejects.toThrow("Sign in");
  });
});
