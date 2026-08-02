import { describe, expect, it, vi } from "vitest";

const generateMock = vi.hoisted(() => vi.fn());

vi.mock("../lib/published-calendar-feed.js", () => ({
  generatePublishedCalendarFeed: generateMock,
  PublishedCalendarFeedError: class PublishedCalendarFeedError extends Error {
    constructor(
      message: string,
      readonly statusCode: number,
      readonly retryAfterSeconds?: number,
    ) {
      super(message);
    }
  },
}));

import { PublishedCalendarFeedError } from "../lib/published-calendar-feed.js";
import { getPublishedCalendarFeed } from "./published-calendar-feed.js";

describe("getPublishedCalendarFeed", () => {
  it("returns calendar content with a validator and supports 304", async () => {
    generateMock.mockResolvedValue({
      body: "BEGIN:VCALENDAR\r\nEND:VCALENDAR\r\n",
      etag: '"abc"',
    });
    const response = await getPublishedCalendarFeed("token", '"abc"');
    expect(response.status).toBe(304);
    expect(response.headers.get("content-type")).toContain("text/calendar");
    expect(response.headers.get("referrer-policy")).toBe("no-referrer");
    expect(response.headers.get("cache-control")).toBe(
      "private, max-age=300, must-revalidate",
    );
  });

  it("returns a non-cacheable 429 with retry guidance", async () => {
    generateMock.mockRejectedValue(
      new PublishedCalendarFeedError("Too many calendar refreshes", 429, 42),
    );
    const response = await getPublishedCalendarFeed("token");
    expect(response.status).toBe(429);
    expect(response.headers.get("retry-after")).toBe("42");
    expect(response.headers.get("cache-control")).toBe("no-store");
  });
});
