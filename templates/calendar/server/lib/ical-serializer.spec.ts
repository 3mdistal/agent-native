import { describe, expect, it } from "vitest";

import { serializePublishedCalendar } from "./ical-serializer.js";

describe("serializePublishedCalendar", () => {
  it("redacts private details, excludes non-publishable events, and uses stable scoped UIDs", () => {
    const calendar = serializePublishedCalendar({
      feedId: "feed-1",
      title: "Family, schedule",
      disclosure: "titles",
      generatedAt: new Date("2026-07-29T12:00:00Z"),
      sources: [
        {
          accountEmail: "me@gmail.com",
          calendarId: "primary",
          events: [
            {
              id: "private",
              summary: "Therapy",
              visibility: "private",
              start: { dateTime: "2026-08-01T12:00:00Z" },
              end: { dateTime: "2026-08-01T13:00:00Z" },
            },
            {
              id: "declined",
              attendees: [{ self: true, responseStatus: "declined" }],
              start: { dateTime: "2026-08-01T12:00:00Z" },
              end: { dateTime: "2026-08-01T13:00:00Z" },
            },
            {
              id: "transparent",
              transparency: "transparent",
              start: { dateTime: "2026-08-01T12:00:00Z" },
              end: { dateTime: "2026-08-01T13:00:00Z" },
            },
            {
              id: "cancelled",
              status: "cancelled",
              start: { dateTime: "2026-08-01T12:00:00Z" },
              end: { dateTime: "2026-08-01T13:00:00Z" },
            },
          ],
        },
      ],
    });
    expect(calendar).toContain("SUMMARY:Busy");
    expect(calendar).not.toContain("Therapy");
    expect(calendar.match(/BEGIN:VEVENT/g)).toHaveLength(2);
    expect(calendar).toContain("STATUS:CANCELLED");
    expect(calendar.replace(/\r\n[ \t]/g, "")).toMatch(
      /UID:[a-f0-9]{64}@agent-native-calendar/,
    );
  });

  it("uses exclusive all-day end dates and folds UTF-8 output", () => {
    const calendar = serializePublishedCalendar({
      feedId: "feed-1",
      title: "Calendar",
      disclosure: "titles",
      sources: [
        {
          accountEmail: "me@gmail.com",
          calendarId: "primary",
          events: [
            {
              id: "day",
              summary: "é".repeat(100),
              start: { date: "2026-08-01" },
              end: { date: "2026-08-02" },
            },
          ],
        },
      ],
    });
    expect(calendar).toContain(
      "DTSTART;VALUE=DATE:20260801\r\nDTEND;VALUE=DATE:20260802",
    );
    expect(calendar).toContain("\r\n ");
    for (const line of calendar.split("\r\n"))
      expect(new TextEncoder().encode(line).byteLength).toBeLessThanOrEqual(75);
  });
});
