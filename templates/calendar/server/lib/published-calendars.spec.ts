import { describe, expect, it } from "vitest";

import {
  MAX_PUBLISHED_CALENDAR_SOURCES,
  generatePublishedCalendarToken,
  hashPublishedCalendarToken,
  normalizePublishedCalendarSources,
  rowToPublishedCalendarSource,
} from "./published-calendars.js";

const source = {
  accountEmail: "Alice@Example.com",
  calendarId: "calendar-a",
  label: "Personal",
  ownershipSnapshot: { kind: "primary" },
  eligibilitySnapshot: { eligible: true as const, reason: "owned" },
};

describe("published calendar resource helpers", () => {
  it("generates a 24-byte opaque token and only persists a SHA-256 digest", () => {
    const token = generatePublishedCalendarToken();
    const tokenHash = hashPublishedCalendarToken(token);

    expect(Buffer.from(token, "base64url")).toHaveLength(24);
    expect(tokenHash).toMatch(/^[a-f0-9]{64}$/);
    expect(tokenHash).not.toContain(token);
  });

  it("normalizes source identity and rejects duplicate account/calendar pairs", () => {
    expect(normalizePublishedCalendarSources([source])).toEqual([
      expect.objectContaining({ accountEmail: "alice@example.com" }),
    ]);
    expect(() =>
      normalizePublishedCalendarSources([
        source,
        { ...source, accountEmail: "alice@example.com", label: "Duplicate" },
      ]),
    ).toThrow("only be selected once");
  });

  it("enforces the source bound before any write", () => {
    expect(() =>
      normalizePublishedCalendarSources(
        Array.from(
          { length: MAX_PUBLISHED_CALENDAR_SOURCES + 1 },
          (_, index) => ({
            ...source,
            calendarId: `calendar-${index}`,
          }),
        ),
      ),
    ).toThrow(`at most ${MAX_PUBLISHED_CALENDAR_SOURCES}`);
  });

  it("fails closed when persisted eligibility evidence is unreadable", () => {
    expect(() =>
      rowToPublishedCalendarSource({
        id: "source-1",
        provider: "google",
        accountEmail: "alice@example.com",
        calendarId: "calendar-a",
        label: "Personal",
        ownershipSnapshot: JSON.stringify({ kind: "primary" }),
        eligibilitySnapshot: "not-json",
        createdAt: "2026-07-29T00:00:00.000Z",
        updatedAt: "2026-07-29T00:00:00.000Z",
      }),
    ).toThrow("eligibility snapshot is unreadable");
  });
});
