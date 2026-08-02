import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

import { publishedCalendarSourceSchema } from "./published-calendar-actions.js";

describe("published calendar management action input", () => {
  it("accepts only source identity; eligibility is derived server-side", () => {
    expect(
      publishedCalendarSourceSchema.parse({
        accountEmail: "alice@example.com",
        calendarId: "calendar-a",
        eligibilitySnapshot: { eligible: true },
      }),
    ).toEqual({
      accountEmail: "alice@example.com",
      calendarId: "calendar-a",
    });
  });

  it("keeps composition edits behind owner/admin access", () => {
    const source = readFileSync(
      new URL("./update-published-calendar.ts", import.meta.url),
      "utf8",
    );
    expect(source).toContain(
      'assertAccess("published-calendar", args.id, "admin")',
    );
    expect(source).not.toContain(
      'assertAccess("published-calendar", args.id, "editor")',
    );
  });
});
