import {
  getRequestOrgId,
  getRequestUserEmail,
} from "@agent-native/core/server/request-context";
import { accessFilter } from "@agent-native/core/sharing";
import { and, desc, eq, inArray } from "drizzle-orm";
import { z } from "zod";

import { getDb, schema } from "../server/db/index.js";
import {
  listPublishedCalendarSources,
  type PublishedCalendarSource as GooglePublishedCalendarSource,
} from "../server/lib/google-calendar.js";
import {
  type PublishedCalendar,
  type PublishedCalendarSourceInput,
  normalizePublishedCalendarSources,
  rowToPublishedCalendar,
} from "../server/lib/published-calendars.js";

export const publishedCalendarSourceSchema = z.object({
  accountEmail: z.string().email(),
  calendarId: z.string().trim().min(1),
});

export const publishedCalendarDisclosureSchema = z.enum(["busy", "titles"]);

export async function listPublishedCalendarRows(): Promise<
  PublishedCalendar[]
> {
  const db = getDb();
  const calendars = await db
    .select()
    .from(schema.publishedCalendars)
    .where(
      accessFilter(schema.publishedCalendars, schema.publishedCalendarShares),
    )
    .orderBy(desc(schema.publishedCalendars.updatedAt));
  if (calendars.length === 0) return [];

  const sources = await db
    .select()
    .from(schema.publishedCalendarSources)
    .where(
      inArray(
        schema.publishedCalendarSources.publishedCalendarId,
        calendars.map((calendar) => calendar.id),
      ),
    );
  const sourcesByCalendar = new Map<string, typeof sources>();
  for (const source of sources) {
    const existing = sourcesByCalendar.get(source.publishedCalendarId) ?? [];
    existing.push(source);
    sourcesByCalendar.set(source.publishedCalendarId, existing);
  }
  return calendars.map((calendar) =>
    rowToPublishedCalendar(calendar, sourcesByCalendar.get(calendar.id) ?? []),
  );
}

export function requirePublishedCalendarOwner(): {
  ownerEmail: string;
  orgId: string | undefined;
} {
  const ownerEmail = getRequestUserEmail();
  if (!ownerEmail) throw new Error("Not authenticated");
  return { ownerEmail, orgId: getRequestOrgId() };
}

export async function resolvePublishedCalendarSources(
  ownerEmail: string,
  selections: Array<{ accountEmail: string; calendarId: string }>,
  disclosure: "busy" | "titles",
): Promise<PublishedCalendarSourceInput[]> {
  const normalizedSelections = normalizePublishedCalendarSources(
    selections.map((selection) => ({
      ...selection,
      label: selection.calendarId,
      ownershipSnapshot: {},
      eligibilitySnapshot: { eligible: true as const },
    })),
  );
  const inventory = await listPublishedCalendarSources(ownerEmail);
  const indexedSources = new Map<string, GooglePublishedCalendarSource>();
  for (const source of inventory.sources) {
    indexedSources.set(
      `${source.accountEmail.trim().toLowerCase()}\u0000${source.calendarId}`,
      source,
    );
  }

  return normalizedSelections.map((selection) => {
    const source = indexedSources.get(
      `${selection.accountEmail}\u0000${selection.calendarId}`,
    );
    if (!source) {
      throw new Error("Selected source calendar could not be verified");
    }
    if (!source.eligible || !source.maximumDisclosure) {
      throw new Error(
        "Selected source calendar is not eligible for publishing",
      );
    }
    if (disclosure === "titles" && source.maximumDisclosure !== "titles") {
      throw new Error(
        "Selected source calendar only permits busy-only disclosure",
      );
    }
    return {
      accountEmail: selection.accountEmail,
      calendarId: selection.calendarId,
      label: source.summary,
      ownershipSnapshot: {
        primary: source.primary,
        dataOwner: source.dataOwner ?? null,
        accessRole: source.accessRole ?? null,
      },
      eligibilitySnapshot: {
        eligible: true as const,
        maximumDisclosure: source.maximumDisclosure,
      },
    };
  });
}

export async function getPublishedCalendarForManagement(id: string) {
  const [calendar] = await getDb()
    .select()
    .from(schema.publishedCalendars)
    .where(
      and(
        eq(schema.publishedCalendars.id, id),
        accessFilter(schema.publishedCalendars, schema.publishedCalendarShares),
      ),
    )
    .limit(1);
  return calendar ?? null;
}
