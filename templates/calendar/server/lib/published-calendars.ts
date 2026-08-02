import crypto from "node:crypto";

import { and, eq } from "drizzle-orm";

import { getDb, schema } from "../db/index.js";

export const MAX_PUBLISHED_CALENDAR_SOURCES = 20;

export type PublishedCalendarDisclosure = "busy" | "titles";

export interface PublishedCalendarSourceInput {
  accountEmail: string;
  calendarId: string;
  label: string;
  ownershipSnapshot: Record<string, unknown>;
  eligibilitySnapshot: Record<string, unknown> & { eligible: true };
}

export interface PublishedCalendarSource {
  id: string;
  provider: "google";
  accountEmail: string;
  calendarId: string;
  label: string;
  ownershipSnapshot: Record<string, unknown>;
  eligibilitySnapshot: Record<string, unknown> & { eligible: true };
  createdAt: string;
  updatedAt: string;
}

export interface PublishedCalendar {
  id: string;
  title: string;
  disclosure: PublishedCalendarDisclosure;
  isActive: boolean;
  lastGeneratedAt: string | null;
  lastSuccessfulAt: string | null;
  lastHealthStatus: "unknown" | "healthy" | "unhealthy";
  lastHealthError: string | null;
  lastHealthCheckedAt: string | null;
  createdAt: string;
  updatedAt: string;
  ownerEmail: string;
  orgId: string | null;
  visibility: "private" | "org" | "public";
  sources: PublishedCalendarSource[];
}

interface SourceRow {
  id: string;
  provider: "google";
  accountEmail: string;
  calendarId: string;
  label: string;
  ownershipSnapshot: string;
  eligibilitySnapshot: string;
  createdAt: string;
  updatedAt: string;
}

interface CalendarRow {
  id: string;
  title: string;
  disclosure: PublishedCalendarDisclosure;
  isActive: boolean;
  lastGeneratedAt: string | null;
  lastSuccessfulAt: string | null;
  lastHealthStatus: "unknown" | "healthy" | "unhealthy";
  lastHealthError: string | null;
  lastHealthCheckedAt: string | null;
  createdAt: string;
  updatedAt: string;
  ownerEmail: string;
  orgId: string | null;
  visibility: "private" | "org" | "public";
}

function parseSnapshot(
  value: string,
  field: "ownership" | "eligibility",
): Record<string, unknown> {
  let parsed: unknown;
  try {
    parsed = JSON.parse(value);
  } catch {
    throw new Error(`Published calendar ${field} snapshot is unreadable`);
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error(`Published calendar ${field} snapshot is invalid`);
  }
  return parsed as Record<string, unknown>;
}

export function normalizePublishedCalendarSources(
  sources: PublishedCalendarSourceInput[],
): PublishedCalendarSourceInput[] {
  if (sources.length === 0) {
    throw new Error("At least one source calendar is required");
  }
  if (sources.length > MAX_PUBLISHED_CALENDAR_SOURCES) {
    throw new Error(
      `A published calendar can include at most ${MAX_PUBLISHED_CALENDAR_SOURCES} source calendars`,
    );
  }

  const pairs = new Set<string>();
  return sources.map((source) => {
    const accountEmail = source.accountEmail.trim().toLowerCase();
    const calendarId = source.calendarId.trim();
    const label = source.label.trim();
    if (!accountEmail || !calendarId || !label) {
      throw new Error(
        "Every published calendar source needs an account, calendar, and label",
      );
    }
    if (source.eligibilitySnapshot.eligible !== true) {
      throw new Error("Only eligible source calendars can be published");
    }
    const pair = `${accountEmail}\u0000${calendarId}`;
    if (pairs.has(pair)) {
      throw new Error("A source calendar can only be selected once");
    }
    pairs.add(pair);
    return {
      ...source,
      accountEmail,
      calendarId,
      label,
    };
  });
}

export function generatePublishedCalendarToken(): string {
  return crypto.randomBytes(24).toString("base64url");
}

export function hashPublishedCalendarToken(token: string): string {
  return crypto.createHash("sha256").update(token).digest("hex");
}

export function rowToPublishedCalendarSource(
  source: SourceRow,
): PublishedCalendarSource {
  const eligibilitySnapshot = parseSnapshot(
    source.eligibilitySnapshot,
    "eligibility",
  );
  if (eligibilitySnapshot.eligible !== true) {
    throw new Error("Published calendar source is not eligible");
  }
  return {
    id: source.id,
    provider: source.provider,
    accountEmail: source.accountEmail,
    calendarId: source.calendarId,
    label: source.label,
    ownershipSnapshot: parseSnapshot(source.ownershipSnapshot, "ownership"),
    eligibilitySnapshot: eligibilitySnapshot as Record<string, unknown> & {
      eligible: true;
    },
    createdAt: source.createdAt,
    updatedAt: source.updatedAt,
  };
}

export function rowToPublishedCalendar(
  row: CalendarRow,
  sources: SourceRow[],
): PublishedCalendar {
  return {
    ...row,
    sources: sources.map(rowToPublishedCalendarSource),
  };
}

/**
 * Public feed transport calls this after it receives a bearer token. The
 * indexed hash equality check is intentionally the only anonymous resource
 * lookup; it does not expose the raw token or bypass any provider boundary.
 */
export async function resolveActivePublishedCalendarByToken(
  token: string,
): Promise<PublishedCalendar | null> {
  if (!/^[A-Za-z0-9_-]{32}$/.test(token)) return null;
  const [calendar] = await getDb()
    .select()
    .from(schema.publishedCalendars)
    .where(
      and(
        eq(
          schema.publishedCalendars.tokenHash,
          hashPublishedCalendarToken(token),
        ),
        eq(schema.publishedCalendars.isActive, true),
      ),
    )
    .limit(1);
  if (!calendar) return null;
  const sources = await getDb()
    .select()
    .from(schema.publishedCalendarSources)
    .where(
      eq(schema.publishedCalendarSources.publishedCalendarId, calendar.id),
    );
  return rowToPublishedCalendar(calendar, sources);
}

export async function recordPublishedCalendarFeedHealth(input: {
  publishedCalendarId: string;
  outcome: "success" | "failure";
  error?: string;
}): Promise<void> {
  const now = new Date().toISOString();
  if (input.outcome === "success") {
    await getDb()
      .update(schema.publishedCalendars)
      .set({
        lastGeneratedAt: now,
        lastSuccessfulAt: now,
        lastHealthStatus: "healthy",
        lastHealthError: null,
        lastHealthCheckedAt: now,
      })
      .where(eq(schema.publishedCalendars.id, input.publishedCalendarId));
    return;
  }

  await getDb()
    .update(schema.publishedCalendars)
    .set({
      lastHealthStatus: "unhealthy",
      lastHealthError: input.error?.slice(0, 1000) ?? "Feed generation failed",
      lastHealthCheckedAt: now,
    })
    .where(eq(schema.publishedCalendars.id, input.publishedCalendarId));
}
