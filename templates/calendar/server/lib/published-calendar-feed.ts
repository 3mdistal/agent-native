import { createHash } from "node:crypto";

import {
  listPublishedCalendarSources,
  listSelectedCalendarEvents,
  type PublishedCalendarSource,
} from "./google-calendar.js";
import { serializePublishedCalendar } from "./ical-serializer.js";
import { requirePublishedCalendarFeedsEnabled } from "./published-calendar-feature.js";
import {
  consumePublishedCalendarFeedRequest,
  PublishedCalendarRateLimitError,
} from "./published-calendar-rate-limit.js";
import {
  hashPublishedCalendarToken,
  recordPublishedCalendarFeedHealth,
  resolveActivePublishedCalendarByToken,
} from "./published-calendars.js";

const PAST_DAYS = 30;
const FUTURE_DAYS = 365;

export class PublishedCalendarFeedError extends Error {
  constructor(
    message: string,
    readonly statusCode: number,
    readonly retryAfterSeconds?: number,
  ) {
    super(message);
  }
}

function horizon(now: Date): { timeMin: string; timeMax: string } {
  const timeMin = new Date(now);
  timeMin.setUTCDate(timeMin.getUTCDate() - PAST_DAYS);
  const timeMax = new Date(now);
  timeMax.setUTCDate(timeMax.getUTCDate() + FUTURE_DAYS);
  return { timeMin: timeMin.toISOString(), timeMax: timeMax.toISOString() };
}

function matchingSource(
  inventory: PublishedCalendarSource[],
  accountEmail: string,
  calendarId: string,
): PublishedCalendarSource | undefined {
  return inventory.find(
    (source) =>
      source.accountEmail.toLowerCase() === accountEmail.toLowerCase() &&
      source.calendarId === calendarId,
  );
}

export async function generatePublishedCalendarFeed(
  token: string,
  now = new Date(),
): Promise<{ body: string; etag: string }> {
  const publishedCalendar = await resolveActivePublishedCalendarByToken(token);
  if (!publishedCalendar) {
    throw new PublishedCalendarFeedError("Not found", 404);
  }

  try {
    await requirePublishedCalendarFeedsEnabled({
      userEmail: publishedCalendar.ownerEmail,
      orgId: publishedCalendar.orgId,
    });
  } catch {
    throw new PublishedCalendarFeedError("Not found", 404);
  }

  try {
    await consumePublishedCalendarFeedRequest(
      hashPublishedCalendarToken(token),
      now,
    );
  } catch (error) {
    if (error instanceof PublishedCalendarRateLimitError) {
      throw new PublishedCalendarFeedError(
        "Too many calendar refreshes",
        429,
        error.retryAfterSeconds,
      );
    }
    throw new PublishedCalendarFeedError(
      "Calendar feed is temporarily unavailable",
      503,
    );
  }

  try {
    const { sources: inventory, errors } = await listPublishedCalendarSources(
      publishedCalendar.ownerEmail,
    );
    if (errors.length > 0) {
      throw new Error(
        `Unable to revalidate selected Google account: ${errors.map((error) => error.email).join(", ")}`,
      );
    }

    const validatedSources = publishedCalendar.sources.map((source) => {
      const current = matchingSource(
        inventory,
        source.accountEmail,
        source.calendarId,
      );
      if (
        !current?.eligible ||
        (publishedCalendar.disclosure === "titles" &&
          current.maximumDisclosure !== "titles")
      ) {
        throw new Error(
          `Selected source is no longer eligible: ${source.label}`,
        );
      }
      return { persisted: source, current };
    });
    const { timeMin, timeMax } = horizon(now);
    const eventSources = await Promise.all(
      validatedSources.map(async ({ persisted, current }) => ({
        accountEmail: persisted.accountEmail,
        calendarId: persisted.calendarId,
        events: await listSelectedCalendarEvents(
          publishedCalendar.ownerEmail,
          current,
          timeMin,
          timeMax,
        ),
      })),
    );
    if (
      eventSources.reduce((count, source) => count + source.events.length, 0) >
      20_000
    ) {
      throw new Error("Published calendar exceeds the feed event limit");
    }
    const body = serializePublishedCalendar({
      feedId: publishedCalendar.id,
      title: publishedCalendar.title,
      disclosure: publishedCalendar.disclosure,
      sources: eventSources,
      generatedAt: now,
    });
    await recordPublishedCalendarFeedHealth({
      publishedCalendarId: publishedCalendar.id,
      outcome: "success",
    });
    return {
      body,
      etag: `"${createHash("sha256").update(body).digest("hex")}"`,
    };
  } catch (error) {
    await recordPublishedCalendarFeedHealth({
      publishedCalendarId: publishedCalendar.id,
      outcome: "failure",
      error:
        error instanceof Error
          ? error.message
          : "Unable to generate calendar feed",
    }).catch(() => undefined);
    throw new PublishedCalendarFeedError(
      "Calendar feed is temporarily unavailable",
      503,
    );
  }
}
