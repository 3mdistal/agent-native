import { defineAction } from "@agent-native/core";
import { eq } from "drizzle-orm";
import { nanoid } from "nanoid";
import { z } from "zod";

import { getDb, schema } from "../server/db/index.js";
import { requirePublishedCalendarFeedsEnabled } from "../server/lib/published-calendar-feature.js";
import {
  generatePublishedCalendarToken,
  hashPublishedCalendarToken,
  rowToPublishedCalendar,
} from "../server/lib/published-calendars.js";
import {
  publishedCalendarDisclosureSchema,
  publishedCalendarSourceSchema,
  requirePublishedCalendarOwner,
  resolvePublishedCalendarSources,
} from "./published-calendar-actions.js";

export default defineAction({
  description:
    "Create a published calendar from explicitly eligible owned Google calendars. Returns the subscription token once; store it safely because it cannot be recovered.",
  schema: z.object({
    title: z.string().trim().min(1).max(200),
    disclosure: publishedCalendarDisclosureSchema.default("busy"),
    sources: z.array(publishedCalendarSourceSchema).min(1),
  }),
  run: async (args, ctx) => {
    await requirePublishedCalendarFeedsEnabled(ctx);
    const { ownerEmail, orgId } = requirePublishedCalendarOwner();
    const sources = await resolvePublishedCalendarSources(
      ownerEmail,
      args.sources,
      args.disclosure,
    );
    const id = nanoid();
    const token = generatePublishedCalendarToken();
    const now = new Date().toISOString();

    await getDb().transaction(async (tx) => {
      await tx.insert(schema.publishedCalendars).values({
        id,
        title: args.title.trim(),
        disclosure: args.disclosure,
        isActive: true,
        tokenHash: hashPublishedCalendarToken(token),
        createdAt: now,
        updatedAt: now,
        ownerEmail,
        orgId,
      });
      await tx.insert(schema.publishedCalendarSources).values(
        sources.map((source) => ({
          id: nanoid(),
          publishedCalendarId: id,
          provider: "google" as const,
          accountEmail: source.accountEmail,
          calendarId: source.calendarId,
          label: source.label,
          ownershipSnapshot: JSON.stringify(source.ownershipSnapshot),
          eligibilitySnapshot: JSON.stringify(source.eligibilitySnapshot),
          createdAt: now,
          updatedAt: now,
          ownerEmail,
          orgId,
        })),
      );
    });

    const [created] = await getDb()
      .select()
      .from(schema.publishedCalendars)
      .where(eq(schema.publishedCalendars.id, id));
    if (!created) throw new Error("Published calendar was not created");
    const createdSources = await getDb()
      .select()
      .from(schema.publishedCalendarSources)
      .where(eq(schema.publishedCalendarSources.publishedCalendarId, id));
    return { ...rowToPublishedCalendar(created, createdSources), token };
  },
});
