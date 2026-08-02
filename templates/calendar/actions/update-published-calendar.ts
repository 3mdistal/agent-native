import { defineAction } from "@agent-native/core";
import { assertAccess } from "@agent-native/core/sharing";
import { eq } from "drizzle-orm";
import { nanoid } from "nanoid";
import { z } from "zod";

import { getDb, schema } from "../server/db/index.js";
import { requirePublishedCalendarFeedsEnabled } from "../server/lib/published-calendar-feature.js";
import { rowToPublishedCalendar } from "../server/lib/published-calendars.js";
import {
  getPublishedCalendarForManagement,
  publishedCalendarDisclosureSchema,
  publishedCalendarSourceSchema,
  resolvePublishedCalendarSources,
} from "./published-calendar-actions.js";

export default defineAction({
  description:
    "Update a published calendar's title, disclosure policy, or explicit source selection.",
  schema: z
    .object({
      id: z.string().min(1),
      title: z.string().trim().min(1).max(200).optional(),
      disclosure: publishedCalendarDisclosureSchema.optional(),
      sources: z.array(publishedCalendarSourceSchema).min(1).optional(),
    })
    .refine(
      (args) =>
        args.title !== undefined ||
        args.disclosure !== undefined ||
        args.sources !== undefined,
      { message: "Provide at least one published calendar field to update" },
    ),
  run: async (args, ctx) => {
    await requirePublishedCalendarFeedsEnabled(ctx);
    await assertAccess("published-calendar", args.id, "admin");
    const current = await getPublishedCalendarForManagement(args.id);
    if (!current) throw new Error("Published calendar not found");
    const disclosure = args.disclosure ?? current.disclosure;
    const currentSources =
      args.sources || args.disclosure
        ? await getDb()
            .select({
              accountEmail: schema.publishedCalendarSources.accountEmail,
              calendarId: schema.publishedCalendarSources.calendarId,
            })
            .from(schema.publishedCalendarSources)
            .where(
              eq(schema.publishedCalendarSources.publishedCalendarId, args.id),
            )
        : [];
    const sources =
      args.sources || args.disclosure
        ? await resolvePublishedCalendarSources(
            current.ownerEmail,
            args.sources ?? currentSources,
            disclosure,
          )
        : undefined;
    const now = new Date().toISOString();

    await getDb().transaction(async (tx) => {
      await tx
        .update(schema.publishedCalendars)
        .set({
          ...(args.title !== undefined ? { title: args.title.trim() } : {}),
          ...(args.disclosure !== undefined
            ? { disclosure: args.disclosure }
            : {}),
          updatedAt: now,
        })
        .where(eq(schema.publishedCalendars.id, args.id));
      if (!sources) return;
      await tx
        .delete(schema.publishedCalendarSources)
        .where(
          eq(schema.publishedCalendarSources.publishedCalendarId, args.id),
        );
      await tx.insert(schema.publishedCalendarSources).values(
        sources.map((source) => ({
          id: nanoid(),
          publishedCalendarId: args.id,
          provider: "google" as const,
          accountEmail: source.accountEmail,
          calendarId: source.calendarId,
          label: source.label,
          ownershipSnapshot: JSON.stringify(source.ownershipSnapshot),
          eligibilitySnapshot: JSON.stringify(source.eligibilitySnapshot),
          createdAt: now,
          updatedAt: now,
          ownerEmail: current.ownerEmail,
          orgId: current.orgId,
        })),
      );
    });

    const updated = await getPublishedCalendarForManagement(args.id);
    if (!updated) throw new Error("Published calendar not found");
    const updatedSources = await getDb()
      .select()
      .from(schema.publishedCalendarSources)
      .where(eq(schema.publishedCalendarSources.publishedCalendarId, args.id));
    return rowToPublishedCalendar(updated, updatedSources);
  },
});
