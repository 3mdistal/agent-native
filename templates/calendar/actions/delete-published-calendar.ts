import { defineAction } from "@agent-native/core";
import { assertAccess } from "@agent-native/core/sharing";
import { eq } from "drizzle-orm";
import { z } from "zod";

import { getDb, schema } from "../server/db/index.js";
import { requirePublishedCalendarFeedsEnabled } from "../server/lib/published-calendar-feature.js";
import { getPublishedCalendarForManagement } from "./published-calendar-actions.js";

export default defineAction({
  description: "Delete a stopped published calendar and its selected sources.",
  schema: z.object({ id: z.string().min(1) }),
  run: async ({ id }, ctx) => {
    await requirePublishedCalendarFeedsEnabled(ctx);
    await assertAccess("published-calendar", id, "admin");
    const calendar = await getPublishedCalendarForManagement(id);
    if (!calendar) throw new Error("Published calendar not found");
    if (calendar.isActive) {
      throw new Error("Stop a published calendar before deleting it");
    }

    await getDb().transaction(async (tx) => {
      await tx
        .delete(schema.publishedCalendarSources)
        .where(eq(schema.publishedCalendarSources.publishedCalendarId, id));
      await tx
        .delete(schema.publishedCalendarShares)
        .where(eq(schema.publishedCalendarShares.resourceId, id));
      await tx
        .delete(schema.publishedCalendars)
        .where(eq(schema.publishedCalendars.id, id));
    });
    return { id, deleted: true };
  },
});
