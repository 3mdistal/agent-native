import { defineAction } from "@agent-native/core";
import { assertAccess } from "@agent-native/core/sharing";
import { eq } from "drizzle-orm";
import { z } from "zod";

import { getDb, schema } from "../server/db/index.js";
import { requirePublishedCalendarFeedsEnabled } from "../server/lib/published-calendar-feature.js";
import {
  generatePublishedCalendarToken,
  hashPublishedCalendarToken,
} from "../server/lib/published-calendars.js";
import { getPublishedCalendarForManagement } from "./published-calendar-actions.js";

export default defineAction({
  description:
    "Rotate a published calendar subscription token. Existing subscribers immediately lose access.",
  schema: z.object({ id: z.string().min(1) }),
  run: async ({ id }, ctx) => {
    await requirePublishedCalendarFeedsEnabled(ctx);
    await assertAccess("published-calendar", id, "admin");
    const calendar = await getPublishedCalendarForManagement(id);
    if (!calendar) throw new Error("Published calendar not found");
    if (!calendar.isActive) {
      throw new Error("Stopped published calendars cannot be rotated");
    }

    const token = generatePublishedCalendarToken();
    await getDb()
      .update(schema.publishedCalendars)
      .set({
        tokenHash: hashPublishedCalendarToken(token),
        updatedAt: new Date().toISOString(),
      })
      .where(eq(schema.publishedCalendars.id, id));
    return { id, token };
  },
});
