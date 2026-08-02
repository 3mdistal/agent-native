import { defineAction } from "@agent-native/core";
import { assertAccess } from "@agent-native/core/sharing";
import { eq } from "drizzle-orm";
import { z } from "zod";

import { getDb, schema } from "../server/db/index.js";
import { requirePublishedCalendarFeedsEnabled } from "../server/lib/published-calendar-feature.js";

export default defineAction({
  description:
    "Stop a published calendar immediately by deactivating it and invalidating its subscription token.",
  schema: z.object({ id: z.string().min(1) }),
  run: async ({ id }, ctx) => {
    await requirePublishedCalendarFeedsEnabled(ctx);
    await assertAccess("published-calendar", id, "admin");
    await getDb()
      .update(schema.publishedCalendars)
      .set({
        isActive: false,
        tokenHash: null,
        updatedAt: new Date().toISOString(),
      })
      .where(eq(schema.publishedCalendars.id, id));
    return { id, isActive: false };
  },
});
