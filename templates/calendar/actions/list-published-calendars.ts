import { defineAction } from "@agent-native/core";
import { z } from "zod";

import { requirePublishedCalendarFeedsEnabled } from "../server/lib/published-calendar-feature.js";
import { listPublishedCalendarRows } from "./published-calendar-actions.js";

export default defineAction({
  description: "List published calendar compositions available to manage.",
  schema: z.object({}),
  http: { method: "GET" },
  run: async (_args, ctx) => {
    await requirePublishedCalendarFeedsEnabled(ctx);
    return listPublishedCalendarRows();
  },
});
