import { defineAction } from "@agent-native/core";
import { getRequestUserEmail } from "@agent-native/core/server";
import { z } from "zod";

import { listPublishedCalendarSources } from "../server/lib/google-calendar.js";
import { requirePublishedCalendarFeedsEnabled } from "../server/lib/published-calendar-feature.js";

export default defineAction({
  description:
    "List Google calendar publication eligibility for the signed-in owner, including unavailable sources and connected-account read failures. Shared overlays, external ICS feeds, and bookings are excluded.",
  schema: z.object({}),
  http: { method: "GET" },
  readOnly: true,
  run: async (_args, ctx) => {
    await requirePublishedCalendarFeedsEnabled(ctx);
    const ownerEmail = getRequestUserEmail();
    if (!ownerEmail) throw new Error("Sign in to list publishable calendars.");
    return listPublishedCalendarSources(ownerEmail);
  },
});
