import { isFeatureFlagEnabled } from "@agent-native/core/feature-flags";

import { PUBLISHED_CALENDAR_FEEDS_FLAG } from "../../shared/feature-flags.js";

export async function requirePublishedCalendarFeedsEnabled(
  scope: { userEmail?: string; orgId?: string | null } = {},
): Promise<void> {
  if (!(await isFeatureFlagEnabled(PUBLISHED_CALENDAR_FEEDS_FLAG, scope))) {
    throw new Error(
      "Published calendar feeds are not enabled for this account.",
    );
  }
}
