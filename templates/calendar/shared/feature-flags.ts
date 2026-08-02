import {
  defineFeatureFlag,
  defineFeatureFlags,
} from "@agent-native/core/feature-flags/registry";

export const PUBLISHED_CALENDAR_FEEDS_FLAG = defineFeatureFlag({
  key: "calendar.published-feeds",
  displayName: "Published calendar feeds",
  description:
    "Compose explicitly selected eligible calendars into a revocable read-only subscription feed.",
});

export const CALENDAR_FEATURE_FLAGS = defineFeatureFlags([
  PUBLISHED_CALENDAR_FEEDS_FLAG,
]);
