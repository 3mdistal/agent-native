import { createFeatureFlagsPlugin } from "@agent-native/core/server";

import { CALENDAR_FEATURE_FLAGS } from "../../shared/feature-flags.js";

export default createFeatureFlagsPlugin({
  flags: CALENDAR_FEATURE_FLAGS,
});
