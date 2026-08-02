import { useT } from "@agent-native/core/client/i18n";
import { useMemo } from "react";

import { useAppHeaderControls } from "@/components/layout/AppLayout";
import { messagesByLocale } from "@/i18n-data";
import PublishedCalendarsPage from "@/pages/PublishedCalendarsPage";

export function meta() {
  return [{ title: messagesByLocale["en-US"].routeTitles.publishedCalendars }];
}

export default function PublishedCalendarsRoute() {
  const t = useT();
  const controls = useMemo(
    () => ({
      left: (
        <h1 className="truncate text-lg font-semibold tracking-tight">
          {t("navigation.publishedCalendars")}
        </h1>
      ),
    }),
    [t],
  );
  useAppHeaderControls(controls);
  return <PublishedCalendarsPage />;
}
