import { appPath } from "@agent-native/core/client/api-path";
import { useFeatureFlag } from "@agent-native/core/client/feature-flags";
import { useT } from "@agent-native/core/client/i18n";
import { ShareButton } from "@agent-native/core/client/sharing";
import { PUBLISHED_CALENDAR_FEEDS_FLAG } from "@shared/feature-flags";
import {
  IconBroadcast,
  IconCheck,
  IconCopy,
  IconDots,
  IconPencil,
  IconPlus,
  IconRefresh,
  IconTrash,
  IconX,
} from "@tabler/icons-react";
import { useMemo, useState } from "react";
import { Navigate } from "react-router";
import { toast } from "sonner";

import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuGroup,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { RadioGroup, RadioGroupItem } from "@/components/ui/radio-group";
import { Skeleton } from "@/components/ui/skeleton";
import {
  type PublishedCalendar,
  type PublishedCalendarDisclosure,
  type PublishedCalendarSourceInput,
  type PublishedCalendarSourceOption,
  useCreatePublishedCalendar,
  useDeletePublishedCalendar,
  usePublishedCalendars,
  usePublishedCalendarSources,
  useRotatePublishedCalendar,
  useStopPublishedCalendar,
  useUpdatePublishedCalendar,
} from "@/hooks/use-published-calendars";
import { copyTextToClipboard } from "@/lib/clipboard";

type PendingConfirmation =
  | { kind: "rotate"; calendar: PublishedCalendar }
  | { kind: "stop"; calendar: PublishedCalendar }
  | { kind: "delete"; calendar: PublishedCalendar }
  | null;

function subscriptionUrl(token: string): string {
  return new URL(
    appPath(`/calendar-subscriptions/${encodeURIComponent(token)}.ics`),
    window.location.origin,
  ).toString();
}

function sourceInput(
  source: PublishedCalendarSourceOption,
): PublishedCalendarSourceInput {
  return {
    accountEmail: source.accountEmail,
    calendarId: source.calendarId,
  };
}

function EditorDialog({
  open,
  calendar,
  sourceOptions,
  sourceErrors,
  onOpenChange,
  onToken,
}: {
  open: boolean;
  calendar: PublishedCalendar | null;
  sourceOptions: PublishedCalendarSourceOption[];
  sourceErrors: Array<{ email: string; error: string }>;
  onOpenChange: (open: boolean) => void;
  onToken: (calendarId: string, token: string) => void;
}) {
  const t = useT();
  const create = useCreatePublishedCalendar();
  const update = useUpdatePublishedCalendar();
  const [title, setTitle] = useState(calendar?.title ?? "");
  const [disclosure, setDisclosure] = useState<PublishedCalendarDisclosure>(
    calendar?.disclosure ?? "busy",
  );
  const [selected, setSelected] = useState<Set<string>>(
    () =>
      new Set(
        calendar?.sources.map(
          (source) => `${source.accountEmail}\u0000${source.calendarId}`,
        ) ?? [],
      ),
  );

  const compatibleSources = sourceOptions.filter(
    (source) =>
      source.eligible &&
      (disclosure === "busy" || source.maximumDisclosure === "titles"),
  );
  const submitting = create.isPending || update.isPending;

  async function submit() {
    const sources = compatibleSources
      .filter((source) =>
        selected.has(`${source.accountEmail}\u0000${source.calendarId}`),
      )
      .map(sourceInput);
    if (!title.trim() || sources.length === 0) return;
    try {
      if (calendar) {
        await update.mutateAsync({
          id: calendar.id,
          title: title.trim(),
          disclosure,
          sources,
        });
        toast.success(t("publishedCalendars.updated"));
      } else {
        const created = (await create.mutateAsync({
          title: title.trim(),
          disclosure,
          sources,
        })) as PublishedCalendar & { token: string };
        onToken(created.id, created.token);
        toast.success(t("publishedCalendars.created"));
      }
      onOpenChange(false);
    } catch {
      toast.error(t("publishedCalendars.failed"));
    }
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-h-[85vh] overflow-y-auto sm:max-w-xl">
        <DialogHeader>
          <DialogTitle>
            {calendar
              ? t("publishedCalendars.edit")
              : t("publishedCalendars.create")}
          </DialogTitle>
          <DialogDescription>
            {t("publishedCalendars.description")}
          </DialogDescription>
        </DialogHeader>

        <div className="grid gap-6 py-2">
          <div className="grid gap-2">
            <Label htmlFor="published-calendar-name">
              {t("publishedCalendars.name")}
            </Label>
            <Input
              id="published-calendar-name"
              value={title}
              onChange={(event) => setTitle(event.target.value)}
              placeholder={t("publishedCalendars.namePlaceholder")}
              maxLength={200}
            />
          </div>

          <div className="grid gap-3">
            <div>
              <Label>{t("publishedCalendars.disclosure")}</Label>
            </div>
            <RadioGroup
              value={disclosure}
              onValueChange={(value) =>
                setDisclosure(value as PublishedCalendarDisclosure)
              }
              className="grid gap-2"
            >
              <Label className="flex cursor-pointer items-start gap-3 rounded-lg border p-3">
                <RadioGroupItem value="busy" className="mt-0.5" />
                <span className="grid gap-0.5">
                  <span>{t("publishedCalendars.busyOnly")}</span>
                  <span className="text-xs font-normal text-muted-foreground">
                    {t("publishedCalendars.busyOnlyDescription")}
                  </span>
                </span>
              </Label>
              <Label className="flex cursor-pointer items-start gap-3 rounded-lg border p-3">
                <RadioGroupItem value="titles" className="mt-0.5" />
                <span className="grid gap-0.5">
                  <span>{t("publishedCalendars.titlesAndTimes")}</span>
                  <span className="text-xs font-normal text-muted-foreground">
                    {t("publishedCalendars.titlesAndTimesDescription")}
                  </span>
                </span>
              </Label>
            </RadioGroup>
          </div>

          <div className="grid gap-3">
            <div>
              <Label>{t("publishedCalendars.sources")}</Label>
              <p className="mt-1 text-xs text-muted-foreground">
                {t("publishedCalendars.sourcesDescription")}
              </p>
            </div>
            {sourceErrors.length > 0 && (
              <div className="rounded-lg border border-destructive/30 bg-destructive/5 p-3 text-sm text-destructive">
                <p>{t("common.loadFailed")}</p>
                <p className="mt-1 text-xs">
                  {sourceErrors.map((error) => error.email).join(", ")}
                </p>
              </div>
            )}
            {sourceOptions.length === 0 ? (
              <p className="rounded-lg border border-dashed p-4 text-sm text-muted-foreground">
                {t("publishedCalendars.noSources")}{" "}
                {t("publishedCalendars.connectHint")}
              </p>
            ) : (
              <div className="grid gap-1 rounded-lg border p-1">
                {sourceOptions.map((source) => {
                  const key = `${source.accountEmail}\u0000${source.calendarId}`;
                  const compatible =
                    source.eligible &&
                    (disclosure === "busy" ||
                      source.maximumDisclosure === "titles");
                  return (
                    <Label
                      key={key}
                      className="flex items-center gap-3 rounded-md px-3 py-2.5 hover:bg-accent/50"
                    >
                      <Checkbox
                        checked={selected.has(key)}
                        disabled={!compatible}
                        onCheckedChange={(checked) => {
                          setSelected((current) => {
                            const next = new Set(current);
                            if (checked) next.add(key);
                            else next.delete(key);
                            return next;
                          });
                        }}
                      />
                      <span className="min-w-0 flex-1">
                        <span className="block truncate text-sm">
                          {source.label}
                        </span>
                        <span className="block truncate text-xs font-normal text-muted-foreground">
                          {source.accountEmail}
                        </span>
                      </span>
                      {!compatible && (
                        <Badge variant="secondary">
                          {t("publishedCalendars.sourceUnavailable")}
                        </Badge>
                      )}
                    </Label>
                  );
                })}
              </div>
            )}
          </div>

          <div className="grid gap-2 rounded-lg bg-muted/40 p-3 text-xs text-muted-foreground">
            <p className="font-medium text-foreground">
              {t("publishedCalendars.reviewTitle")}
            </p>
            <p>{t("publishedCalendars.reviewAnyone")}</p>
            <p>{t("publishedCalendars.reviewRedaction")}</p>
            <p>{t("publishedCalendars.reviewRefresh")}</p>
          </div>
        </div>

        <DialogFooter>
          <Button variant="ghost" onClick={() => onOpenChange(false)}>
            {t("publishedCalendars.cancel")}
          </Button>
          <Button
            onClick={submit}
            disabled={
              submitting ||
              !title.trim() ||
              !compatibleSources.some((source) =>
                selected.has(
                  `${source.accountEmail}\u0000${source.calendarId}`,
                ),
              )
            }
          >
            {calendar
              ? t("publishedCalendars.save")
              : t("publishedCalendars.create")}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

export default function PublishedCalendarsPage() {
  const t = useT();
  const enabled = useFeatureFlag(PUBLISHED_CALENDAR_FEEDS_FLAG.key);
  const calendarsQuery = usePublishedCalendars();
  const sourcesQuery = usePublishedCalendarSources();
  const rotate = useRotatePublishedCalendar();
  const stop = useStopPublishedCalendar();
  const remove = useDeletePublishedCalendar();
  const [editing, setEditing] = useState<
    PublishedCalendar | null | undefined
  >();
  const [tokens, setTokens] = useState<Record<string, string>>({});
  const [confirmation, setConfirmation] = useState<PendingConfirmation>(null);

  const calendars = useMemo(
    () =>
      (Array.isArray(calendarsQuery.data)
        ? calendarsQuery.data
        : []) as PublishedCalendar[],
    [calendarsQuery.data],
  );
  const sourceEnvelope = sourcesQuery.data as
    | {
        sources?: Array<PublishedCalendarSourceOption & { summary?: string }>;
        errors?: Array<{ email: string; error: string }>;
      }
    | undefined;
  const sourceOptions = (sourceEnvelope?.sources ?? []).map((source) => ({
    ...source,
    label: source.label ?? source.summary ?? source.calendarId,
  }));

  if (!enabled) return <Navigate to="/" replace />;

  async function copyToken(calendarId: string, token: string) {
    if (await copyTextToClipboard(subscriptionUrl(token))) {
      toast.success(t("publishedCalendars.copied"));
    }
  }

  async function confirmAction() {
    if (!confirmation) return;
    const { calendar, kind } = confirmation;
    try {
      if (kind === "rotate") {
        const result = (await rotate.mutateAsync({ id: calendar.id })) as {
          token: string;
        };
        setTokens((current) => ({ ...current, [calendar.id]: result.token }));
        await copyToken(calendar.id, result.token);
        toast.success(t("publishedCalendars.rotated"));
      } else if (kind === "stop") {
        await stop.mutateAsync({ id: calendar.id });
        setTokens((current) => {
          const next = { ...current };
          delete next[calendar.id];
          return next;
        });
        toast.success(t("publishedCalendars.stoppedToast"));
      } else {
        await remove.mutateAsync({ id: calendar.id });
        toast.success(t("publishedCalendars.deleted"));
      }
      setConfirmation(null);
    } catch {
      toast.error(t("publishedCalendars.failed"));
    }
  }

  const confirmationCopy = confirmation
    ? {
        rotate: ["rotateTitle", "rotateDescription"],
        stop: ["stopTitle", "stopDescription"],
        delete: ["deleteTitle", "deleteDescription"],
      }[confirmation.kind]
    : null;

  return (
    <div className="mx-auto flex w-full max-w-4xl flex-1 flex-col px-4 py-6 sm:px-6">
      <div className="flex items-start justify-between gap-4">
        <div className="min-w-0">
          <h1 className="text-xl font-semibold tracking-tight">
            {t("publishedCalendars.title")}
          </h1>
          <p className="mt-1 max-w-2xl text-sm text-muted-foreground">
            {t("publishedCalendars.description")}
          </p>
        </div>
        <Button onClick={() => setEditing(null)}>
          <IconPlus />
          {t("publishedCalendars.create")}
        </Button>
      </div>

      <div className="mt-8 grid gap-1">
        {calendarsQuery.isLoading ? (
          <>
            <Skeleton className="h-20 w-full" />
            <Skeleton className="h-20 w-full" />
          </>
        ) : calendars.length === 0 ? (
          <div className="flex min-h-64 flex-col items-center justify-center gap-3 rounded-xl border border-dashed p-8 text-center">
            <IconBroadcast className="size-7 text-muted-foreground" />
            <div>
              <p className="font-medium">
                {t("publishedCalendars.emptyTitle")}
              </p>
              <p className="mt-1 max-w-sm text-sm text-muted-foreground">
                {t("publishedCalendars.emptyDescription")}
              </p>
            </div>
            <Button variant="outline" onClick={() => setEditing(null)}>
              {t("publishedCalendars.create")}
            </Button>
          </div>
        ) : (
          calendars.map((calendar) => {
            const token = tokens[calendar.id];
            return (
              <div
                key={calendar.id}
                className="flex items-center gap-4 rounded-lg px-3 py-4 hover:bg-accent/40"
              >
                <span className="flex size-9 shrink-0 items-center justify-center rounded-full bg-muted">
                  {calendar.isActive ? (
                    <IconCheck className="size-4 text-primary" />
                  ) : (
                    <IconX className="size-4 text-muted-foreground" />
                  )}
                </span>
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-2">
                    <p className="truncate text-sm font-medium">
                      {calendar.title}
                    </p>
                    <Badge variant="secondary">
                      {calendar.isActive
                        ? t("publishedCalendars.active")
                        : t("publishedCalendars.stopped")}
                    </Badge>
                  </div>
                  <p className="mt-0.5 text-xs text-muted-foreground">
                    {t("publishedCalendars.sourceCount", {
                      count: calendar.sources.length,
                    })}
                    {" · "}
                    {calendar.disclosure === "busy"
                      ? t("publishedCalendars.busyOnly")
                      : t("publishedCalendars.titlesAndTimes")}
                    {calendar.isActive && !token
                      ? ` · ${t("publishedCalendars.linkOnlyShownOnce")}`
                      : ""}
                  </p>
                </div>
                {calendar.isActive && token && (
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => copyToken(calendar.id, token)}
                  >
                    <IconCopy />
                    {t("publishedCalendars.copyLink")}
                  </Button>
                )}
                <ShareButton
                  resourceType="published-calendar"
                  resourceId={calendar.id}
                  resourceTitle={calendar.title}
                  variant="compact"
                />
                <DropdownMenu>
                  <DropdownMenuTrigger asChild>
                    <Button
                      variant="ghost"
                      size="icon"
                      aria-label={t("common.more")}
                    >
                      <IconDots />
                    </Button>
                  </DropdownMenuTrigger>
                  <DropdownMenuContent align="end">
                    <DropdownMenuGroup>
                      <DropdownMenuItem onSelect={() => setEditing(calendar)}>
                        <IconPencil />
                        {t("publishedCalendars.edit")}
                      </DropdownMenuItem>
                      {calendar.isActive && (
                        <DropdownMenuItem
                          onSelect={() =>
                            setConfirmation({ kind: "rotate", calendar })
                          }
                        >
                          <IconRefresh />
                          {t("publishedCalendars.rotateLink")}
                        </DropdownMenuItem>
                      )}
                    </DropdownMenuGroup>
                    <DropdownMenuSeparator />
                    {calendar.isActive ? (
                      <DropdownMenuItem
                        className="text-destructive focus:text-destructive"
                        onSelect={() =>
                          setConfirmation({ kind: "stop", calendar })
                        }
                      >
                        <IconX />
                        {t("publishedCalendars.stop")}
                      </DropdownMenuItem>
                    ) : (
                      <DropdownMenuItem
                        className="text-destructive focus:text-destructive"
                        onSelect={() =>
                          setConfirmation({ kind: "delete", calendar })
                        }
                      >
                        <IconTrash />
                        {t("publishedCalendars.delete")}
                      </DropdownMenuItem>
                    )}
                  </DropdownMenuContent>
                </DropdownMenu>
              </div>
            );
          })
        )}
      </div>

      {editing !== undefined && (
        <EditorDialog
          key={editing?.id ?? "new"}
          open
          calendar={editing}
          sourceOptions={sourceOptions}
          sourceErrors={sourceEnvelope?.errors ?? []}
          onOpenChange={(open) => {
            if (!open) setEditing(undefined);
          }}
          onToken={(calendarId, token) => {
            setTokens((current) => ({ ...current, [calendarId]: token }));
            void copyToken(calendarId, token);
          }}
        />
      )}

      <AlertDialog
        open={confirmation !== null}
        onOpenChange={(open) => {
          if (!open) setConfirmation(null);
        }}
      >
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>
              {confirmationCopy
                ? t(`publishedCalendars.${confirmationCopy[0]}`)
                : ""}
            </AlertDialogTitle>
            <AlertDialogDescription>
              {confirmationCopy
                ? t(`publishedCalendars.${confirmationCopy[1]}`)
                : ""}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>
              {t("publishedCalendars.cancel")}
            </AlertDialogCancel>
            <AlertDialogAction onClick={confirmAction}>
              {confirmation?.kind === "rotate"
                ? t("publishedCalendars.rotateLink")
                : confirmation?.kind === "stop"
                  ? t("publishedCalendars.stop")
                  : t("publishedCalendars.delete")}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}
