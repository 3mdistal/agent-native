import {
  useActionMutation,
  useActionQuery,
} from "@agent-native/core/client/hooks";

export type PublishedCalendarDisclosure = "busy" | "titles";

export interface PublishedCalendarSourceInput {
  accountEmail: string;
  calendarId: string;
}

export interface PublishedCalendarSourceOption {
  accountEmail: string;
  calendarId: string;
  label: string;
  primary?: boolean;
  accessRole?: string;
  dataOwner?: string;
  eligible: boolean;
  eligibilityReason?: string;
  ineligibleReason?: string;
  busyEligible?: boolean;
  titlesEligible?: boolean;
  maximumDisclosure?: PublishedCalendarDisclosure;
  ownershipSnapshot?: Record<string, unknown>;
  eligibilitySnapshot?: Record<string, unknown>;
}

export interface PublishedCalendar {
  id: string;
  title: string;
  disclosure: PublishedCalendarDisclosure;
  isActive: boolean;
  lastSuccessfulAt: string | null;
  lastHealthStatus: "unknown" | "healthy" | "unhealthy";
  lastHealthError: string | null;
  sources: Array<
    PublishedCalendarSourceInput & {
      id: string;
      label: string;
      ownershipSnapshot: Record<string, unknown>;
      eligibilitySnapshot: Record<string, unknown> & { eligible: true };
    }
  >;
}

export interface PublishedCalendarWithToken extends PublishedCalendar {
  token: string;
}

export function usePublishedCalendars() {
  return useActionQuery("list-published-calendars", {});
}

export function usePublishedCalendarSources() {
  return useActionQuery("list-published-calendar-sources", {});
}

export function useCreatePublishedCalendar() {
  return useActionMutation("create-published-calendar");
}

export function useUpdatePublishedCalendar() {
  return useActionMutation("update-published-calendar");
}

export function useRotatePublishedCalendar() {
  return useActionMutation("rotate-published-calendar");
}

export function useStopPublishedCalendar() {
  return useActionMutation("stop-published-calendar");
}

export function useDeletePublishedCalendar() {
  return useActionMutation("delete-published-calendar");
}
