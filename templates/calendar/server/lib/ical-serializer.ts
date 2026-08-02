import { createHash } from "node:crypto";

export type PublishedDisclosure = "busy" | "titles";

export type IcalSourceEvent = {
  id?: string;
  iCalUID?: string;
  summary?: string;
  status?: string;
  transparency?: string;
  visibility?: string;
  eventType?: string;
  start?: { date?: string; dateTime?: string; timeZone?: string };
  end?: { date?: string; dateTime?: string; timeZone?: string };
  originalStartTime?: { date?: string; dateTime?: string; timeZone?: string };
  updated?: string;
  created?: string;
  sequence?: number;
  attendees?: Array<{ self?: boolean; responseStatus?: string }>;
};

export type IcalSource = {
  accountEmail: string;
  calendarId: string;
  events: IcalSourceEvent[];
};

function hash(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

function escapeText(value: string): string {
  return value
    .replace(/\\/g, "\\\\")
    .replace(/;/g, "\\;")
    .replace(/,/g, "\\,")
    .replace(/\r?\n/g, "\\n");
}

function fold(line: string): string {
  const encoder = new TextEncoder();
  const out: string[] = [];
  let current = "";
  let bytes = 0;
  for (const char of line) {
    const charBytes = encoder.encode(char).byteLength;
    if (bytes + charBytes > 75) {
      out.push(current);
      current = ` ${char}`;
      bytes = 1 + charBytes;
    } else {
      current += char;
      bytes += charBytes;
    }
  }
  out.push(current);
  return out.join("\r\n");
}

function utcTimestamp(value: string | undefined, fallback: Date): string {
  const date = value ? new Date(value) : fallback;
  if (Number.isNaN(date.getTime())) return utcTimestamp(undefined, fallback);
  return date
    .toISOString()
    .replace(/[-:]/g, "")
    .replace(/\.\d{3}/, "");
}

function dateValue(value: string): string {
  return value.replace(/-/g, "");
}

function timedValue(value: string): string {
  return utcTimestamp(value, new Date(0));
}

function isDeclined(event: IcalSourceEvent): boolean {
  return (
    event.attendees?.some(
      (attendee) => attendee.self && attendee.responseStatus === "declined",
    ) === true
  );
}

function projectEvent(
  feedId: string,
  source: Omit<IcalSource, "events">,
  event: IcalSourceEvent,
  disclosure: PublishedDisclosure,
  generatedAt: Date,
): string[] | null {
  if (!event.id || isDeclined(event)) return null;
  if (
    event.transparency === "transparent" ||
    event.eventType === "workingLocation" ||
    event.eventType === "birthday"
  )
    return null;
  const uid = `${hash(`${feedId}\u0000${source.accountEmail}\u0000${source.calendarId}\u0000${event.id}`)}@agent-native-calendar`;
  if (event.status === "cancelled") {
    const originalStart = event.originalStartTime ?? event.start;
    const lines = [
      "BEGIN:VEVENT",
      `UID:${uid}`,
      `DTSTAMP:${utcTimestamp(event.updated ?? event.created, generatedAt)}`,
      `LAST-MODIFIED:${utcTimestamp(event.updated ?? event.created, generatedAt)}`,
      `SEQUENCE:${Number.isSafeInteger(event.sequence) ? event.sequence : 0}`,
      "STATUS:CANCELLED",
      "SUMMARY:Busy",
    ];
    if (originalStart?.date) {
      lines.push(`DTSTART;VALUE=DATE:${dateValue(originalStart.date)}`);
    } else if (originalStart?.dateTime) {
      lines.push(`DTSTART:${timedValue(originalStart.dateTime)}`);
    }
    lines.push("END:VEVENT");
    return lines;
  }
  if (!event.start || !event.end) return null;
  const allDay = Boolean(
    event.start.date &&
    !event.start.dateTime &&
    event.end.date &&
    !event.end.dateTime,
  );
  if (!allDay && (!event.start.dateTime || !event.end.dateTime)) return null;
  const privateEvent =
    event.visibility === "private" || event.visibility === "confidential";
  const lines = [
    "BEGIN:VEVENT",
    `UID:${uid}`,
    `DTSTAMP:${utcTimestamp(event.updated ?? event.created, generatedAt)}`,
    `LAST-MODIFIED:${utcTimestamp(event.updated ?? event.created, generatedAt)}`,
    `SEQUENCE:${Number.isSafeInteger(event.sequence) ? event.sequence : 0}`,
    "STATUS:CONFIRMED",
    "TRANSP:OPAQUE",
    `SUMMARY:${escapeText(disclosure === "titles" && !privateEvent ? event.summary || "Busy" : "Busy")}`,
  ];
  if (allDay) {
    lines.push(
      `DTSTART;VALUE=DATE:${dateValue(event.start.date!)}`,
      `DTEND;VALUE=DATE:${dateValue(event.end.date!)}`,
    );
  } else {
    lines.push(
      `DTSTART:${timedValue(event.start.dateTime!)}`,
      `DTEND:${timedValue(event.end.dateTime!)}`,
    );
  }
  lines.push("END:VEVENT");
  return lines;
}

export function serializePublishedCalendar(input: {
  feedId: string;
  title: string;
  disclosure: PublishedDisclosure;
  sources: IcalSource[];
  generatedAt?: Date;
}): string {
  const generatedAt = input.generatedAt ?? new Date();
  const lines = [
    "BEGIN:VCALENDAR",
    "VERSION:2.0",
    "PRODID:-//Agent Native//Calendar Published Feed//EN",
    "CALSCALE:GREGORIAN",
    `X-WR-CALNAME:${escapeText(input.title)}`,
  ];
  for (const source of input.sources) {
    for (const event of source.events) {
      const projected = projectEvent(
        input.feedId,
        source,
        event,
        input.disclosure,
        generatedAt,
      );
      if (projected) lines.push(...projected);
    }
  }
  lines.push("END:VCALENDAR");
  return lines.map(fold).join("\r\n") + "\r\n";
}
