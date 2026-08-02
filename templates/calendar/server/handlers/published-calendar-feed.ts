import {
  generatePublishedCalendarFeed,
  PublishedCalendarFeedError,
} from "../lib/published-calendar-feed.js";

export async function getPublishedCalendarFeed(
  token: string,
  ifNoneMatch?: string,
): Promise<Response> {
  try {
    const { body, etag } = await generatePublishedCalendarFeed(token);
    const headers = new Headers({
      "Content-Type": "text/calendar; charset=utf-8",
      "Content-Disposition": "inline; filename=calendar.ics",
      "Referrer-Policy": "no-referrer",
      "Cache-Control": "private, max-age=300, must-revalidate",
      ETag: etag,
    });
    if (ifNoneMatch === etag)
      return new Response(null, { status: 304, headers });
    return new Response(body, { status: 200, headers });
  } catch (error) {
    const status =
      error instanceof PublishedCalendarFeedError ? error.statusCode : 503;
    const retryAfter =
      status === 429 && error instanceof PublishedCalendarFeedError
        ? String(error.retryAfterSeconds ?? 1)
        : undefined;
    return new Response(
      status === 404
        ? "Not found"
        : status === 429
          ? "Too many calendar refreshes. Try again shortly."
          : "Calendar feed is temporarily unavailable",
      {
        status,
        headers: {
          "Content-Type": "text/plain; charset=utf-8",
          "Referrer-Policy": "no-referrer",
          "Cache-Control": "no-store",
          ...(retryAfter ? { "Retry-After": retryAfter } : {}),
        },
      },
    );
  }
}
