import { getDbExec } from "@agent-native/core/db";

const WINDOW_MS = 5 * 60 * 1000;
const REQUEST_LIMIT = 30;
const RETENTION_MS = 60 * 60 * 1000;

export class PublishedCalendarRateLimitError extends Error {
  readonly statusCode = 429;
  readonly retryAfterSeconds: number;

  constructor(retryAfterSeconds: number) {
    super("Published calendar feed rate limit exceeded");
    this.name = "PublishedCalendarRateLimitError";
    this.retryAfterSeconds = retryAfterSeconds;
  }
}

export async function consumePublishedCalendarFeedRequest(
  tokenHash: string,
  now = new Date(),
): Promise<void> {
  const db = getDbExec();
  const windowStartMs = Math.floor(now.getTime() / WINDOW_MS) * WINDOW_MS;
  const windowStart = new Date(windowStartMs).toISOString();
  let rows: unknown[];
  try {
    ({ rows } = await db.execute({
      sql: `INSERT INTO published_calendar_feed_limits
  (token_hash, window_start, request_count, updated_at)
VALUES (?, ?, 1, ?)
ON CONFLICT (token_hash, window_start) DO UPDATE SET
  request_count = published_calendar_feed_limits.request_count + 1,
  updated_at = excluded.updated_at
WHERE published_calendar_feed_limits.request_count < ${REQUEST_LIMIT}
RETURNING request_count`,
      args: [tokenHash, windowStart, now.toISOString()],
    }));
  } catch {
    throw new Error("Unable to enforce published calendar feed rate limit");
  }

  if (rows.length === 0) {
    const retryAfterSeconds = Math.max(
      1,
      Math.ceil((windowStartMs + WINDOW_MS - now.getTime()) / 1000),
    );
    throw new PublishedCalendarRateLimitError(retryAfterSeconds);
  }

  try {
    await db.execute({
      sql: `DELETE FROM published_calendar_feed_limits WHERE updated_at < ?`,
      args: [new Date(now.getTime() - RETENTION_MS).toISOString()],
    });
  } catch {
    throw new Error("Unable to record published calendar feed rate limit");
  }
}
