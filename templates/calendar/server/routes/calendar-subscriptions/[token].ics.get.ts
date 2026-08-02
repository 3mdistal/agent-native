import { defineEventHandler, getHeader, getRouterParam } from "h3";

import { getPublishedCalendarFeed } from "../../handlers/published-calendar-feed.js";

export default defineEventHandler(async (event) => {
  const token = getRouterParam(event, "token") ?? "";
  return getPublishedCalendarFeed(token, getHeader(event, "if-none-match"));
});
