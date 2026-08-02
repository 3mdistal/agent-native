# Published composite calendar feed — feasibility and product shape

## Answer

Yes: Agent Native Calendar can feasibly publish one read-only iCalendar
subscription URL assembled from several calendars. The transport is ordinary
`https://…/calendar.ics` (also copyable as `webcal://…`), so a recipient can
subscribe from Google Calendar, Apple Calendar, Outlook, and other iCalendar
clients.

The hard part is not serializing events. It is deciding which events the owner
is allowed to republish, redacting them consistently, and making failures and
revocation safe. “I can see this calendar” does not imply “I can redistribute
this calendar.”

The recommended first slice is therefore:

> A user creates a **Published calendar**, explicitly selects calendars they
> own across their connected Google accounts, chooses **Busy only** or
> **Titles and times**, and receives one revocable possession link. Calendar
> clients can subscribe to the link but cannot write through it.

Coworker overlays and private third-party subscription feeds are deliberately
excluded from the first slice. They can be added later only when Agent Native
can prove that the source owner or publisher permits redistribution.

### Feasibility verdict

| Dimension | Verdict | Why |
| --- | --- | --- |
| Standards and client support | Feasible | iCalendar subscription by URL is broadly supported; subscriptions are read-only in Apple Calendar and refresh automatically in Outlook. |
| Existing Calendar read path | Strong starting point | `list-events` already merges connected Google accounts, coworker overlays, subscribed ICS feeds, and local bookings while preserving source-coverage failures. |
| Exact “all my Google calendars” support | Small but real gap | The first-class UI currently reads only each connected account’s `primary` calendar. Google’s `CalendarList` API can inventory secondary, subscribed, selected, and hidden Google calendars, and the app’s existing `calendar.readonly` OAuth scope is sufficient to read that list. |
| Public delivery | Feasible with a new boundary | A non-JSON, unauthenticated `.ics` route is an allowed framework exception, but it must resolve a hashed, revocable feed token to an owner-scoped composition. |
| Privacy and policy | Feasible only with source eligibility | Owned calendars can be an explicit user publication. Merely readable coworker calendars and private third-party feeds cannot safely be republished by default. |
| Operational reliability | Feasible with fail-closed delivery | A selected-source failure must return a non-success response or a still-valid last-known-good snapshot; it must never emit a plausible empty/partial calendar. |

## Demonstrated caller and request

The caller is a Calendar user who has connected a work and personal Google
account and wants a loved one to follow one combined, read-only schedule
without separately subscribing to every source.

Success means:

1. the owner intentionally chooses the sources and disclosure level;
2. one link can be subscribed to in an ordinary calendar client;
3. source changes flow through on the subscriber client’s next refresh;
4. the subscriber cannot edit source calendars;
5. excluded details and ineligible sources never leak;
6. the owner can stop or rotate the feed without touching the source calendars.

## Evidence

### What Calendar actually combines today

`listCalendarEvents` already fans out independent reads for:

- every connected Google account selected by `accountEmails`;
- up to ten coworker overlay email addresses;
- every saved external ICS feed; and
- local booking records.

It then merges and sorts those events
(`templates/calendar/actions/list-events.ts:575-755`). Its inventory response
also reports account and source coverage and computes `coverageComplete`
instead of treating a partial read as an empty calendar
(`templates/calendar/actions/list-events.ts:953-1021`).

There are three important constraints:

1. Each connected Google account is currently read through calendar ID
   `"primary"` (`templates/calendar/server/lib/google-calendar.ts:835-874`).
   Secondary or subscribed Google calendars are reachable through Google’s API
   substrate, but they are not yet first-class selectable sources in the main
   calendar view.
2. Coworker overlays are read by using one of the owner’s connected Google
   accounts to request the coworker’s calendar
   (`templates/calendar/server/lib/google-calendar.ts:1050-1137`). That proves
   viewer access, not redistribution permission.
3. The current visible/hidden composition is browser-local `localStorage`
   (`templates/calendar/app/hooks/use-hidden-calendars.ts:1-49`) and is applied
   after the server response
   (`templates/calendar/app/pages/CalendarView.tsx:495-534`). A published feed
   must use its own durable server-side source list rather than silently
   publishing “whatever happens to be visible in this browser.”

The current Google connection already requests
`https://www.googleapis.com/auth/calendar.readonly`
(`templates/calendar/server/lib/google-calendar.ts:39-47`). Google documents
that scope as sufficient to list the calendars a user can access. Calendar
list entries expose `primary`, `selected`, `hidden`, `accessRole`, and, for
secondary calendars, `dataOwner`. This gives the source picker enough
information to distinguish “in my list,” “I can manage it,” and “I am the data
owner.” [Google CalendarList resource](https://developers.google.com/workspace/calendar/api/v3/reference/calendarList)

### iCalendar is the correct output contract

[RFC 5545](https://www.rfc-editor.org/info/rfc5545/) defines the interoperable
iCalendar object and the stable event identity/versioning fields needed for
updates: `UID`, `DTSTAMP`, `RECURRENCE-ID`, and `SEQUENCE`. It also defines
all-day `DTEND` as non-inclusive.

[RFC 7986](https://www.rfc-editor.org/info/rfc7986/) adds calendar-level
`NAME`, `COLOR`, `SOURCE`, and `REFRESH-INTERVAL`; the interval is only a
suggestion to clients, not a promise of immediate refresh.

Apple documents URL subscriptions as provider-controlled and read-only.
[Apple subscription support](https://support.apple.com/en-gb/102301)
Microsoft documents URL subscriptions as automatically refreshed, but warns
that updates can sometimes take more than 24 hours.
[Microsoft subscription support](https://support.microsoft.com/en-US/Outlook/import-or-subscribe-to-a-calendar-in-outlook-com-or-outlook-on-the-web)
The product promise must therefore be “updates on the subscriber client’s next
refresh,” never “instant sync.”

The existing inbound ICS parser is not a suitable outbound serializer. It
extracts only a small subset of `VEVENT` fields, does not preserve recurrence
rules or timezone definitions, and treats an unparsed duration as zero length
(`templates/calendar/server/lib/ical-fetcher.ts:129-214`). Publishing needs a
dedicated, standards-tested serializer.

### Visibility is not redistribution permission

Google’s calendar list exposes an effective `accessRole`, but explicitly notes
that the `owner` role is different from the calendar’s data owner.
[Google CalendarList resource](https://developers.google.com/workspace/calendar/api/v3/reference/calendarList)
Google Workspace can also cap external sharing at the domain level, including
free/busy-only access.
[Google calendar sharing model](https://developers.google.com/workspace/calendar/api/concepts/sharing)

Google’s API terms say that non-public content obtained through an API may not
be exposed to another user or third party without the relevant user’s explicit
opt-in, and prohibit redistribution without the content owner’s permission.
[Google APIs Terms of Service](https://developers.google.com/terms)
Google’s User Data Policy separately requires prominent, timely disclosure of
how Google user data is accessed, stored, and shared.
[Google API Services User Data Policy](https://developers.google.com/terms/api-services-user-data-policy)

That makes the source policy:

| Source | First-slice eligibility | Reason |
| --- | --- | --- |
| Primary Google calendar of a connected account | Yes, with explicit publication consent | The connected user is the primary calendar’s owner. |
| Secondary Google calendar whose `dataOwner` is a connected account identity | Yes, with explicit publication consent | Data ownership can be proven, not merely inferred from access role. |
| Google calendar already public at the chosen disclosure level | Yes | Republishing does not widen the source’s disclosed detail level. |
| Coworker/person overlay | No | Read access is not consent to pass the events onward. |
| Google calendar merely shared with the user (`reader`, `writer`, or delegated `owner`) | No by default | `accessRole` is not data ownership; delegated owner is explicitly distinct. |
| External ICS feed | No by default | A secret or readable feed URL proves access, not a redistribution license. |
| Local bookings | Defer | They contain guest identity, notes, and meeting links; the linked Google event is already the visible source of truth in most successful cases. |

For Workspace-managed owned calendars, Work must add a fail-closed external
sharing eligibility check or keep the source unavailable. The app must not use a
derived feed to route around an administrator’s sharing ceiling.

## Product shape

### Vocabulary

- **Published calendar** — the user-authored composition and its disclosure
  policy.
- **Subscription link** — the possession URL a calendar client reads.
- **Source calendar** — one explicitly selected eligible calendar.
- **Busy only** — publish opaque busy intervals with no source event title.
- **Titles and times** — publish the event title and time, with sensitive fields
  still removed.

“Public calendar” is intentionally avoided. The link is unlisted and
possession-gated, but anyone who obtains it can read it.

### Creation flow

1. Choose **Publish calendar** from Calendar.
2. Name the published calendar.
3. Select eligible source calendars grouped by connected account.
4. Choose disclosure:
   - **Busy only** — recommended default.
   - **Titles and times** — explicit higher-disclosure choice.
5. Review a concrete preview showing what will and will not be exposed.
6. Publish and copy one `webcal://`/HTTPS subscription link.

The review must say plainly:

- included calendars;
- calendars that are ineligible and why;
- whether titles are exposed;
- that descriptions, locations, attendees, conference links, attachments,
  organizer identity, source URLs, and provider IDs are never exposed in v1;
- that anyone with the link can read the feed;
- how to stop sharing or rotate the link; and
- that subscriber refresh timing is controlled by the recipient’s calendar
  client.

Private/confidential events are always reduced to busy blocks. Transparent
events are omitted from **Busy only** because they do not represent occupied
time. Declined events are omitted. Working-location events and birthdays are
deferred until their disclosure semantics are deliberately designed.

### Management flow

A **Published calendars** surface lists each composition, disclosure level,
source count, link state, last successful generation, and current source
health. The owner can:

- edit source selection or disclosure;
- copy the subscription link immediately after publishing or rotation; because
  only its hash is retained, recovering a link later requires rotation;
- rotate the link (with a warning that existing subscribers will stop);
- stop publishing immediately; and
- delete the composition after publishing has stopped.

Framework resource sharing governs who may help manage the composition inside
Agent Native. The anonymous subscription link is a separate axis, matching the
framework’s existing distinction between resource sharing and public slugs.

## Governing architecture

### Existing primitives and intentional seams

- Actions remain the source of truth for creating, editing, listing, rotating,
  and stopping published calendars.
- Google credential resolution stays in the existing owner-scoped Google
  integration; public requests never receive provider tokens.
- `CalendarList` inventory should use the existing Google provider/API seam,
  then become a focused Calendar action because it is part of the ordinary
  source-picker workflow.
- The standard framework sharing registry manages authenticated collaborators
  on a Published calendar, just as it already does for booking links
  (`templates/calendar/server/db/schema.ts:36-78`,
  `templates/calendar/server/db/index.ts:9-17`).
- A non-JSON public route is the correct exception for
  `GET /calendar-subscriptions/{token}.ics`.
- Core’s chat-thread sharing implementation is a direct token precedent:
  random bearer tokens are stored only as SHA-256 hashes, resolved by indexed
  equality, and revocable
  (`packages/core/src/chat-threads/store.ts:1092-1097,1153-1269`).

### Smallest compatible delta

1. Add additive, dialect-agnostic SQL tables:
   - `published_calendars`: identity, title, disclosure policy, owner/org,
     active state, token hash, timestamps, and last successful generation
     metadata;
   - `published_calendar_sources`: parent ID, provider, connected account ID,
     source calendar ID, source ownership/eligibility snapshot, and source
     label;
   - `published_calendar_shares`: standard framework share grants.
2. Add source-inventory and Published-calendar management actions.
3. Split the current aggregation logic into an owner-explicit server service:
   authenticated actions get the owner from request context; the public route
   gets the owner only by resolving the opaque feed token. Shared helpers take
   the owner email as a parameter. The public route must not impersonate a
   browser session or call an authenticated action through HTTP.
4. Add a dedicated iCalendar projection/serializer:
   - bounded horizon (recommended: 30 days past through 365 days future);
   - stable derived UID per published calendar + source + provider event
     occurrence;
   - correct all-day, timezone, recurrence/occurrence, cancellation, escaping,
     line folding, `DTSTAMP`, and `LAST-MODIFIED` behavior;
   - no write-capable URLs or source credentials.
5. Add the public `.ics` route:
   - resolve only a hashed active token;
   - `Content-Type: text/calendar; charset=utf-8`;
   - `Content-Disposition: inline`;
   - `Referrer-Policy: no-referrer`;
   - private short-lived caching plus `ETag`/conditional GET;
   - rate limits and bounded event/source counts;
   - identical not-found behavior for unknown, rotated, revoked, and deleted
     tokens.
6. If any selected source is unreadable or eligibility can no longer be
   proven, return a non-success response and preserve the subscriber’s prior
   copy. Never serialize a partial or empty success. Do not put event payloads
   in SQL; if a later design needs a last-known-good body, use configured
   private blob storage with a bounded retention policy and persist only its
   handle.
7. Add a progressively disclosed management UI, navigation/application state,
   agent instructions, and a default-off feature flag
   `calendar.published-feeds`.

### Domain boundaries

- **Google Calendar** owns events, calendar ACLs, connected account identity,
  and source visibility.
- **Calendar template SQL** owns the user’s composition, disclosure decision,
  subscription-token hash, source references, and health metadata.
- **Framework sharing** owns authenticated management grants; it does not
  authorize anonymous feed reads.
- **The `.ics` route** owns read-only transport and projection only. It must
  never mutate Google or accept event writes.
- **Subscriber clients** own polling frequency and local display behavior.

### Legacy contracts that must remain unchanged

- Existing calendar display continues to merge Google primary calendars,
  overlays, external ICS, and bookings exactly as today.
- Existing `list-events` account/source coverage remains explicit; a partial
  read never becomes “no events.”
- Browser-local hide/show state remains a personal display preference and does
  not silently alter any published composition.
- External ICS ingestion remains read-only and SSRF-protected.
- Booking-link public access and framework management sharing remain separate.
- Google event writes continue to target the selected connected account’s
  primary calendar.

### Deferred capabilities

- coworker overlays or delegated calendars with source-owner opt-in;
- private third-party ICS feeds with verifiable redistribution permission;
- per-recipient links, subscriber identities, passwords, or expiry;
- CalDAV write support;
- HTML calendar pages and search/indexing;
- location, description, attendee, conferencing, attachment, organizer, and
  source-link disclosure;
- local bookings, working locations, birthdays, tasks, and appointment
  schedules;
- push-triggered materialization, long-term event snapshots, and analytics on
  individual subscriber activity.

## Failure and privacy invariants

1. A failed source is not an empty source.
2. A partial feed is not a successful feed.
3. A connected-account identity is not proof of ownership of every calendar in
   that account’s CalendarList.
4. A Google `owner` access role is not the same as `dataOwner`.
5. A readable coworker calendar or possession of an ICS URL is not a
   redistribution license.
6. The raw subscription token is returned only when created or rotated, is
   stored only as a hash, and is never written to logs or analytics.
7. Stopping or rotating publishing invalidates the old URL immediately at the
   origin; client-side cached copies cannot be remotely erased.
8. Every event gets a stable feed-scoped UID so two source calendars cannot
   collide and one source’s provider identifier is not disclosed.
9. No description, location, attendee list, conference credential, attachment,
   provider URL, or source feed URL leaves the public route in v1.
10. Publisher activity is not inferred from subscriber polling; RFC 7986 notes
    that individualized refresh URLs can reveal subscriber IP/activity, so the
    product should avoid unnecessary tracking.

## Acceptance story

### Successful-user story

Alice connects one personal and one work Google account, creates “Alice with
family,” selects one eligible owned calendar from each account, chooses
**Titles and times**, subscribes to the single link from a separate Google
Calendar or Apple Calendar account, and sees the intended schedule without any
excluded details. Changes arrive on a forced re-fetch/next client refresh.
Alice stops publishing and the URL can no longer be fetched.

### Required assertions

1. **Source inventory:** Calendar lists primary and secondary Google calendars
   with account, calendar ID, ownership, access role, and eligibility; coworker
   and private third-party sources are visibly unavailable, not silently
   omitted.
2. **Management isolation:** only the owner/admin can create, edit, rotate,
   stop, or delete a Published calendar; framework viewers remain read-only.
3. **Projection:** timed, all-day, multi-day, DST-crossing, recurring, moved,
   cancelled, private, declined, and transparent fixtures serialize according
   to the frozen disclosure rules with stable UIDs.
4. **Redaction:** descriptions, locations, attendees, conference data,
   attachments, organizer/source identities, HTML links, provider IDs, and raw
   source URLs are absent from generated output.
5. **Coverage:** one selected-source/auth/eligibility failure produces a
   non-success response, never `200` with partial or empty calendar data.
6. **Possession-link safety:** database/log inspection finds only token hashes;
   unknown/revoked/rotated tokens reveal nothing; old links stop and new links
   work.
7. **Interoperability:** the exact generated feed passes a standards parser and
   is successfully subscribed to in current Google Calendar and Apple Calendar
   clients; update and removal behavior is observed, with refresh latency
   reported rather than guessed.
8. **No source mutation:** provider and SQL evidence show subscription reads,
   link rotation, and unpublishing never create, update, delete, RSVP to, or
   share a source event/calendar.
9. **Legacy behavior:** existing focused Calendar action/UI tests remain green,
   including source coverage, overlay reads, external ICS ingestion, booking
   deduplication, and multi-account event writes.
10. **Feature flag:** `calendar.published-feeds` is proven off on every named
    shipping surface before integration; controlled post-integration
    validation must pass before enablement.

## Recommendation

Proceed eventually, but name the feature **Published calendars**, not “share
my current view.” The explicit source list is the product: it makes the
composition durable, reviewable, and safe.

The smallest useful release should support owned Google calendars across
multiple connected accounts, default to **Busy only**, offer **Titles and
times** as an explicit disclosure step, and expose one revocable subscription
link. Do not include coworker overlays or private external feeds in v1.

This slice solves the intimate work-plus-personal use case without turning
Calendar’s unusually powerful read surface into an accidental redistribution
surface.

## Authorized implementation plan

Alice authorized Work on 2026-07-29 against the product and architecture
fingerprint above. Work stays on the current checkout and may change local
source, additive schema declarations, tests, instructions, and this governing
artifact. It does not include branch operations, commits, pushes, pull requests,
deployment, feature-flag rollout, or merge.

1. **Establish the source contract.** Add an owner-explicit Google CalendarList
   inventory that returns connected account identity, calendar identity,
   effective access, ownership evidence, and a concrete eligibility reason.
   Keep coworker overlays, external ICS feeds, and sources whose ownership or
   Workspace sharing ceiling cannot be proven out of the selectable set.
2. **Add the durable resource.** Add dialect-agnostic SQL for Published
   calendars, selected source rows, and standard framework share grants. Store
   only a random token hash, never the raw subscription token. Register the
   resource for authenticated management sharing and scope every management
   read/write through framework access controls.
3. **Add one orthogonal action surface.** Provide focused source inventory plus
   list/create/update/rotate/stop/delete actions. The UI and agent use these
   actions; the unauthenticated feed route resolves its token directly through
   an owner-explicit server service rather than impersonating an action caller.
4. **Project and deliver iCalendar.** Fetch each selected source within fixed
   bounds, fail the entire request if any source becomes unavailable or
   ineligible, redact according to the frozen disclosure policy, and serialize
   stable standards-conformant output from the public non-JSON route.
5. **Expose management with parity.** Add a progressively disclosed Published
   calendars surface with source selection, disclosure review, link copy,
   rotation, stopping, and deletion. Keep navigation/application state and
   `view-screen`/`navigate` aware of the surface, and document the actions and
   privacy boundary for the agent.
6. **Gate and verify.** Register `calendar.published-feeds` default-off on both
   server and client paths, add the user-facing changelog entry, format changed
   source, run focused unit/integration tests and guards, and obtain an
   independent security/coverage review. Real Google Calendar and Apple
   Calendar subscription acceptance remains a post-integration gate because it
   requires a reachable deployed feed and live client accounts.

## Architecture grounding record

```yaml
applicability: required
reason: >
  The feature crosses authentication, Google provider ACLs, shared SQL
  resources, anonymous public transport, and a public interoperability
  protocol.
status: grounded
demonstrated-callers:
  - Calendar owner combines owned work and personal calendars for a loved one's read-only subscription.
existing-primitives:
  - coverage-aware multi-source list-events aggregation
  - owner-scoped Google OAuth tokens and calendar.readonly scope
  - Google provider API substrate
  - framework ownable resources and share grants
  - non-JSON/public route exception
  - hashed and revocable share-token precedent in Core chat threads
ownership-boundaries:
  - Google owns events, source ACLs, and calendar identities
  - Calendar SQL owns compositions, disclosure policy, and token hashes
  - framework sharing owns authenticated management access
  - public ICS route owns read-only projection and transport
legacy-contracts:
  - existing Calendar UI aggregation and coverage semantics
  - local hide/show remains display-only
  - provider writes remain primary-calendar/account scoped
  - booking-link public access and management sharing remain separate
shared-vocabulary:
  - Published calendar
  - subscription link
  - source calendar
  - Busy only
  - Titles and times
smallest-compatible-delta: >
  One additive ownable Published-calendar resource, explicit eligible Google
  source rows, management actions/UI/state/instructions, and one hashed-token
  read-only ICS route behind a default-off feature flag.
deferred-capabilities:
  - coworker and delegated calendar redistribution
  - private external ICS redistribution
  - per-recipient identity and CalDAV
  - sensitive event fields and HTML views
reversibility: >
  Additive tables and a default-off flag isolate the feature; every feed can be
  individually stopped or rotated without mutating source calendars.
direct-evidence:
  - templates/calendar/actions/list-events.ts:575-755
  - templates/calendar/actions/list-events.ts:953-1021
  - templates/calendar/server/lib/google-calendar.ts:39-47
  - templates/calendar/server/lib/google-calendar.ts:835-874
  - templates/calendar/server/lib/google-calendar.ts:1050-1137
  - templates/calendar/app/hooks/use-hidden-calendars.ts:1-49
  - templates/calendar/server/db/schema.ts:36-78
  - templates/calendar/server/db/index.ts:9-17
  - packages/core/src/chat-threads/store.ts:1092-1097,1153-1269
  - RFC 5545 and RFC 7986
  - Google CalendarList, sharing, API terms, and User Data Policy
inferences:
  - A standards-conformant feed will interoperate beyond the two explicitly accepted clients.
  - Subscriber refresh latency will vary by client and cannot be controlled by Calendar.
unresolved-owner-questions: []
```

## Lifecycle envelope

```yaml
stage: work
authority-source: >
  Alice's 2026-07-29 instruction to shape the remaining implementation plan and
  then work that plan, following her 2026-07-28 Shape request.
authorized-scope:
  repositories:
    - /Users/alicemoore/.codex/worktrees/6ba9/agent-native
  product-surfaces:
    - Agent Native Calendar Published calendars
  outcome: >
    Implement the authorized first slice of Calendar Published calendars on the
    current checkout and verify it as far as local and independent evidence allow.
allowed-mutations:
  - artifact-write
  - source
  - additive-schema-source
  - tests
  - instructions
write-targets:
  artifacts:
    - plans/published-composite-calendar-feed/feasibility.md
  source-roots:
    - templates/calendar/actions
    - templates/calendar/app
    - templates/calendar/server
    - templates/calendar/shared
    - templates/calendar/AGENTS.md
    - templates/calendar/changelog
governing-artifact:
  path: plans/published-composite-calendar-feed/feasibility.md
  revision: work-r2
architecture-fingerprint:
  outcome: >
    A user can publish one revocable read-only subscription feed from explicitly
    selected eligible calendars they own across connected Google accounts.
  shipping-surfaces:
    - id: agent-native-calendar-template
      repository: agent-native
      product-surface: Calendar template UI, actions, SQL, instructions, and public ICS route
      constituency: source-blind Agent Native Calendar users and developers
      durable-destination: public Agent Native repository Calendar template
      integration-action: merge
    - id: hosted-calendar-enablements
      repository: agent-native
      product-surface: hosted Calendar deployments using the template
      constituency: Calendar publishers and possession-link subscribers
      durable-destination: opted-in hosted Calendar deployments
      integration-action: deploy
  governing-architecture: >
    SQL owns an explicit ownable composition and hashed revocable link; Google
    remains event/ACL source of truth; a non-JSON public route projects only
    eligible owner-scoped events into redacted iCalendar without source writes.
  acceptance-story:
    id: published-calendar-family-v1
    summary: >
      Alice combines one eligible owned work calendar and one eligible owned
      personal calendar, subscribes from a separate client, observes correct
      redacted updates, and can stop the feed.
    required-assertions:
      - source eligibility and ownership are proven
      - owner/admin management access is isolated
      - iCalendar projection and stable identity are standards-correct
      - sensitive fields are absent
      - source failures never become partial or empty success
      - token storage, rotation, and revocation are safe
      - current Google Calendar and Apple Calendar subscription acceptance passes
      - source calendars are never mutated
      - legacy Calendar behavior remains unchanged
      - feature flag is off before integration and controlled validation precedes enablement
  risk-strategy:
    kind: feature-flagged
    production-validation-after-merge: true
delegation-ceiling:
  - read-only repository inventory via terra-explorer
  - isolated implementation or verification via terra-worker with exact file ownership
  - independent successful-user-story execution via human-qa-tester when a runnable surface exists
acceptance-state:
  status: in-progress
  summary: >
    The default-off local implementation is complete and technically green.
    Live Google source behavior plus Google Calendar and Apple Calendar
    subscription acceptance have not occurred.
  evidence:
    - Calendar typecheck passed.
    - Calendar Vitest passed with 55 files and 337 tests.
    - Calendar production client, SSR, and Nitro build passed.
    - i18n catalog, no-action-twin-route, agent-chat-context, and workspace-skill guards passed.
    - Independent security review found no remaining static release blocker after admin-only mutation, atomic durable rate limiting, explicit Workspace public-default ACL proof, and cancellation tombstones were added.
    - The calendar.published-feeds flag defaults off and gates UI, actions, and the public feed.
    - Independent real-interface preflight reached the healthy local sign-in surface, but could not begin the authenticated default-off story because no disposable signed-in Calendar session was available.
  blockers:
    - Real Google Workspace ACL behavior needs controlled validation with a live eligible owned work calendar.
    - The exact generated feed still needs standards-parser acceptance and subscription/update/removal observation in current Google Calendar and Apple Calendar clients.
    - Full successful-user-story QA needs a reachable feed, live Google accounts, and a non-shipping flag enablement after integration.
    - Authenticated local default-off navigation QA needs a disposable signed-in Calendar browser session.
ledger-revision: work-published-calendar-r2
status: active
```

## Sources

- [Google CalendarList resource](https://developers.google.com/workspace/calendar/api/v3/reference/calendarList)
- [Google CalendarList list method](https://developers.google.com/workspace/calendar/api/v3/reference/calendarList/list)
- [Google Calendar sharing model](https://developers.google.com/workspace/calendar/api/concepts/sharing)
- [Google Calendar API scopes](https://developers.google.com/workspace/calendar/api/auth)
- [Google Calendar incremental synchronization](https://developers.google.com/workspace/calendar/api/guides/sync)
- [Google API Services User Data Policy](https://developers.google.com/terms/api-services-user-data-policy)
- [Google APIs Terms of Service](https://developers.google.com/terms)
- [RFC 5545: iCalendar](https://www.rfc-editor.org/info/rfc5545/)
- [RFC 7986: New Properties for iCalendar](https://www.rfc-editor.org/info/rfc7986/)
- [Apple calendar subscriptions](https://support.apple.com/en-gb/102301)
- [Microsoft calendar subscriptions](https://support.microsoft.com/en-US/Outlook/import-or-subscribe-to-a-calendar-in-outlook-com-or-outlook-on-the-web)
