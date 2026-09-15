import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const openThread = vi.hoisted(() => vi.fn());

vi.mock("./agent-chat.js", () => ({
  requestAgentChatThreadOpen: openThread,
}));

vi.mock("./api-path.js", () => ({
  agentNativePath: (path: string) => path,
}));

import {
  cancelBackgroundAgentSession,
  getBackgroundAgentSessionStatus,
  startBackgroundAgentSession,
} from "./background-agent-session.js";

function streamResponse(): Response {
  return new Response(
    new ReadableStream({
      start(controller) {
        controller.enqueue(new TextEncoder().encode("event: run_started\n\n"));
        controller.close();
      },
    }),
    { status: 200, headers: { "Content-Type": "text/event-stream" } },
  );
}

describe("background agent sessions", () => {
  beforeEach(() => {
    openThread.mockReset();
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => streamResponse()),
    );
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("starts fresh isolated threads without touching the foreground chat UI", async () => {
    const first = startBackgroundAgentSession({ message: "First" });
    const second = startBackgroundAgentSession({ message: "Second" });
    await Promise.all([first.accepted, second.accepted]);
    await Promise.all([first.completion, second.completion]);

    expect(first.threadId).not.toBe(second.threadId);
    expect(first.operationId).not.toBe(second.operationId);
    expect(openThread).not.toHaveBeenCalled();
  });

  it("carries stable identity, scope, model selection, and instructions through the shared route", async () => {
    const fetchMock = vi.mocked(fetch);
    const handle = startBackgroundAgentSession({
      message: "Reply to the comment",
      operationId: "operation-1",
      threadId: "thread-1",
      scope: { type: "content-comment-ai", id: "comment-7" },
      actionScope: {
        kind: "content-comment-ai",
        requestId: "request-7",
        intent: "reply",
      },
      mode: "act",
      model: "gpt-5.6-sol",
      engine: "openai",
      effort: "medium",
      instructions: "Use only the supplied comment context.",
      usageLabel: "content:comment-ai",
    });
    await handle.accepted;

    expect(fetchMock).toHaveBeenCalledOnce();
    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe("/_agent-native/agent-chat");
    expect(JSON.parse(String(init?.body))).toMatchObject({
      message:
        "Reply to the comment\n\n<context>\nUse only the supplied comment context.\n</context>",
      displayMessage: "Reply to the comment",
      queuedMessageId: "operation-1",
      turnId: "operation-1",
      threadId: "thread-1",
      scope: { type: "content-comment-ai", id: "comment-7" },
      actionScope: {
        kind: "content-comment-ai",
        requestId: "request-7",
        intent: "reply",
      },
      mode: "act",
      model: "gpt-5.6-sol",
      engine: "openai",
      effort: "medium",
      usageLabel: "content:comment-ai",
    });
  });

  it("rejects an invalid action scope before dispatch", () => {
    expect(() =>
      startBackgroundAgentSession({
        message: "Reply to the comment",
        actionScope: { invalid: undefined } as never,
      }),
    ).toThrow("actionScope must contain only JSON values");
    expect(fetch).not.toHaveBeenCalled();
  });

  it("atomically opens and prefills the exact background thread", () => {
    const handle = startBackgroundAgentSession({
      message: "Start",
      operationId: "operation-2",
      threadId: "thread-2",
    });
    handle.open({ prefill: "Continue this exact conversation" });

    expect(openThread).toHaveBeenCalledWith({
      threadId: "thread-2",
      prefill: "Continue this exact conversation",
    });
  });

  it("reports terminal status and keeps inaccessible sessions indistinguishable from missing ones", async () => {
    const fetchMock = vi.mocked(fetch);
    fetchMock
      .mockResolvedValueOnce(
        Response.json({
          status: "completed",
          runId: "run-1",
          terminalReason: null,
        }),
      )
      .mockResolvedValueOnce(Response.json({}, { status: 404 }));
    const receipt = {
      operationId: "operation-3",
      threadId: "thread-3",
      turnId: "operation-3",
    };

    await expect(getBackgroundAgentSessionStatus(receipt)).resolves.toEqual({
      ...receipt,
      status: "completed",
      runId: "run-1",
      terminalReason: null,
    });
    await expect(getBackgroundAgentSessionStatus(receipt)).resolves.toEqual({
      ...receipt,
      status: "unavailable",
    });
    expect(fetchMock.mock.calls.map(([url]) => url)).toEqual([
      "/_agent-native/agent-chat/runs/latest?threadId=thread-3&turnId=operation-3",
      "/_agent-native/agent-chat/runs/latest?threadId=thread-3&turnId=operation-3",
    ]);
  });

  it("atomically aborts the logical turn through the shared run manager", async () => {
    const fetchMock = vi.mocked(fetch);
    fetchMock.mockResolvedValueOnce(Response.json({ ok: true }));

    await cancelBackgroundAgentSession({
      threadId: "thread-4",
      turnId: "operation-4",
      reason: "dismissed",
    });

    expect(fetchMock.mock.calls.map(([url]) => url)).toEqual([
      "/_agent-native/agent-chat/runs/turn/operation-4/abort",
    ]);
  });

  it("waits for route acceptance before cancelling a newly created thread", async () => {
    let acceptStart!: (response: Response) => void;
    const fetchMock = vi.mocked(fetch);
    fetchMock
      .mockImplementationOnce(
        () =>
          new Promise<Response>((resolve) => {
            acceptStart = resolve;
          }),
      )
      .mockResolvedValueOnce(Response.json({ ok: true }));

    const handle = startBackgroundAgentSession({
      message: "Start then stop",
      operationId: "operation-5",
      threadId: "thread-5",
    });
    const cancellation = handle.cancel("dismissed");
    await Promise.resolve();
    expect(fetchMock).toHaveBeenCalledOnce();

    acceptStart(streamResponse());
    await cancellation;
    expect(fetchMock.mock.calls.map(([url]) => url)).toEqual([
      "/_agent-native/agent-chat",
      "/_agent-native/agent-chat/runs/turn/operation-5/abort",
    ]);
  });

  it("reports local queued state only before route acceptance", async () => {
    let acceptStart!: (response: Response) => void;
    const fetchMock = vi.mocked(fetch);
    fetchMock
      .mockImplementationOnce(
        () =>
          new Promise<Response>((resolve) => {
            acceptStart = resolve;
          }),
      )
      .mockResolvedValueOnce(Response.json({}, { status: 404 }));

    const handle = startBackgroundAgentSession({
      message: "Start and inspect status",
      operationId: "operation-6",
      threadId: "thread-6",
    });
    await expect(handle.status()).resolves.toEqual({
      operationId: "operation-6",
      threadId: "thread-6",
      turnId: "operation-6",
      status: "queued",
    });
    expect(fetchMock).toHaveBeenCalledOnce();

    acceptStart(streamResponse());
    await handle.accepted;
    await expect(handle.status()).resolves.toEqual({
      operationId: "operation-6",
      threadId: "thread-6",
      turnId: "operation-6",
      status: "unavailable",
    });
  });
});
