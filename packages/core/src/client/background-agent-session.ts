import {
  normalizeAgentActionScope,
  type AgentActionScope,
  type AgentChatAttachment,
  type AgentChatScope,
} from "../agent/types.js";
import { appendAgentChatContextToMessage } from "../shared/agent-chat-context.js";
import type { ReasoningEffort } from "../shared/reasoning-effort.js";
import { requestAgentChatThreadOpen } from "./agent-chat.js";
import { agentNativePath } from "./api-path.js";

export type BackgroundAgentSessionStatus =
  | "queued"
  | "running"
  | "completed"
  | "truncated"
  | "errored"
  | "aborted"
  | "unavailable";

export interface BackgroundAgentSessionStartOptions {
  /** The visible first user turn. */
  message: string;
  /** Stable caller-owned operation id. Reuse it when retrying a lost acknowledgement. */
  operationId?: string;
  /** Stable thread id. Supply it with operationId when retrying the same operation. */
  threadId?: string;
  /** Explicit app/resource boundary persisted on the thread. */
  scope?: AgentChatScope | null;
  /** App-defined boundary for the actions exposed to this turn. */
  actionScope?: AgentActionScope;
  mode?: "act" | "plan";
  model?: string;
  engine?: string;
  effort?: ReasoningEffort;
  instructions?: string;
  attachments?: AgentChatAttachment[];
  usageLabel?: string;
}

export interface BackgroundAgentSessionReceipt {
  operationId: string;
  threadId: string;
  turnId: string;
}

export interface BackgroundAgentSessionSnapshot extends BackgroundAgentSessionReceipt {
  status: BackgroundAgentSessionStatus;
  runId?: string;
  terminalReason?: string | null;
}

export interface BackgroundAgentSessionHandle extends BackgroundAgentSessionReceipt {
  /** Resolves once the shared agent-chat route accepts the run. */
  accepted: Promise<BackgroundAgentSessionReceipt>;
  /** Resolves when the response stream closes. The durable run survives this browser surface. */
  completion: Promise<void>;
  status(): Promise<BackgroundAgentSessionSnapshot>;
  cancel(reason?: string): Promise<void>;
  open(options?: { prefill?: string }): void;
}

function generateSessionId(prefix: string): string {
  const id = globalThis.crypto?.randomUUID?.();
  return id
    ? `${prefix}-${id}`
    : `${prefix}-${Date.now()}-${Math.random().toString(36).slice(2, 10)}`;
}

function requiredId(value: string | undefined, prefix: string): string {
  const normalized = value?.trim();
  return normalized || generateSessionId(prefix);
}

function turnIdForReceipt(threadId: string, operationId: string): string {
  const input = `${threadId}\0${operationId}`;
  let first = 0xcbf29ce484222325n;
  let second = 0x84222325cbf29ce4n;
  for (const byte of new TextEncoder().encode(input)) {
    first = BigInt.asUintN(64, (first ^ BigInt(byte)) * 0x100000001b3n);
    second = BigInt.asUintN(64, (second ^ BigInt(byte)) * 0x100000001b3n);
  }
  return `background-turn-${first.toString(16).padStart(16, "0")}${second
    .toString(16)
    .padStart(16, "0")}`;
}

async function responseError(response: Response): Promise<Error> {
  const body = await response
    .json()
    .catch(() => null as { error?: unknown } | null);
  const detail =
    body && typeof body.error === "string" && body.error.trim()
      ? `: ${body.error.trim()}`
      : "";
  return new Error(
    `Background agent session was rejected (HTTP ${response.status})${detail}`,
  );
}

async function drainResponse(response: Response): Promise<void> {
  const reader = response.body?.getReader();
  if (!reader) return;
  while (!(await reader.read()).done) {
    // Discard streaming presentation events. The shared run manager persists
    // the transcript and owns durable continuation.
  }
}

/**
 * Start one isolated agent-chat thread without mounting, opening, or focusing
 * chat UI. The normal agent-chat route owns authentication, model/tool
 * resolution, persistence, durable dispatch, retries, and deduplication.
 */
export function startBackgroundAgentSession(
  options: BackgroundAgentSessionStartOptions,
): BackgroundAgentSessionHandle {
  const message = options.message.trim();
  if (!message) throw new Error("Background agent session message is required");

  const operationId = requiredId(options.operationId, "background-operation");
  const threadId = requiredId(options.threadId, "background-thread");
  const turnId = turnIdForReceipt(threadId, operationId);
  const actionScope =
    options.actionScope === undefined
      ? undefined
      : normalizeAgentActionScope(options.actionScope);
  let routeAccepted = false;
  let routeError: Error | undefined;
  let resolveCompletion!: () => void;
  let rejectCompletion!: (error: unknown) => void;
  const completion = new Promise<void>((resolve, reject) => {
    resolveCompletion = resolve;
    rejectCompletion = reject;
  });

  const accepted = fetch(agentNativePath("/_agent-native/agent-chat"), {
    method: "POST",
    credentials: "same-origin",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      message: appendAgentChatContextToMessage(
        message,
        options.instructions ?? "",
      ),
      displayMessage: message,
      queuedMessageId: operationId,
      threadId,
      turnId,
      history: [],
      structuredHistory: [],
      ...(options.scope !== undefined ? { scope: options.scope } : {}),
      ...(actionScope ? { actionScope } : {}),
      ...(options.mode ? { mode: options.mode } : {}),
      ...(options.model?.trim() ? { model: options.model.trim() } : {}),
      ...(options.engine?.trim() ? { engine: options.engine.trim() } : {}),
      ...(options.effort ? { effort: options.effort } : {}),
      ...(options.attachments?.length
        ? { attachments: options.attachments }
        : {}),
      ...(options.usageLabel?.trim()
        ? { usageLabel: options.usageLabel.trim() }
        : {}),
    }),
  })
    .then(async (response) => {
      if (!response.ok) throw await responseError(response);
      routeAccepted = true;
      void drainResponse(response).then(resolveCompletion, rejectCompletion);
      return { operationId, threadId, turnId };
    })
    .catch((error) => {
      routeError = error instanceof Error ? error : new Error(String(error));
      rejectCompletion(routeError);
      throw routeError;
    });
  void accepted.catch(() => {});
  void completion.catch(() => {});

  return {
    operationId,
    threadId,
    turnId,
    accepted,
    completion,
    status: () =>
      routeAccepted
        ? getBackgroundAgentSessionStatus({ operationId, threadId, turnId })
        : Promise.resolve(
            routeError
              ? {
                  operationId,
                  threadId,
                  turnId,
                  status: "errored" as const,
                  terminalReason: routeError.message,
                }
              : { operationId, threadId, turnId, status: "queued" as const },
          ),
    cancel: async (reason) => {
      await accepted;
      await cancelBackgroundAgentSession({ threadId, turnId, reason });
    },
    open: (openOptions) =>
      requestAgentChatThreadOpen({
        threadId,
        ...(openOptions?.prefill ? { prefill: openOptions.prefill } : {}),
      }),
  };
}

export async function getBackgroundAgentSessionStatus(
  receipt: BackgroundAgentSessionReceipt,
): Promise<BackgroundAgentSessionSnapshot> {
  const params = new URLSearchParams({
    threadId: receipt.threadId,
    turnId: receipt.turnId,
  });
  const response = await fetch(
    `${agentNativePath("/_agent-native/agent-chat/runs/latest")}?${params}`,
    { credentials: "same-origin", cache: "no-store" },
  );
  if (response.status === 404) {
    return { ...receipt, status: "unavailable" };
  }
  if (!response.ok) throw await responseError(response);
  const body = (await response.json()) as {
    status?: unknown;
    runId?: unknown;
    terminalReason?: unknown;
  };
  const rawStatus = typeof body.status === "string" ? body.status : "queued";
  const status: BackgroundAgentSessionStatus = [
    "queued",
    "running",
    "completed",
    "truncated",
    "errored",
    "aborted",
  ].includes(rawStatus)
    ? (rawStatus as BackgroundAgentSessionStatus)
    : "errored";
  return {
    ...receipt,
    status,
    ...(typeof body.runId === "string" ? { runId: body.runId } : {}),
    ...(body.terminalReason === null || typeof body.terminalReason === "string"
      ? { terminalReason: body.terminalReason }
      : {}),
  };
}

export async function cancelBackgroundAgentSession(options: {
  threadId: string;
  turnId: string;
  reason?: string;
}): Promise<void> {
  const reason = options.reason?.trim() || "user";
  const turnResponse = await fetch(
    agentNativePath(
      `/_agent-native/agent-chat/runs/turn/${encodeURIComponent(options.turnId)}/abort`,
    ),
    {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ threadId: options.threadId, reason }),
    },
  );
  if (!turnResponse.ok) {
    throw await responseError(turnResponse);
  }
}
