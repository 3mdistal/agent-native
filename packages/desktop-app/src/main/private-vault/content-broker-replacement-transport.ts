import {
  endpointRequestProofSchema,
  type EndpointRequestProof,
} from "@agent-native/core/e2ee";

import type { PrivateVaultContentSession } from "./content-genesis-transport.js";

const MEDIA_TYPE =
  "application/vnd.agent-native.private-vault-broker-replacement+cbor";
const STATUS_MAX_BYTES = 1024 * 1024;
const OFFER_MAX_BYTES = 64 * 1024;
const CHALLENGE_MAX_BYTES = 64 * 1024;
const SAS_MAX_BYTES = 2 * 1024;
const APPROVAL_MAX_BYTES = 1024;
const DRAIN_ATTESTATION_MAX_BYTES = 1024;
const ROTATION_APPEND_MAX_BYTES = 512 * 1024;
const HEX_ID = /^[0-9a-f]{32}$/;
const HEX_HASH = /^[0-9a-f]{64}$/;
const ISO_TIME = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;

const phases = [
  "offer",
  "challenge",
  "candidate_confirmed",
  "authorized",
  "draining",
  "drained",
  "rotation_committed",
  "activated",
  "rejected",
  "expired",
  "aborted",
] as const;

export type PrivateVaultBrokerReplacementPhase = (typeof phases)[number];

export interface PrivateVaultBrokerReplacementTransportStatus {
  readonly transcriptId: string;
  readonly phase: PrivateVaultBrokerReplacementPhase;
  readonly oldBrokerEndpointId: string;
  readonly newBrokerEndpointId: string;
  readonly authorizerEndpointId: string;
  readonly offer: Uint8Array;
  readonly challenge: Uint8Array | null;
  readonly sasDecision: Uint8Array | null;
  readonly replacementApproval: Uint8Array | null;
  readonly drainId: string | null;
  readonly drainGeneration: string | null;
  readonly drain: Readonly<{
    totalCount: number | null;
    completedCount: number | null;
    failedCount: number | null;
    cancelledCount: number | null;
    digest: string | null;
    signedAttestation: Uint8Array | null;
  }>;
  readonly rotation: Readonly<{
    controlEntryId: string | null;
    controlEntryHash: string | null;
    controlSequence: number | null;
    receipt: Uint8Array | null;
  }>;
  readonly expiresAt: string;
}

export class PrivateVaultBrokerReplacementTransportError extends Error {
  constructor() {
    super("Private Vault broker replacement transport unavailable");
    this.name = "PrivateVaultBrokerReplacementTransportError";
  }
}

function exactOrigin(value: string) {
  try {
    const parsed = new URL(value);
    if (
      parsed.protocol !== "https:" ||
      parsed.username ||
      parsed.password ||
      parsed.pathname !== "/" ||
      parsed.search ||
      parsed.hash
    )
      throw new Error();
    return parsed.origin;
  } catch {
    throw new PrivateVaultBrokerReplacementTransportError();
  }
}

function exactKeys(value: Record<string, unknown>, expected: string[]) {
  const keys = Object.keys(value).sort();
  const wanted = [...expected].sort();
  return (
    keys.length === wanted.length &&
    keys.every((key, index) => key === wanted[index])
  );
}

function bounded(value: Uint8Array, maximum: number) {
  if (
    !(value instanceof Uint8Array) ||
    value.byteLength < 1 ||
    value.byteLength > maximum
  )
    throw new PrivateVaultBrokerReplacementTransportError();
  return value.slice();
}

function decodeBytes(value: unknown, maximum: number): Uint8Array | null {
  if (value === null) return null;
  if (
    typeof value !== "string" ||
    value.length < 1 ||
    value.length > Math.ceil((maximum * 4) / 3) ||
    !/^[A-Za-z0-9_-]+$/.test(value)
  )
    throw new PrivateVaultBrokerReplacementTransportError();
  const bytes = Uint8Array.from(Buffer.from(value, "base64url"));
  if (
    bytes.byteLength < 1 ||
    bytes.byteLength > maximum ||
    Buffer.from(bytes).toString("base64url") !== value
  )
    throw new PrivateVaultBrokerReplacementTransportError();
  return bytes;
}

function nullableCount(value: unknown) {
  if (value === null) return null;
  if (!Number.isSafeInteger(value) || (value as number) < 0)
    throw new PrivateVaultBrokerReplacementTransportError();
  return value as number;
}

function nullable(value: unknown, pattern: RegExp) {
  if (value === null) return null;
  if (typeof value !== "string" || !pattern.test(value))
    throw new PrivateVaultBrokerReplacementTransportError();
  return value;
}

const STATUS_KEYS = [
  "version",
  "suite",
  "transcriptId",
  "phase",
  "oldBrokerEndpointId",
  "newBrokerEndpointId",
  "authorizerEndpointId",
  "offer",
  "challenge",
  "sasDecision",
  "replacementApproval",
  "drainId",
  "drainGeneration",
  "drain",
  "rotation",
  "expiresAt",
];

function parseStatus(
  value: unknown,
): PrivateVaultBrokerReplacementTransportStatus {
  if (!value || typeof value !== "object" || Array.isArray(value))
    throw new PrivateVaultBrokerReplacementTransportError();
  const input = value as Record<string, unknown>;
  if (
    !exactKeys(input, STATUS_KEYS) ||
    input.version !== 1 ||
    input.suite !== "anc/v1" ||
    typeof input.transcriptId !== "string" ||
    !HEX_HASH.test(input.transcriptId) ||
    !phases.includes(input.phase as PrivateVaultBrokerReplacementPhase) ||
    typeof input.oldBrokerEndpointId !== "string" ||
    !HEX_ID.test(input.oldBrokerEndpointId) ||
    typeof input.newBrokerEndpointId !== "string" ||
    !HEX_ID.test(input.newBrokerEndpointId) ||
    typeof input.authorizerEndpointId !== "string" ||
    !HEX_ID.test(input.authorizerEndpointId) ||
    new Set([
      input.oldBrokerEndpointId,
      input.newBrokerEndpointId,
      input.authorizerEndpointId,
    ]).size !== 3 ||
    typeof input.expiresAt !== "string" ||
    !ISO_TIME.test(input.expiresAt) ||
    !input.drain ||
    typeof input.drain !== "object" ||
    Array.isArray(input.drain) ||
    !input.rotation ||
    typeof input.rotation !== "object" ||
    Array.isArray(input.rotation)
  )
    throw new PrivateVaultBrokerReplacementTransportError();

  const drainInput = input.drain as Record<string, unknown>;
  const rotationInput = input.rotation as Record<string, unknown>;
  if (
    !exactKeys(drainInput, [
      "totalCount",
      "completedCount",
      "failedCount",
      "cancelledCount",
      "digest",
      "signedAttestation",
    ]) ||
    !exactKeys(rotationInput, [
      "controlEntryId",
      "controlEntryHash",
      "controlSequence",
      "receipt",
    ])
  )
    throw new PrivateVaultBrokerReplacementTransportError();

  const offer = decodeBytes(input.offer, OFFER_MAX_BYTES);
  const challenge = decodeBytes(input.challenge, CHALLENGE_MAX_BYTES);
  const sasDecision = decodeBytes(input.sasDecision, SAS_MAX_BYTES);
  const replacementApproval = decodeBytes(
    input.replacementApproval,
    APPROVAL_MAX_BYTES,
  );
  const signedAttestation = decodeBytes(
    drainInput.signedAttestation,
    DRAIN_ATTESTATION_MAX_BYTES,
  );
  const receipt = decodeBytes(rotationInput.receipt, 16 * 1024);
  if (!offer) throw new PrivateVaultBrokerReplacementTransportError();
  const drainId = nullable(input.drainId, HEX_ID);
  const drainGeneration = nullable(input.drainGeneration, /^[0-9]{8}$/);
  const drain = Object.freeze({
    totalCount: nullableCount(drainInput.totalCount),
    completedCount: nullableCount(drainInput.completedCount),
    failedCount: nullableCount(drainInput.failedCount),
    cancelledCount: nullableCount(drainInput.cancelledCount),
    digest: nullable(drainInput.digest, HEX_HASH),
    signedAttestation,
  });
  const rotation = Object.freeze({
    controlEntryId: nullable(rotationInput.controlEntryId, HEX_ID),
    controlEntryHash: nullable(rotationInput.controlEntryHash, HEX_HASH),
    controlSequence: nullableCount(rotationInput.controlSequence),
    receipt,
  });
  const drainValues = [
    drain.totalCount,
    drain.completedCount,
    drain.failedCount,
    drain.cancelledCount,
    drain.digest,
    drain.signedAttestation,
  ];
  const rotationValues = [
    rotation.controlEntryId,
    rotation.controlEntryHash,
    rotation.controlSequence,
    rotation.receipt,
  ];
  if (
    (challenge === null &&
      (sasDecision !== null || replacementApproval !== null)) ||
    (sasDecision === null && replacementApproval !== null) ||
    (drainId === null) !== (drainGeneration === null) ||
    (drainId === null && drainValues.some((item) => item !== null)) ||
    (replacementApproval === null && drainId !== null) ||
    (signedAttestation === null &&
      rotationValues.some((item) => item !== null)) ||
    (rotationValues.some((item) => item === null) &&
      rotationValues.some((item) => item !== null)) ||
    (rotation.controlSequence !== null && rotation.controlSequence < 1) ||
    (signedAttestation !== null &&
      drainValues.slice(0, 5).some((item) => item === null))
  )
    throw new PrivateVaultBrokerReplacementTransportError();

  const phase = input.phase as PrivateVaultBrokerReplacementPhase;
  const exactPhase =
    (phase === "offer" && challenge === null) ||
    (phase === "challenge" && challenge !== null && sasDecision === null) ||
    (phase === "candidate_confirmed" &&
      sasDecision !== null &&
      replacementApproval === null) ||
    (phase === "authorized" &&
      replacementApproval !== null &&
      drainId === null) ||
    (phase === "draining" && drainId !== null && signedAttestation === null) ||
    (phase === "drained" &&
      signedAttestation !== null &&
      rotation.receipt === null) ||
    ((phase === "rotation_committed" || phase === "activated") &&
      rotation.receipt !== null) ||
    phase === "rejected" ||
    phase === "expired" ||
    phase === "aborted";
  if (!exactPhase) throw new PrivateVaultBrokerReplacementTransportError();

  return Object.freeze({
    transcriptId: input.transcriptId,
    phase,
    oldBrokerEndpointId: input.oldBrokerEndpointId,
    newBrokerEndpointId: input.newBrokerEndpointId,
    authorizerEndpointId: input.authorizerEndpointId,
    offer,
    challenge,
    sasDecision,
    replacementApproval,
    drainId,
    drainGeneration,
    drain,
    rotation,
    expiresAt: input.expiresAt,
  });
}

function validateWitnessProgress(
  value: unknown,
  status: PrivateVaultBrokerReplacementTransportStatus,
) {
  if (value === null) {
    if (status.drainId !== null)
      throw new PrivateVaultBrokerReplacementTransportError();
    return;
  }
  if (!value || typeof value !== "object" || Array.isArray(value))
    throw new PrivateVaultBrokerReplacementTransportError();
  const input = value as Record<string, unknown>;
  nullable(input.deadlineDecisionId, HEX_HASH);
  nullable(input.terminalJobsDigest, HEX_HASH);
  nullable(input.completionId, HEX_ID);
  if (
    !exactKeys(input, [
      "drainId",
      "vaultId",
      "oldBrokerEndpointId",
      "replacementBrokerEndpointId",
      "authorizerEndpointId",
      "authorizerApprovalId",
      "authorizerApprovalHash",
      "drainGeneration",
      "phase",
      "deadlineAt",
      "frozenAt",
      "deadlineDecisionId",
      "deadlineDecision",
      "deadlineDecidedAt",
      "witnessGeneration",
      "totalJobCount",
      "completedJobCount",
      "failedJobCount",
      "cancelledJobCount",
      "terminalJobsDigest",
      "witnessedAt",
      "completionId",
      "completedAt",
    ]) ||
    input.drainId !== status.drainId ||
    input.oldBrokerEndpointId !== status.oldBrokerEndpointId ||
    input.replacementBrokerEndpointId !== status.newBrokerEndpointId ||
    input.authorizerEndpointId !== status.authorizerEndpointId ||
    input.authorizerApprovalId !== status.drainId ||
    typeof input.vaultId !== "string" ||
    !HEX_ID.test(input.vaultId) ||
    typeof input.authorizerApprovalHash !== "string" ||
    !HEX_HASH.test(input.authorizerApprovalHash) ||
    input.drainGeneration !== status.drainGeneration ||
    !["draining", "witnessed", "committed", "aborted"].includes(
      input.phase as string,
    ) ||
    typeof input.deadlineAt !== "string" ||
    !ISO_TIME.test(input.deadlineAt) ||
    typeof input.frozenAt !== "string" ||
    !ISO_TIME.test(input.frozenAt) ||
    ![null, "abort", "cancel_nonterminal", "expire_nonterminal"].includes(
      input.deadlineDecision as never,
    ) ||
    (input.deadlineDecidedAt !== null &&
      (typeof input.deadlineDecidedAt !== "string" ||
        !ISO_TIME.test(input.deadlineDecidedAt))) ||
    (input.witnessedAt !== null &&
      (typeof input.witnessedAt !== "string" ||
        !ISO_TIME.test(input.witnessedAt))) ||
    (input.completedAt !== null &&
      (typeof input.completedAt !== "string" ||
        !ISO_TIME.test(input.completedAt)))
  )
    throw new PrivateVaultBrokerReplacementTransportError();
  for (const key of [
    "witnessGeneration",
    "totalJobCount",
    "completedJobCount",
    "failedJobCount",
    "cancelledJobCount",
  ])
    nullableCount(input[key]);
}

export class PrivateVaultContentBrokerReplacementTransport {
  readonly #origin: string;
  readonly #session: PrivateVaultContentSession;

  constructor(input: {
    readonly origin: string;
    readonly session: PrivateVaultContentSession;
  }) {
    this.#origin = exactOrigin(input.origin);
    this.#session = input.session;
  }

  publishOffer(offer: Uint8Array) {
    return this.#request(
      "/api/private-vault/broker-replacement/offer",
      "POST",
      bounded(offer, OFFER_MAX_BYTES),
    );
  }

  publishChallenge(transcriptId: string, challenge: Uint8Array) {
    return this.#postArtifact(
      transcriptId,
      "challenge",
      challenge,
      CHALLENGE_MAX_BYTES,
    );
  }

  publishSasDecision(transcriptId: string, decision: Uint8Array) {
    return this.#postArtifact(
      transcriptId,
      "sas-decision",
      decision,
      SAS_MAX_BYTES,
    );
  }

  publishApproval(transcriptId: string, approval: Uint8Array) {
    return this.#postArtifact(
      transcriptId,
      "approval",
      approval,
      APPROVAL_MAX_BYTES,
    );
  }

  async witness(transcriptId: string) {
    const status = await this.#request(
      this.#path(transcriptId, "witness"),
      "POST",
      new TextEncoder().encode("witness"),
      undefined,
      false,
    );
    if (status !== null)
      throw new PrivateVaultBrokerReplacementTransportError();
    return this.readStatus(transcriptId);
  }

  publishDrainAttestation(transcriptId: string, attestation: Uint8Array) {
    return this.#postArtifact(
      transcriptId,
      "drain-attestation",
      attestation,
      DRAIN_ATTESTATION_MAX_BYTES,
    );
  }

  commitRotation(input: {
    readonly transcriptId: string;
    readonly body: Uint8Array;
    readonly proof: EndpointRequestProof;
  }) {
    let proofHeader: string;
    try {
      const proof = endpointRequestProofSchema.parse(input.proof);
      const expectedPath = this.#path(input.transcriptId, "commit");
      if (proof.method !== "POST" || proof.path !== expectedPath)
        throw new Error();
      proofHeader = Buffer.from(JSON.stringify(proof)).toString("base64url");
      if (proofHeader.length > 8_192) throw new Error();
    } catch {
      throw new PrivateVaultBrokerReplacementTransportError();
    }
    return this.#request(
      this.#path(input.transcriptId, "commit"),
      "POST",
      bounded(input.body, ROTATION_APPEND_MAX_BYTES),
      proofHeader,
    );
  }

  resolveDeadline(
    transcriptId: string,
    decision: "abort" | "cancel_nonterminal" | "expire_nonterminal",
  ) {
    return this.#postArtifact(
      transcriptId,
      "deadline",
      new TextEncoder().encode(decision),
      32,
    );
  }

  readStatus(transcriptId: string) {
    return this.#request(this.#path(transcriptId, "status"), "GET");
  }

  #postArtifact(
    transcriptId: string,
    operation: string,
    value: Uint8Array,
    maximum: number,
  ) {
    return this.#request(
      this.#path(transcriptId, operation),
      "POST",
      bounded(value, maximum),
    );
  }

  #path(transcriptId: string, operation: string) {
    if (!HEX_HASH.test(transcriptId))
      throw new PrivateVaultBrokerReplacementTransportError();
    return `/api/private-vault/broker-replacement/${transcriptId}/${operation}`;
  }

  async #request(
    path: string,
    method: "GET" | "POST",
    body?: Uint8Array,
    proofHeader?: string,
    parseResponse = true,
  ): Promise<PrivateVaultBrokerReplacementTransportStatus | null> {
    const requestBody = body ? Buffer.from(body) : null;
    try {
      const url = `${this.#origin}${path}`;
      const response = await this.#session.fetch(url, {
        method,
        redirect: "error",
        credentials: "include",
        cache: "no-store",
        headers: {
          Accept: "application/json",
          "Cache-Control": "no-store",
          Origin: this.#origin,
          ...(body
            ? {
                "Content-Type": MEDIA_TYPE,
                "Content-Length": String(body.byteLength),
                "X-Agent-Native-CSRF": "1",
              }
            : {}),
          ...(proofHeader
            ? { "X-Anc-Endpoint-Request-Proof": proofHeader }
            : {}),
        },
        ...(requestBody ? { body: requestBody } : {}),
      });
      if (
        response.status !== 200 ||
        response.url !== url ||
        response.redirected ||
        response.headers.get("content-type")?.split(";", 1)[0]?.trim() !==
          "application/json"
      )
        throw new Error();
      const bytes = new Uint8Array(await response.arrayBuffer());
      if (bytes.byteLength < 1 || bytes.byteLength > STATUS_MAX_BYTES)
        throw new Error();
      const value = JSON.parse(
        new TextDecoder("utf-8", { fatal: true }).decode(bytes),
      );
      if (!parseResponse) {
        if (
          !value ||
          typeof value !== "object" ||
          Array.isArray(value) ||
          !exactKeys(value as Record<string, unknown>, [
            "version",
            "suite",
            "witness",
          ]) ||
          (value as Record<string, unknown>).version !== 1 ||
          (value as Record<string, unknown>).suite !== "anc/v1" ||
          !(value as Record<string, unknown>).witness ||
          typeof (value as Record<string, unknown>).witness !== "object"
        )
          throw new Error();
        return null;
      }
      let statusValue = value;
      let witnessedProgress: unknown = undefined;
      if (path.endsWith("/status")) {
        if (
          !value ||
          typeof value !== "object" ||
          Array.isArray(value) ||
          !exactKeys(value as Record<string, unknown>, [
            ...STATUS_KEYS,
            "witnessedProgress",
          ])
        )
          throw new Error();
        const { witnessedProgress: progress, ...withoutProgress } =
          value as Record<string, unknown>;
        witnessedProgress = progress;
        statusValue = withoutProgress;
      }
      const status = parseStatus(statusValue);
      if (witnessedProgress !== undefined)
        validateWitnessProgress(witnessedProgress, status);
      const expectedTranscript = path.match(
        /broker-replacement\/([0-9a-f]{64})\//,
      )?.[1];
      if (expectedTranscript && status.transcriptId !== expectedTranscript)
        throw new Error();
      return status;
    } catch {
      throw new PrivateVaultBrokerReplacementTransportError();
    } finally {
      requestBody?.fill(0);
      body?.fill(0);
    }
  }
}
