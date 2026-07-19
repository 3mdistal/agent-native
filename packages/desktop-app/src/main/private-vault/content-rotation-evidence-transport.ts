import { randomBytes } from "node:crypto";

import {
  ANC_ROTATION_EVIDENCE_SIZE_LIMITS,
  ancV1BytesToHex,
  ancV1Hash,
  encodeEndpointRequestUnsignedProof,
  endpointRequestProofSchema,
  endpointRequestUnsignedProofSchema,
} from "@agent-native/core/e2ee";

import type { PrivateVaultContentSession } from "./content-genesis-transport.js";
import type { PrivateVaultNativeServiceClient } from "./native-service-client.js";

const MAX_RESPONSE_BYTES = 1024 * 1024;
const MAX_EEK_WRAP_BYTES = 2_048;
const IDENTIFIER = /^[0-9a-f]{32}$/;
const PHASES = [
  "collecting_offers",
  "awaiting_acknowledgements",
  "awaiting_destructions",
  "awaiting_hosted_receipt",
  "awaiting_completion",
  "completed",
] as const;

type RotationEvidencePhase = (typeof PHASES)[number];

export interface PrivateVaultRotationEvidenceWriteStatus {
  readonly state: "stored";
  readonly ceremonyId: string;
  readonly phase: RotationEvidencePhase;
  readonly expectedRecipientCount: number;
}

export interface PrivateVaultRotationRecipientArtifact {
  readonly ceremonyId: string;
  readonly recipientEndpointId: string;
  readonly offer: Uint8Array;
  readonly eekWrap: Uint8Array;
}

export interface PrivateVaultRotationEvidenceCollection {
  readonly ceremonyId: string;
  readonly phase: RotationEvidencePhase;
  readonly expectedRecipientCount: number;
  readonly recipients: readonly Readonly<{
    recipientEndpointId: string;
    acknowledgement: Uint8Array | null;
    destructionAttestation: Uint8Array | null;
  }>[];
}

export class PrivateVaultRotationEvidenceTransportError extends Error {
  constructor() {
    super("Private Vault rotation evidence transport unavailable");
    this.name = "PrivateVaultRotationEvidenceTransportError";
  }
}

function origin(value: string) {
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
    throw new PrivateVaultRotationEvidenceTransportError();
  }
}

function exactKeys(value: Record<string, unknown>, keys: readonly string[]) {
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  return (
    actual.length === expected.length &&
    actual.every((key, index) => key === expected[index])
  );
}

function phase(value: unknown): RotationEvidencePhase {
  if (!PHASES.includes(value as RotationEvidencePhase))
    throw new PrivateVaultRotationEvidenceTransportError();
  return value as RotationEvidencePhase;
}

function count(value: unknown) {
  if (
    !Number.isSafeInteger(value) ||
    (value as number) < 1 ||
    (value as number) > ANC_ROTATION_EVIDENCE_SIZE_LIMITS.acknowledgements
  )
    throw new PrivateVaultRotationEvidenceTransportError();
  return value as number;
}

function identifier(value: unknown) {
  if (typeof value !== "string" || !IDENTIFIER.test(value))
    throw new PrivateVaultRotationEvidenceTransportError();
  return value;
}

function bytes(value: Uint8Array, maximum: number) {
  if (
    !(value instanceof Uint8Array) ||
    value.byteLength < 1 ||
    value.byteLength > maximum
  )
    throw new PrivateVaultRotationEvidenceTransportError();
  return value.slice();
}

function decoded(value: unknown, maximum: number): Uint8Array | null {
  if (value === null) return null;
  if (
    typeof value !== "string" ||
    value.length < 1 ||
    value.length > Math.ceil((maximum * 4) / 3) ||
    !/^[A-Za-z0-9_-]+$/.test(value)
  )
    throw new PrivateVaultRotationEvidenceTransportError();
  const result = Uint8Array.from(Buffer.from(value, "base64url"));
  if (
    result.byteLength < 1 ||
    result.byteLength > maximum ||
    Buffer.from(result).toString("base64url") !== value
  )
    throw new PrivateVaultRotationEvidenceTransportError();
  return result;
}

function writeStatus(value: unknown): PrivateVaultRotationEvidenceWriteStatus {
  if (!value || typeof value !== "object" || Array.isArray(value))
    throw new PrivateVaultRotationEvidenceTransportError();
  const input = value as Record<string, unknown>;
  if (
    !exactKeys(input, [
      "state",
      "ceremonyId",
      "phase",
      "expectedRecipientCount",
    ]) ||
    input.state !== "stored"
  )
    throw new PrivateVaultRotationEvidenceTransportError();
  return Object.freeze({
    state: "stored" as const,
    ceremonyId: identifier(input.ceremonyId),
    phase: phase(input.phase),
    expectedRecipientCount: count(input.expectedRecipientCount),
  });
}

export class PrivateVaultContentRotationEvidenceTransport {
  readonly #origin: string;
  readonly #session: PrivateVaultContentSession;
  readonly #native: Pick<
    PrivateVaultNativeServiceClient,
    "listVaultMembers" | "signEndpointRequest"
  >;
  readonly #now: () => Date;
  readonly #nonce: () => string;

  constructor(input: {
    origin: string;
    session: PrivateVaultContentSession;
    native: Pick<
      PrivateVaultNativeServiceClient,
      "listVaultMembers" | "signEndpointRequest"
    >;
    now?: () => Date;
    nonce?: () => string;
  }) {
    this.#origin = origin(input.origin);
    this.#session = input.session;
    this.#native = input.native;
    this.#now = input.now ?? (() => new Date());
    this.#nonce = input.nonce ?? (() => randomBytes(32).toString("hex"));
  }

  appendCheckpoint(vaultId: string, checkpoint: Uint8Array) {
    return this.#write(
      vaultId,
      "/api/private-vault/rotation-evidence/checkpoint",
      bytes(checkpoint, ANC_ROTATION_EVIDENCE_SIZE_LIMITS.checkpointBytes),
      "endpoint",
    );
  }

  appendOffer(vaultId: string, offer: Uint8Array, eekWrap: Uint8Array) {
    const wrap = bytes(eekWrap, MAX_EEK_WRAP_BYTES);
    return this.#write(
      vaultId,
      "/api/private-vault/rotation-evidence/offer",
      bytes(offer, ANC_ROTATION_EVIDENCE_SIZE_LIMITS.offerBytes),
      "endpoint",
      wrap,
    ).finally(() => wrap.fill(0));
  }

  async fetchRecipient(
    vaultId: string,
    ceremonyId: string,
    recipientEndpointId: string,
  ): Promise<PrivateVaultRotationRecipientArtifact> {
    const path = this.#recipientPath(
      ceremonyId,
      recipientEndpointId,
      "recipient",
    );
    const value = await this.#request(
      vaultId,
      path,
      new Uint8Array(),
      "either",
    );
    if (
      !exactKeys(value, [
        "ceremonyId",
        "recipientEndpointId",
        "offer",
        "eekWrap",
      ]) ||
      value.ceremonyId !== ceremonyId ||
      value.recipientEndpointId !== recipientEndpointId
    )
      throw new PrivateVaultRotationEvidenceTransportError();
    const offer = decoded(
      value.offer,
      ANC_ROTATION_EVIDENCE_SIZE_LIMITS.offerBytes,
    );
    const eekWrap = decoded(value.eekWrap, MAX_EEK_WRAP_BYTES);
    if (!offer || !eekWrap)
      throw new PrivateVaultRotationEvidenceTransportError();
    return Object.freeze({ ceremonyId, recipientEndpointId, offer, eekWrap });
  }

  appendAcknowledgement(
    vaultId: string,
    ceremonyId: string,
    recipientEndpointId: string,
    acknowledgement: Uint8Array,
  ) {
    return this.#write(
      vaultId,
      this.#recipientPath(ceremonyId, recipientEndpointId, "acknowledgement"),
      bytes(
        acknowledgement,
        ANC_ROTATION_EVIDENCE_SIZE_LIMITS.acknowledgementBytes,
      ),
      "either",
    );
  }

  appendDestruction(
    vaultId: string,
    ceremonyId: string,
    recipientEndpointId: string,
    destruction: Uint8Array,
  ) {
    return this.#write(
      vaultId,
      this.#recipientPath(ceremonyId, recipientEndpointId, "destruction"),
      bytes(destruction, ANC_ROTATION_EVIDENCE_SIZE_LIMITS.destructionBytes),
      "either",
    );
  }

  async readStatus(
    vaultId: string,
    ceremonyId: string,
  ): Promise<PrivateVaultRotationEvidenceCollection> {
    identifier(ceremonyId);
    const value = await this.#request(
      vaultId,
      `/api/private-vault/rotation-evidence/${ceremonyId}/status`,
      new Uint8Array(),
      "endpoint",
    );
    if (
      !exactKeys(value, [
        "ceremonyId",
        "phase",
        "expectedRecipientCount",
        "recipients",
      ]) ||
      value.ceremonyId !== ceremonyId ||
      !Array.isArray(value.recipients)
    )
      throw new PrivateVaultRotationEvidenceTransportError();
    const expectedRecipientCount = count(value.expectedRecipientCount);
    const evidencePhase = phase(value.phase);
    if (value.recipients.length > expectedRecipientCount)
      throw new PrivateVaultRotationEvidenceTransportError();
    const seen = new Set<string>();
    const recipients = value.recipients.map((candidate) => {
      if (
        !candidate ||
        typeof candidate !== "object" ||
        Array.isArray(candidate) ||
        !exactKeys(candidate as Record<string, unknown>, [
          "recipientEndpointId",
          "acknowledgement",
          "destructionAttestation",
        ])
      )
        throw new PrivateVaultRotationEvidenceTransportError();
      const item = candidate as Record<string, unknown>;
      const recipientEndpointId = identifier(item.recipientEndpointId);
      if (seen.has(recipientEndpointId))
        throw new PrivateVaultRotationEvidenceTransportError();
      seen.add(recipientEndpointId);
      return Object.freeze({
        recipientEndpointId,
        acknowledgement: decoded(
          item.acknowledgement,
          ANC_ROTATION_EVIDENCE_SIZE_LIMITS.acknowledgementBytes,
        ),
        destructionAttestation: decoded(
          item.destructionAttestation,
          ANC_ROTATION_EVIDENCE_SIZE_LIMITS.destructionBytes,
        ),
      });
    });
    const completeOffers = recipients.length === expectedRecipientCount;
    const allAcknowledged =
      completeOffers &&
      recipients.every((recipient) => recipient.acknowledgement !== null);
    const allDestroyed =
      completeOffers &&
      recipients.every(
        (recipient) => recipient.destructionAttestation !== null,
      );
    if (
      recipients.some(
        (recipient) =>
          recipient.destructionAttestation !== null &&
          recipient.acknowledgement === null,
      ) ||
      (evidencePhase === "collecting_offers" &&
        recipients.some(
          (recipient) =>
            recipient.acknowledgement !== null ||
            recipient.destructionAttestation !== null,
        )) ||
      (evidencePhase !== "collecting_offers" && !completeOffers) ||
      (evidencePhase === "awaiting_acknowledgements" &&
        recipients.some(
          (recipient) => recipient.destructionAttestation !== null,
        )) ||
      (evidencePhase === "awaiting_destructions" && !allAcknowledged) ||
      ((evidencePhase === "awaiting_hosted_receipt" ||
        evidencePhase === "awaiting_completion" ||
        evidencePhase === "completed") &&
        (!allAcknowledged || !allDestroyed))
    )
      throw new PrivateVaultRotationEvidenceTransportError();
    return Object.freeze({
      ceremonyId,
      phase: evidencePhase,
      expectedRecipientCount,
      recipients: Object.freeze(recipients),
    });
  }

  #recipientPath(
    ceremonyId: string,
    recipientEndpointId: string,
    suffix: "recipient" | "acknowledgement" | "destruction",
  ) {
    identifier(ceremonyId);
    identifier(recipientEndpointId);
    return `/api/private-vault/rotation-evidence/${ceremonyId}/recipients/${recipientEndpointId}/${suffix}`;
  }

  async #write(
    vaultId: string,
    path: string,
    body: Uint8Array,
    role: "endpoint" | "either",
    eekWrap?: Uint8Array,
  ) {
    return writeStatus(await this.#request(vaultId, path, body, role, eekWrap));
  }

  async #request(
    vaultId: string,
    path: string,
    body: Uint8Array,
    role: "endpoint" | "either",
    eekWrap?: Uint8Array,
  ): Promise<Record<string, unknown>> {
    const requestBody = Buffer.from(body);
    try {
      if (!IDENTIFIER.test(vaultId)) throw new Error();
      const membership = await this.#native.listVaultMembers(vaultId);
      const current = membership.members.filter((member) => member.current);
      if (
        current.length !== 1 ||
        (current[0]!.role !== "endpoint" && current[0]!.role !== "broker") ||
        (role === "endpoint" &&
          (current[0]!.role !== "endpoint" || current[0]!.unattended)) ||
        (current[0]!.role === "broker" && !current[0]!.unattended)
      )
        throw new Error();
      const unsigned = endpointRequestUnsignedProofSchema.parse({
        version: 1,
        suite: "anc/v1",
        type: "endpoint_request",
        vaultId,
        endpointId: current[0]!.endpointId,
        method: "POST",
        path,
        bodyHash: ancV1BytesToHex(
          await ancV1Hash("endpoint-request-body", body),
        ),
        issuedAt: this.#now().toISOString(),
        nonce: this.#nonce(),
      });
      const signed = await this.#native.signEndpointRequest({
        version: 1,
        suite: "anc/v1",
        operation: "signEndpointRequest",
        unsignedProof: encodeEndpointRequestUnsignedProof(unsigned),
      });
      const proof = endpointRequestProofSchema.parse({
        ...unsigned,
        signature: ancV1BytesToHex(signed.signature),
      });
      const proofHeader = Buffer.from(JSON.stringify(proof)).toString(
        "base64url",
      );
      if (proofHeader.length > 16_384) throw new Error();
      const url = `${this.#origin}${path}`;
      const response = await this.#session.fetch(url, {
        method: "POST",
        redirect: "error",
        credentials: "include",
        cache: "no-store",
        headers: {
          Accept: "application/json",
          "Cache-Control": "no-store",
          "Content-Type": "application/octet-stream",
          "Content-Length": String(body.byteLength),
          "X-Agent-Native-CSRF": "1",
          "X-Anc-Endpoint-Proof": proofHeader,
          ...(eekWrap
            ? { "X-Anc-Eek-Wrap": Buffer.from(eekWrap).toString("base64url") }
            : {}),
        },
        body: requestBody,
      });
      if (
        response.status !== 200 ||
        response.url !== url ||
        response.redirected ||
        response.headers.get("content-type")?.split(";", 1)[0]?.trim() !==
          "application/json"
      )
        throw new Error();
      const encoded = new Uint8Array(await response.arrayBuffer());
      if (encoded.byteLength < 1 || encoded.byteLength > MAX_RESPONSE_BYTES)
        throw new Error();
      const value = JSON.parse(
        new TextDecoder("utf-8", { fatal: true }).decode(encoded),
      );
      if (!value || typeof value !== "object" || Array.isArray(value))
        throw new Error();
      return value as Record<string, unknown>;
    } catch {
      throw new PrivateVaultRotationEvidenceTransportError();
    } finally {
      requestBody.fill(0);
      body.fill(0);
    }
  }
}
