import { describe, expect, it, vi } from "vitest";

import {
  PrivateVaultBrokerReplacementTransportError,
  PrivateVaultContentBrokerReplacementTransport,
} from "./content-broker-replacement-transport.js";
import type { PrivateVaultContentSession } from "./content-genesis-transport.js";

const transcriptId = "11".repeat(32);
const oldBrokerEndpointId = "22".repeat(16);
const newBrokerEndpointId = "33".repeat(16);
const authorizerEndpointId = "44".repeat(16);
const offer = Uint8Array.of(1, 2, 3);
const challenge = Uint8Array.of(4, 5, 6);
const sas = Uint8Array.of(7, 8, 9);
const approval = Uint8Array.of(10, 11, 12);
const attestation = Uint8Array.of(13, 14, 15);
const receipt = Uint8Array.of(16, 17, 18);

function encoded(value: Uint8Array) {
  return Buffer.from(value).toString("base64url");
}

function statusBody(
  phase:
    | "offer"
    | "challenge"
    | "candidate_confirmed"
    | "draining"
    | "drained"
    | "rotation_committed",
) {
  const challenged = phase !== "offer";
  const confirmed = !["offer", "challenge"].includes(phase);
  const draining = ["draining", "drained", "rotation_committed"].includes(
    phase,
  );
  const drained = ["drained", "rotation_committed"].includes(phase);
  const committed = phase === "rotation_committed";
  return {
    version: 1,
    suite: "anc/v1",
    transcriptId,
    phase,
    oldBrokerEndpointId,
    newBrokerEndpointId,
    authorizerEndpointId,
    offer: encoded(offer),
    challenge: challenged ? encoded(challenge) : null,
    sasDecision: confirmed ? encoded(sas) : null,
    replacementApproval: draining ? encoded(approval) : null,
    drainId: draining ? "55".repeat(16) : null,
    drainGeneration: draining ? "00000001" : null,
    drain: {
      totalCount: drained ? 2 : null,
      completedCount: drained ? 2 : null,
      failedCount: drained ? 0 : null,
      cancelledCount: drained ? 0 : null,
      digest: drained ? "66".repeat(32) : null,
      signedAttestation: drained ? encoded(attestation) : null,
    },
    rotation: {
      controlEntryId: committed ? "77".repeat(16) : null,
      controlEntryHash: committed ? "88".repeat(32) : null,
      controlSequence: committed ? 2 : null,
      receipt: committed ? encoded(receipt) : null,
    },
    expiresAt: "2026-07-19T13:00:00.000Z",
  };
}

function response(path: string, body: unknown): Response {
  const bytes = Buffer.from(JSON.stringify(body));
  return {
    status: 200,
    url: `https://content-fork.example${path}`,
    redirected: false,
    headers: new Headers({ "content-type": "application/json" }),
    arrayBuffer: async () => bytes,
  } as unknown as Response;
}

function transport(fetch: PrivateVaultContentSession["fetch"]) {
  return new PrivateVaultContentBrokerReplacementTransport({
    origin: "https://content-fork.example",
    session: { fetch },
  });
}

describe("PrivateVaultContentBrokerReplacementTransport", () => {
  it("carries exact public ceremony bytes through the pre-drain state machine", async () => {
    const paths = [
      "/api/private-vault/broker-replacement/offer",
      `/api/private-vault/broker-replacement/${transcriptId}/challenge`,
      `/api/private-vault/broker-replacement/${transcriptId}/sas-decision`,
      `/api/private-vault/broker-replacement/${transcriptId}/approval`,
      `/api/private-vault/broker-replacement/${transcriptId}/drain-attestation`,
    ];
    const fetch = vi
      .fn<PrivateVaultContentSession["fetch"]>()
      .mockResolvedValueOnce(response(paths[0]!, statusBody("offer")))
      .mockResolvedValueOnce(response(paths[1]!, statusBody("challenge")))
      .mockResolvedValueOnce(
        response(paths[2]!, statusBody("candidate_confirmed")),
      )
      .mockResolvedValueOnce(response(paths[3]!, statusBody("draining")))
      .mockResolvedValueOnce(response(paths[4]!, statusBody("drained")));
    const hosted = transport(fetch);

    await expect(hosted.publishOffer(offer)).resolves.toMatchObject({
      phase: "offer",
      transcriptId,
    });
    await expect(
      hosted.publishChallenge(transcriptId, challenge),
    ).resolves.toMatchObject({ phase: "challenge", challenge });
    await expect(
      hosted.publishSasDecision(transcriptId, sas),
    ).resolves.toMatchObject({
      phase: "candidate_confirmed",
      sasDecision: sas,
    });
    await expect(
      hosted.publishApproval(transcriptId, approval),
    ).resolves.toMatchObject({
      phase: "draining",
      replacementApproval: approval,
    });
    await expect(
      hosted.publishDrainAttestation(transcriptId, attestation),
    ).resolves.toMatchObject({
      phase: "drained",
      drain: { signedAttestation: attestation },
    });
    expect(fetch.mock.calls.map(([url]) => url)).toEqual(
      paths.map((path) => `https://content-fork.example${path}`),
    );
    expect(fetch.mock.calls[0]![1]).toMatchObject({
      method: "POST" as const,
      credentials: "include",
      redirect: "error",
      headers: expect.objectContaining({
        "Content-Type":
          "application/vnd.agent-native.private-vault-broker-replacement+cbor",
        "X-Agent-Native-CSRF": "1",
      }),
    });
  });

  it("binds the signed endpoint proof to the exact transcript commit request", async () => {
    const path = `/api/private-vault/broker-replacement/${transcriptId}/commit`;
    const fetch = vi
      .fn<PrivateVaultContentSession["fetch"]>()
      .mockResolvedValue(response(path, statusBody("rotation_committed")));
    const body = Uint8Array.of(21, 22, 23);
    const proof = {
      version: 1 as const,
      suite: "anc/v1" as const,
      type: "endpoint_request" as const,
      vaultId: "99".repeat(16),
      endpointId: authorizerEndpointId,
      method: "POST" as const,
      path,
      bodyHash: "aa".repeat(32),
      issuedAt: "2026-07-19T12:00:00.000Z",
      nonce: "bb".repeat(32),
      signature: "cc".repeat(64),
    };
    await expect(
      transport(fetch).commitRotation({ transcriptId, body, proof }),
    ).resolves.toMatchObject({
      phase: "rotation_committed",
      rotation: { receipt },
    });
    expect(body).toEqual(Uint8Array.of(21, 22, 23));
    const headers = fetch.mock.calls[0]![1]!.headers as Record<string, string>;
    expect(
      JSON.parse(
        Buffer.from(
          headers["X-Anc-Endpoint-Request-Proof"]!,
          "base64url",
        ).toString("utf8"),
      ),
    ).toEqual(proof);
    expect(() =>
      transport(fetch).commitRotation({
        transcriptId,
        body,
        proof: { ...proof, path: "/api/private-vault/control-log/append" },
      }),
    ).toThrow(PrivateVaultBrokerReplacementTransportError);
    expect(fetch).toHaveBeenCalledTimes(1);
  });

  it("rejects transcript substitution, extra status fields, and partial receipts", async () => {
    const path = `/api/private-vault/broker-replacement/${transcriptId}/status`;
    const substituted = {
      ...statusBody("challenge"),
      transcriptId: "dd".repeat(32),
    };
    const extra = { ...statusBody("challenge"), plaintext: "nope" };
    const partial = statusBody("rotation_committed");
    partial.rotation.receipt = null;
    for (const value of [substituted, extra, partial]) {
      const fetch = vi
        .fn<PrivateVaultContentSession["fetch"]>()
        .mockResolvedValue(response(path, value));
      await expect(
        transport(fetch).readStatus(transcriptId),
      ).rejects.toBeInstanceOf(PrivateVaultBrokerReplacementTransportError);
    }
  });

  it("rejects non-HTTPS origins and malformed coordinates before transport", async () => {
    expect(
      () =>
        new PrivateVaultContentBrokerReplacementTransport({
          origin: "http://content-fork.example",
          session: { fetch: vi.fn() },
        }),
    ).toThrow(PrivateVaultBrokerReplacementTransportError);
    const fetch = vi.fn<PrivateVaultContentSession["fetch"]>();
    expect(() => transport(fetch).readStatus("NOT-A-TRANSCRIPT")).toThrow(
      PrivateVaultBrokerReplacementTransportError,
    );
    expect(fetch).not.toHaveBeenCalled();
  });
});
