#include <cassert>

#include "addon.mm"

namespace {

xpc_object_t MakeReply(const char *oldBrokerEndpointID,
                       const char *candidateBrokerEndpointID) {
  uint8_t signedEntry[] = {0xa1, 0x01, 0x01};
  uint8_t recoveryWrap[] = {0xa1, 0x02, 0x02};
  uint8_t digest[32] = {0x31};
  uint8_t ceremonyID[16] = {0x41};
  xpc_object_t reply = xpc_dictionary_create(nullptr, nullptr, 0);
  xpc_dictionary_set_int64(reply, "version", PV_PROTOCOL_VERSION);
  xpc_dictionary_set_bool(reply, "ok", true);
  xpc_dictionary_set_string(reply, "requestId", "replacement-request");
  xpc_dictionary_set_string(reply, "state", "prepared");
  xpc_dictionary_set_string(reply, "vaultId",
                            "00112233445566778899aabbccddeeff");
  xpc_dictionary_set_string(reply, "oldBrokerEndpointId",
                            oldBrokerEndpointID);
  xpc_dictionary_set_string(reply, "candidateBrokerEndpointId",
                            candidateBrokerEndpointID);
  xpc_dictionary_set_data(reply, "signedEntry", signedEntry,
                          sizeof signedEntry);
  xpc_dictionary_set_data(reply, "recoveryWrap", recoveryWrap,
                          sizeof recoveryWrap);
  xpc_dictionary_set_data(reply, "transcriptDigest", digest, sizeof digest);
  xpc_dictionary_set_data(reply, "drainAttestationHash", digest,
                          sizeof digest);
  xpc_dictionary_set_uint64(reply, "preparationGeneration", 3);
  xpc_dictionary_set_uint64(reply, "fenceGeneration", 7);
  xpc_dictionary_set_data(reply, "checkpointDigest", digest, sizeof digest);
  xpc_dictionary_set_data(reply, "ceremonyId", ceremonyID,
                          sizeof ceremonyID);
  xpc_dictionary_set_uint64(reply, "baseSequence", 11);
  xpc_dictionary_set_data(reply, "baseHead", digest, sizeof digest);
  xpc_dictionary_set_data(reply, "baseMembership", digest, sizeof digest);
  xpc_dictionary_set_uint64(reply, "baseEpoch", 4);
  xpc_dictionary_set_uint64(reply, "baseRecoveryGeneration", 2);
  xpc_dictionary_set_uint64(reply, "pendingEpoch", 5);
  return reply;
}

xpc_object_t MakeCeremonyReply(PVOperation operation) {
  uint8_t body[] = {0xa1, 0x01, 0x01};
  uint8_t digest[32] = {0x31};
  uint8_t id[16] = {0x41};
  xpc_object_t reply = xpc_dictionary_create(nullptr, nullptr, 0);
  xpc_dictionary_set_int64(reply, "version", PV_PROTOCOL_VERSION);
  xpc_dictionary_set_bool(reply, "ok", true);
  xpc_dictionary_set_string(reply, "requestId", "ceremony-request");
  xpc_dictionary_set_string(reply, "vaultId",
                            "00112233445566778899aabbccddeeff");
  xpc_dictionary_set_string(reply, "oldBrokerEndpointId",
                            "11112222333344445555666677778888");
  xpc_dictionary_set_string(reply, "candidateBrokerEndpointId",
                            "9999aaaabbbbccccddddeeeeffff0000");
  if (operation == PVOperation::ChallengeBrokerReplacement) {
    xpc_dictionary_set_string(reply, "state", "challenged");
    xpc_dictionary_set_data(reply, "challenge", body, sizeof body);
    xpc_dictionary_set_string(reply, "sasCode", "056-775-976");
    xpc_dictionary_set_data(reply, "sasTranscriptHash", digest, sizeof digest);
  } else if (operation == PVOperation::ConfirmBrokerReplacement) {
    xpc_dictionary_set_string(reply, "state", "confirmed");
    xpc_dictionary_set_data(reply, "sasDecisionHash", digest, sizeof digest);
  } else {
    uint8_t drain[16] = {0x42};
    xpc_dictionary_set_string(reply, "state", "approved");
    xpc_dictionary_set_string(reply, "issuerEndpointId",
                              "22223333444455556666777788889999");
    xpc_dictionary_set_data(reply, "approval", body, sizeof body);
    xpc_dictionary_set_data(reply, "freezeId", id, sizeof id);
    xpc_dictionary_set_data(reply, "envelopeId", id, sizeof id);
    xpc_dictionary_set_data(reply, "drainId", drain, sizeof drain);
    xpc_dictionary_set_uint64(reply, "drainGeneration", 1);
    xpc_dictionary_set_uint64(reply, "createdAt", 1721111111);
    xpc_dictionary_set_uint64(reply, "deadlineAt", 1721114711);
  }
  return reply;
}

xpc_object_t MakeEndpointRemovalReply(void) {
  uint8_t body[] = {0xa1, 0x01, 0x01};
  uint8_t digest[32] = {0x31};
  uint8_t id[16] = {0x41};
  xpc_object_t reply = xpc_dictionary_create(nullptr, nullptr, 0);
  xpc_dictionary_set_int64(reply, "version", PV_PROTOCOL_VERSION);
  xpc_dictionary_set_bool(reply, "ok", true);
  xpc_dictionary_set_string(reply, "requestId", "removal-request");
  xpc_dictionary_set_string(reply, "state", "pending");
  xpc_dictionary_set_string(reply, "vaultId",
                            "00112233445566778899aabbccddeeff");
  xpc_dictionary_set_string(reply, "targetEndpointId",
                            "9999aaaabbbbccccddddeeeeffff0000");
  xpc_dictionary_set_uint64(reply, "createdAt", 1721111111);
  xpc_dictionary_set_data(reply, "ceremonyId", id, sizeof id);
  xpc_dictionary_set_data(reply, "signedEntry", body, sizeof body);
  xpc_dictionary_set_data(reply, "recoveryWrap", body, sizeof body);
  xpc_dictionary_set_data(reply, "transcriptDigest", digest, sizeof digest);
  xpc_dictionary_set_uint64(reply, "baseSequence", 11);
  xpc_dictionary_set_data(reply, "baseHead", digest, sizeof digest);
  xpc_dictionary_set_data(reply, "baseMembership", digest, sizeof digest);
  xpc_dictionary_set_uint64(reply, "baseEpoch", 4);
  xpc_dictionary_set_uint64(reply, "pendingEpoch", 5);
  xpc_object_t wraps = xpc_array_create(nullptr, 0);
  for (const char *recipient : {"11112222333344445555666677778888",
                                "22223333444455556666777788889999"}) {
    xpc_object_t item = xpc_dictionary_create(nullptr, nullptr, 0);
    xpc_dictionary_set_string(item, "recipientEndpointId", recipient);
    xpc_dictionary_set_data(item, "envelopeId", id, sizeof id);
    xpc_dictionary_set_data(item, "wrapHash", digest, sizeof digest);
    xpc_dictionary_set_data(item, "encodedWrap", body, sizeof body);
    xpc_array_append_value(wraps, item);
    xpc_release(item);
  }
  xpc_dictionary_set_value(reply, "recipientEekWraps", wraps);
  xpc_release(wraps);
  return reply;
}

}

int main() {
  const char *oldBroker = "11112222333344445555666677778888";
  const char *candidateBroker = "9999aaaabbbbccccddddeeeeffff0000";
  xpc_object_t valid = MakeReply(oldBroker, candidateBroker);
  PVParsedReply parsed = PVParseReply(
      valid, PVOperation::ReplaceBroker, "replacement-request",
      "00112233445566778899aabbccddeeff");
  assert(parsed.failure == PVFailure::None);
  assert(PVBrokerReplacementReplyMatchesRequest(parsed, oldBroker,
                                                candidateBroker));
  assert(!PVBrokerReplacementReplyMatchesRequest(
      parsed, "00000000000000000000000000000000", candidateBroker));

  for (PVOperation operation : {PVOperation::ChallengeBrokerReplacement,
                                PVOperation::ConfirmBrokerReplacement,
                                PVOperation::ApproveBrokerReplacement}) {
    xpc_object_t ceremony = MakeCeremonyReply(operation);
    PVParsedReply ceremonyParsed = PVParseReply(
        ceremony, operation, "ceremony-request",
        "00112233445566778899aabbccddeeff");
    assert(ceremonyParsed.failure == PVFailure::None);
    xpc_object_t extraCeremony = xpc_copy(ceremony);
    xpc_dictionary_set_string(extraCeremony, "baseHead", "not-accepted");
    assert(PVParseReply(extraCeremony, operation, "ceremony-request",
                        "00112233445566778899aabbccddeeff")
               .failure == PVFailure::MalformedReply);
    xpc_release(extraCeremony);
    xpc_release(ceremony);
  }

  xpc_object_t substitutedApproval =
      MakeCeremonyReply(PVOperation::ApproveBrokerReplacement);
  uint8_t sameDrain[16] = {0x41};
  xpc_dictionary_set_data(substitutedApproval, "drainId", sameDrain,
                          sizeof sameDrain);
  assert(PVParseReply(substitutedApproval,
                      PVOperation::ApproveBrokerReplacement,
                      "ceremony-request",
                      "00112233445566778899aabbccddeeff")
             .failure == PVFailure::MalformedReply);
  xpc_release(substitutedApproval);

  xpc_object_t removal = MakeEndpointRemovalReply();
  PVParsedReply removalParsed = PVParseReply(
      removal, PVOperation::RemoveEndpoint, "removal-request",
      "00112233445566778899aabbccddeeff");
  assert(removalParsed.failure == PVFailure::None &&
         removalParsed.recipientEekWraps.size() == 2 &&
         removalParsed.baseSequence == 11 && removalParsed.baseEpoch == 4 &&
         removalParsed.pendingEpoch == 5);
  xpc_object_t missingWraps = xpc_copy(removal);
  xpc_dictionary_set_value(missingWraps, "recipientEekWraps", nullptr);
  assert(PVParseReply(missingWraps, PVOperation::RemoveEndpoint,
                      "removal-request",
                      "00112233445566778899aabbccddeeff")
             .failure == PVFailure::MalformedReply);
  xpc_object_t substitutedEpoch = xpc_copy(removal);
  xpc_dictionary_set_uint64(substitutedEpoch, "pendingEpoch", 6);
  assert(PVParseReply(substitutedEpoch, PVOperation::RemoveEndpoint,
                      "removal-request",
                      "00112233445566778899aabbccddeeff")
             .failure == PVFailure::MalformedReply);
  xpc_object_t extraRemoval = xpc_copy(removal);
  xpc_dictionary_set_bool(extraRemoval, "checkpointSigned", true);
  assert(PVParseReply(extraRemoval, PVOperation::RemoveEndpoint,
                      "removal-request",
                      "00112233445566778899aabbccddeeff")
             .failure == PVFailure::MalformedReply);
  xpc_release(extraRemoval);
  xpc_release(substitutedEpoch);
  xpc_release(missingWraps);
  xpc_release(removal);

  xpc_object_t missing = xpc_copy(valid);
  xpc_dictionary_set_value(missing, "checkpointDigest", nullptr);
  assert(PVParseReply(missing, PVOperation::ReplaceBroker,
                      "replacement-request",
                      "00112233445566778899aabbccddeeff")
             .failure == PVFailure::MalformedReply);

  xpc_object_t substituted = xpc_copy(valid);
  xpc_dictionary_set_string(substituted, "baseHead", "not-a-digest");
  assert(PVParseReply(substituted, PVOperation::ReplaceBroker,
                      "replacement-request",
                      "00112233445566778899aabbccddeeff")
             .failure == PVFailure::MalformedReply);

  xpc_object_t extra = xpc_copy(valid);
  xpc_dictionary_set_string(extra, "callerIdentity", "example");
  assert(PVParseReply(extra, PVOperation::ReplaceBroker,
                      "replacement-request",
                      "00112233445566778899aabbccddeeff")
             .failure == PVFailure::MalformedReply);

  std::vector<uint8_t> oversized(PV_ROTATION_ARTIFACT_MAXIMUM_BYTES + 1, 0);
  xpc_object_t oversizedReply = xpc_copy(valid);
  xpc_dictionary_set_data(oversizedReply, "signedEntry", oversized.data(),
                          oversized.size());
  assert(PVParseReply(oversizedReply, PVOperation::ReplaceBroker,
                      "replacement-request",
                      "00112233445566778899aabbccddeeff")
             .failure == PVFailure::MalformedReply);

  xpc_release(oversizedReply);
  xpc_release(extra);
  xpc_release(substituted);
  xpc_release(missing);
  xpc_release(valid);
  return 0;
}
