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
