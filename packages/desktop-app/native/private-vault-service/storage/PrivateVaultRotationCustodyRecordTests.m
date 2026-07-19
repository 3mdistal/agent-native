#import <Foundation/Foundation.h>

#import "PrivateVaultRotationCustodyRecord.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(condition, message)                                               \
  do {                                                                          \
    if (!(condition)) {                                                         \
      fprintf(stderr, "FAIL: %s\n", message);                                 \
      exit(1);                                                                  \
    }                                                                           \
  } while (0)

static void Fill(uint8_t *bytes, size_t length, uint8_t value) {
  memset(bytes, value, length);
}

static AncPrivateVaultRotationCustodySnapshot Snapshot(
    const uint8_t signingSeed[32], const uint8_t boxSeed[32]) {
  AncPrivateVaultRotationCustodySnapshot snapshot = {0};
  snapshot.record_version = ANC_PV_ROTATION_CUSTODY_VERSION;
  snapshot.base_custody_generation = 7;
  snapshot.target_custody_generation = 8;
  snapshot.active_epoch = 3;
  snapshot.pending_epoch = 4;
  snapshot.expected_next_sequence = 12;
  snapshot.preparation_fence_generation = 9;
  memcpy(snapshot.vault_id, "vault", 5);
  snapshot.vault_id_length = 5;
  Fill(snapshot.target_endpoint_id, 16, 1);
  Fill(snapshot.ceremony_id, 16, 2);
  Fill(snapshot.base_snapshot_digest, 32, 3);
  Fill(snapshot.expected_previous_head, 32, 4);
  Fill(snapshot.successor_membership_digest, 32, 5);
  Fill(snapshot.preparation_record_digest, 32, 6);
  uint8_t signingPrivate[64] = {0};
  uint8_t boxPrivate[32] = {0};
  CHECK(anc_pv_ed25519_seed_keypair(snapshot.signing_public_key, signingPrivate,
                                    signingSeed) == ANC_PV_CRYPTO_OK,
        "derive signing public key");
  CHECK(anc_pv_box_seed_keypair(snapshot.box_public_key, boxPrivate, boxSeed) ==
            ANC_PV_CRYPTO_OK,
        "derive box public key");
  anc_pv_zeroize(signingPrivate, sizeof signingPrivate);
  anc_pv_zeroize(boxPrivate, sizeof boxPrivate);
  return snapshot;
}

static void RecomputeChecksum(
    uint8_t record[ANC_PV_ROTATION_CUSTODY_RECORD_BYTES]) {
  static const uint8_t domain[] =
      "agent-native/private-vault/rotation-custody-record/checksum/anc-v1";
  CHECK(anc_pv_blake2b_256_two_part(record + 1056, domain, sizeof domain,
                                    record, 1056) == ANC_PV_CRYPTO_OK,
        "recompute checksum");
}

int main(void) {
  @autoreleasepool {
    uint8_t secrets[5][32];
    for (size_t index = 0; index < 5; index += 1)
      Fill(secrets[index], 32, (uint8_t)(20 + index));
    AncPrivateVaultRotationCustodySnapshot snapshot =
        Snapshot(secrets[0], secrets[1]);
    AncPrivateVaultRotationCustodySecretInputs inputs = {
        .signing_seed = secrets[0],
        .box_seed = secrets[1],
        .local_state_key = secrets[2],
        .active_epoch_key = secrets[3],
        .pending_epoch_key = secrets[4],
    };
    uint8_t record[ANC_PV_ROTATION_CUSTODY_RECORD_BYTES] = {0};
    CHECK(anc_pv_rotation_custody_record_encode(
              &snapshot, &inputs, record, sizeof record) ==
              ANC_PV_ROTATION_CUSTODY_OK,
          "encode dedicated rotation custody record");

    uint8_t outputs[5][32] = {0};
    AncPrivateVaultRotationCustodySecretOutputs outputDescriptor = {
        .signing_seed = outputs[0],
        .box_seed = outputs[1],
        .local_state_key = outputs[2],
        .active_epoch_key = outputs[3],
        .pending_epoch_key = outputs[4],
    };
    AncPrivateVaultRotationCustodySnapshot decoded;
    CHECK(anc_pv_rotation_custody_record_decode(
              record, sizeof record, &decoded, &outputDescriptor) ==
              ANC_PV_ROTATION_CUSTODY_OK,
          "decode dedicated rotation custody record");
    CHECK(decoded.target_custody_generation == 8 &&
              decoded.pending_epoch == 4 &&
              memcmp(outputs, secrets, sizeof secrets) == 0,
          "round trip exact public bindings and five secrets");

    AncPrivateVaultRotationCustodySnapshot substituted = snapshot;
    substituted.signing_public_key[0] ^= 1;
    memset(record, 0x55, sizeof record);
    CHECK(anc_pv_rotation_custody_record_encode(
              &substituted, &inputs, record, sizeof record) ==
                  ANC_PV_ROTATION_CUSTODY_INVALID_RECORD &&
              record[0] == 0,
          "public-key substitution rejected during encode");

    CHECK(anc_pv_rotation_custody_record_encode(
              &snapshot, &inputs, record, sizeof record) ==
              ANC_PV_ROTATION_CUSTODY_OK,
          "restore record");
    record[384] ^= 1;
    RecomputeChecksum(record);
    CHECK(anc_pv_rotation_custody_record_decode(
              record, sizeof record, &decoded, &outputDescriptor) ==
              ANC_PV_ROTATION_CUSTODY_INVALID_RECORD,
          "checksummed public-key substitution rejected during decode");

    uint8_t aliasRecord[ANC_PV_ROTATION_CUSTODY_RECORD_BYTES];
    memset(aliasRecord, 0x5a, sizeof aliasRecord);
    uint8_t aliasOriginal[ANC_PV_ROTATION_CUSTODY_RECORD_BYTES];
    memcpy(aliasOriginal, aliasRecord, sizeof aliasRecord);
    AncPrivateVaultRotationCustodySecretInputs aliasInputs = inputs;
    aliasInputs.signing_seed = aliasRecord + 100;
    CHECK(anc_pv_rotation_custody_record_encode(
              &snapshot, &aliasInputs, aliasRecord, sizeof aliasRecord) ==
                  ANC_PV_ROTATION_CUSTODY_INVALID_ARGUMENT &&
              memcmp(aliasRecord, aliasOriginal, sizeof aliasRecord) == 0,
          "encode source alias rejected without clobbering source");

    CHECK(anc_pv_rotation_custody_record_encode(
              &snapshot, &inputs, record, sizeof record) ==
              ANC_PV_ROTATION_CUSTODY_OK,
          "restore record after alias test");
    uint8_t recordOriginal[sizeof record];
    memcpy(recordOriginal, record, sizeof record);
    memset(&decoded, 0x6a, sizeof decoded);
    AncPrivateVaultRotationCustodySnapshot decodedOriginal = decoded;
    AncPrivateVaultRotationCustodySecretOutputs aliasOutputs =
        outputDescriptor;
    aliasOutputs.pending_epoch_key = record + 100;
    CHECK(anc_pv_rotation_custody_record_decode(
              record, sizeof record, &decoded, &aliasOutputs) ==
                  ANC_PV_ROTATION_CUSTODY_INVALID_ARGUMENT &&
              memcmp(record, recordOriginal, sizeof record) == 0 &&
              memcmp(&decoded, &decodedOriginal, sizeof decoded) == 0,
          "decode destination alias rejected without clobbering source");

    aliasOutputs = outputDescriptor;
    aliasOutputs.pending_epoch_key = outputs[3];
    memset(&decoded, 0x6b, sizeof decoded);
    decodedOriginal = decoded;
    CHECK(anc_pv_rotation_custody_record_decode(
              record, sizeof record, &decoded, &aliasOutputs) ==
                  ANC_PV_ROTATION_CUSTODY_INVALID_ARGUMENT &&
              memcmp(&decoded, &decodedOriginal, sizeof decoded) == 0,
          "overlapping secret outputs rejected untouched");
  }
  fprintf(stdout, "PASS: rotation custody record tests\n");
  return 0;
}
