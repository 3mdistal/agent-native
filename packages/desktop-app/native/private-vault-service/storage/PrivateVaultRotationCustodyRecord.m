#import "PrivateVaultRotationCustodyRecord.h"

#include <string.h>

enum {
  ANC_PV_ROT_OFF_MAGIC = 0,
  ANC_PV_ROT_OFF_VERSION = 4,
  ANC_PV_ROT_OFF_LENGTH = 6,
  ANC_PV_ROT_OFF_BASE_GENERATION = 8,
  ANC_PV_ROT_OFF_TARGET_GENERATION = 16,
  ANC_PV_ROT_OFF_ACTIVE_EPOCH = 24,
  ANC_PV_ROT_OFF_PENDING_EPOCH = 32,
  ANC_PV_ROT_OFF_EXPECTED_SEQUENCE = 40,
  ANC_PV_ROT_OFF_PREPARATION_FENCE = 48,
  ANC_PV_ROT_OFF_VAULT_ID_LENGTH = 56,
  ANC_PV_ROT_OFF_VAULT_ID = 64,
  ANC_PV_ROT_OFF_TARGET_ENDPOINT = 224,
  ANC_PV_ROT_OFF_CEREMONY = 240,
  ANC_PV_ROT_OFF_BASE_DIGEST = 256,
  ANC_PV_ROT_OFF_PREVIOUS_HEAD = 288,
  ANC_PV_ROT_OFF_MEMBERSHIP = 320,
  ANC_PV_ROT_OFF_PREPARATION_DIGEST = 352,
  ANC_PV_ROT_OFF_SIGNING_PUBLIC = 384,
  ANC_PV_ROT_OFF_BOX_PUBLIC = 416,
  ANC_PV_ROT_OFF_SIGNING_SEED = 448,
  ANC_PV_ROT_OFF_BOX_SEED = 480,
  ANC_PV_ROT_OFF_LOCAL_STATE_KEY = 512,
  ANC_PV_ROT_OFF_ACTIVE_EPOCH_KEY = 544,
  ANC_PV_ROT_OFF_PENDING_EPOCH_KEY = 576,
  ANC_PV_ROT_OFF_RESERVED = 608,
  ANC_PV_ROT_OFF_CHECKSUM = 1056,
};

static const uint8_t kAncRotationCustodyMagic[4] = {'A', 'N', 'V', 'R'};
static const uint8_t kAncRotationCustodyChecksumDomain[] =
    "agent-native/private-vault/rotation-custody-record/checksum/anc-v1";
static const uint64_t kAncRotationCustodyMaxSafeInteger =
    9007199254740991ULL;

_Static_assert(ANC_PV_ROT_OFF_CHECKSUM + 32 ==
                   ANC_PV_ROTATION_CUSTODY_RECORD_BYTES,
               "rotation custody record must remain exactly 1088 bytes");

static void AncRotationWriteU16(uint8_t *output, uint16_t value) {
  output[0] = (uint8_t)(value >> 8);
  output[1] = (uint8_t)value;
}

static uint16_t AncRotationReadU16(const uint8_t *input) {
  return (uint16_t)(((uint16_t)input[0] << 8) | input[1]);
}

static void AncRotationWriteU64(uint8_t *output, uint64_t value) {
  for (size_t index = 0; index < 8; index += 1)
    output[index] = (uint8_t)(value >> (56 - index * 8));
}

static uint64_t AncRotationReadU64(const uint8_t *input) {
  uint64_t value = 0;
  for (size_t index = 0; index < 8; index += 1)
    value = (value << 8) | input[index];
  return value;
}

static int AncRotationIsZero(const uint8_t *bytes, size_t length) {
  uint8_t aggregate = 0;
  for (size_t index = 0; index < length; index += 1)
    aggregate |= bytes[index];
  return aggregate == 0;
}

typedef struct AncRotationRange {
  const void *pointer;
  size_t length;
} AncRotationRange;

static int AncRotationRangesOverlap(AncRotationRange left,
                                    AncRotationRange right) {
  if (left.pointer == NULL || right.pointer == NULL || left.length == 0 ||
      right.length == 0)
    return 0;
  uintptr_t leftStart = (uintptr_t)left.pointer;
  uintptr_t rightStart = (uintptr_t)right.pointer;
  if (leftStart > UINTPTR_MAX - left.length ||
      rightStart > UINTPTR_MAX - right.length)
    return 1;
  return leftStart < rightStart + right.length &&
         rightStart < leftStart + left.length;
}

static int AncRotationAnyOverlap(const AncRotationRange *ranges,
                                 size_t count) {
  for (size_t left = 0; left < count; left += 1) {
    for (size_t right = left + 1; right < count; right += 1) {
      if (AncRotationRangesOverlap(ranges[left], ranges[right]))
        return 1;
    }
  }
  return 0;
}

static int AncRotationValidPointers(
    const AncPrivateVaultRotationCustodySecretInputs *secrets) {
  return secrets != NULL && secrets->signing_seed != NULL &&
         secrets->box_seed != NULL && secrets->local_state_key != NULL &&
         secrets->active_epoch_key != NULL &&
         secrets->pending_epoch_key != NULL;
}

static int AncRotationValidOutputs(
    const AncPrivateVaultRotationCustodySecretOutputs *outputs) {
  return outputs != NULL && outputs->signing_seed != NULL &&
         outputs->box_seed != NULL && outputs->local_state_key != NULL &&
         outputs->active_epoch_key != NULL &&
         outputs->pending_epoch_key != NULL;
}

static void AncRotationClearOutputs(
    const AncPrivateVaultRotationCustodySecretOutputs *outputs) {
  if (!AncRotationValidOutputs(outputs))
    return;
  anc_pv_zeroize(outputs->signing_seed, 32);
  anc_pv_zeroize(outputs->box_seed, 32);
  anc_pv_zeroize(outputs->local_state_key, 32);
  anc_pv_zeroize(outputs->active_epoch_key, 32);
  anc_pv_zeroize(outputs->pending_epoch_key, 32);
}

static int AncRotationValidSnapshot(
    const AncPrivateVaultRotationCustodySnapshot *snapshot) {
  if (snapshot == NULL ||
      snapshot->record_version != ANC_PV_ROTATION_CUSTODY_VERSION ||
      snapshot->vault_id_length == 0 ||
      snapshot->vault_id_length > ANC_PV_ROTATION_CUSTODY_VAULT_ID_BYTES ||
      memchr(snapshot->vault_id, 0, snapshot->vault_id_length) != NULL ||
      !AncRotationIsZero(snapshot->vault_id + snapshot->vault_id_length,
                         ANC_PV_ROTATION_CUSTODY_VAULT_ID_BYTES -
                             snapshot->vault_id_length))
    return 0;
  const uint64_t values[] = {
      snapshot->base_custody_generation,
      snapshot->target_custody_generation,
      snapshot->active_epoch,
      snapshot->pending_epoch,
      snapshot->expected_next_sequence,
      snapshot->preparation_fence_generation,
  };
  for (size_t index = 0; index < sizeof values / sizeof values[0]; index += 1) {
    if (values[index] == 0 || values[index] > kAncRotationCustodyMaxSafeInteger)
      return 0;
  }
  return snapshot->base_custody_generation < kAncRotationCustodyMaxSafeInteger &&
         snapshot->target_custody_generation ==
             snapshot->base_custody_generation + 1 &&
         snapshot->active_epoch < kAncRotationCustodyMaxSafeInteger &&
         snapshot->pending_epoch == snapshot->active_epoch + 1 &&
         !AncRotationIsZero(snapshot->target_endpoint_id, 16) &&
         !AncRotationIsZero(snapshot->ceremony_id, 16) &&
         !AncRotationIsZero(snapshot->base_snapshot_digest, 32) &&
         !AncRotationIsZero(snapshot->expected_previous_head, 32) &&
         !AncRotationIsZero(snapshot->successor_membership_digest, 32) &&
         !AncRotationIsZero(snapshot->preparation_record_digest, 32) &&
         !AncRotationIsZero(snapshot->signing_public_key, 32) &&
         !AncRotationIsZero(snapshot->box_public_key, 32);
}

static AncPrivateVaultRotationCustodyRecordStatus
AncRotationChecksum(uint8_t output[32], const uint8_t *record) {
  return anc_pv_blake2b_256_two_part(
             output, kAncRotationCustodyChecksumDomain,
             sizeof kAncRotationCustodyChecksumDomain, record,
             ANC_PV_ROT_OFF_CHECKSUM) == ANC_PV_CRYPTO_OK
             ? ANC_PV_ROTATION_CUSTODY_OK
             : ANC_PV_ROTATION_CUSTODY_CRYPTO_FAILED;
}

static AncPrivateVaultRotationCustodyRecordStatus AncRotationValidateKeys(
    const AncPrivateVaultRotationCustodySnapshot *snapshot,
    const AncPrivateVaultRotationCustodySecretInputs *secrets) {
  uint8_t signingPublic[32] = {0};
  uint8_t signingPrivate[64] = {0};
  uint8_t boxPublic[32] = {0};
  uint8_t boxPrivate[32] = {0};
  AncPrivateVaultRotationCustodyRecordStatus status =
      ANC_PV_ROTATION_CUSTODY_CRYPTO_FAILED;
  if (anc_pv_ed25519_seed_keypair(signingPublic, signingPrivate,
                                  secrets->signing_seed) != ANC_PV_CRYPTO_OK ||
      anc_pv_box_seed_keypair(boxPublic, boxPrivate, secrets->box_seed) !=
          ANC_PV_CRYPTO_OK)
    goto cleanup;
  status = anc_pv_memcmp(signingPublic, snapshot->signing_public_key, 32) ==
                       ANC_PV_CRYPTO_OK &&
                   anc_pv_memcmp(boxPublic, snapshot->box_public_key, 32) ==
                       ANC_PV_CRYPTO_OK
               ? ANC_PV_ROTATION_CUSTODY_OK
               : ANC_PV_ROTATION_CUSTODY_INVALID_RECORD;
cleanup:
  anc_pv_zeroize(signingPublic, sizeof signingPublic);
  anc_pv_zeroize(signingPrivate, sizeof signingPrivate);
  anc_pv_zeroize(boxPublic, sizeof boxPublic);
  anc_pv_zeroize(boxPrivate, sizeof boxPrivate);
  return status;
}

AncPrivateVaultRotationCustodyRecordStatus
anc_pv_rotation_custody_record_encode(
    const AncPrivateVaultRotationCustodySnapshot *snapshot,
    const AncPrivateVaultRotationCustodySecretInputs *secrets, uint8_t *record,
    size_t record_length) {
  if (record == NULL || record_length != ANC_PV_ROTATION_CUSTODY_RECORD_BYTES ||
      snapshot == NULL || secrets == NULL)
    return ANC_PV_ROTATION_CUSTODY_INVALID_ARGUMENT;
  const AncRotationRange fixedRanges[] = {
      {record, record_length},
      {snapshot, sizeof *snapshot},
      {secrets, sizeof *secrets},
  };
  if (AncRotationAnyOverlap(fixedRanges,
                            sizeof fixedRanges / sizeof fixedRanges[0]))
    return ANC_PV_ROTATION_CUSTODY_INVALID_ARGUMENT;
  AncPrivateVaultRotationCustodySecretInputs captured = *secrets;
  if (!AncRotationValidPointers(&captured))
    return ANC_PV_ROTATION_CUSTODY_INVALID_ARGUMENT;
  const AncRotationRange allRanges[] = {
      fixedRanges[0], fixedRanges[1], fixedRanges[2],
      {captured.signing_seed, 32}, {captured.box_seed, 32},
      {captured.local_state_key, 32}, {captured.active_epoch_key, 32},
      {captured.pending_epoch_key, 32},
  };
  if (AncRotationAnyOverlap(allRanges,
                            sizeof allRanges / sizeof allRanges[0]))
    return ANC_PV_ROTATION_CUSTODY_INVALID_ARGUMENT;
  anc_pv_zeroize(record, record_length);
  if (!AncRotationValidSnapshot(snapshot) ||
      AncRotationIsZero(captured.signing_seed, 32) ||
      AncRotationIsZero(captured.box_seed, 32) ||
      AncRotationIsZero(captured.local_state_key, 32) ||
      AncRotationIsZero(captured.active_epoch_key, 32) ||
      AncRotationIsZero(captured.pending_epoch_key, 32) ||
      anc_pv_memcmp(captured.active_epoch_key, captured.pending_epoch_key, 32) ==
          ANC_PV_CRYPTO_OK)
    return ANC_PV_ROTATION_CUSTODY_INVALID_ARGUMENT;
  AncPrivateVaultRotationCustodyRecordStatus keyStatus =
      AncRotationValidateKeys(snapshot, &captured);
  if (keyStatus != ANC_PV_ROTATION_CUSTODY_OK)
    return keyStatus;

  memcpy(record + ANC_PV_ROT_OFF_MAGIC, kAncRotationCustodyMagic, 4);
  AncRotationWriteU16(record + ANC_PV_ROT_OFF_VERSION,
                      ANC_PV_ROTATION_CUSTODY_VERSION);
  AncRotationWriteU16(record + ANC_PV_ROT_OFF_LENGTH,
                      ANC_PV_ROTATION_CUSTODY_RECORD_BYTES);
  AncRotationWriteU64(record + ANC_PV_ROT_OFF_BASE_GENERATION,
                      snapshot->base_custody_generation);
  AncRotationWriteU64(record + ANC_PV_ROT_OFF_TARGET_GENERATION,
                      snapshot->target_custody_generation);
  AncRotationWriteU64(record + ANC_PV_ROT_OFF_ACTIVE_EPOCH,
                      snapshot->active_epoch);
  AncRotationWriteU64(record + ANC_PV_ROT_OFF_PENDING_EPOCH,
                      snapshot->pending_epoch);
  AncRotationWriteU64(record + ANC_PV_ROT_OFF_EXPECTED_SEQUENCE,
                      snapshot->expected_next_sequence);
  AncRotationWriteU64(record + ANC_PV_ROT_OFF_PREPARATION_FENCE,
                      snapshot->preparation_fence_generation);
  AncRotationWriteU16(record + ANC_PV_ROT_OFF_VAULT_ID_LENGTH,
                      (uint16_t)snapshot->vault_id_length);
  memcpy(record + ANC_PV_ROT_OFF_VAULT_ID, snapshot->vault_id,
         snapshot->vault_id_length);
  memcpy(record + ANC_PV_ROT_OFF_TARGET_ENDPOINT,
         snapshot->target_endpoint_id, 16);
  memcpy(record + ANC_PV_ROT_OFF_CEREMONY, snapshot->ceremony_id, 16);
  memcpy(record + ANC_PV_ROT_OFF_BASE_DIGEST, snapshot->base_snapshot_digest,
         32);
  memcpy(record + ANC_PV_ROT_OFF_PREVIOUS_HEAD,
         snapshot->expected_previous_head, 32);
  memcpy(record + ANC_PV_ROT_OFF_MEMBERSHIP,
         snapshot->successor_membership_digest, 32);
  memcpy(record + ANC_PV_ROT_OFF_PREPARATION_DIGEST,
         snapshot->preparation_record_digest, 32);
  memcpy(record + ANC_PV_ROT_OFF_SIGNING_PUBLIC, snapshot->signing_public_key,
         32);
  memcpy(record + ANC_PV_ROT_OFF_BOX_PUBLIC, snapshot->box_public_key, 32);
  memcpy(record + ANC_PV_ROT_OFF_SIGNING_SEED, captured.signing_seed, 32);
  memcpy(record + ANC_PV_ROT_OFF_BOX_SEED, captured.box_seed, 32);
  memcpy(record + ANC_PV_ROT_OFF_LOCAL_STATE_KEY, captured.local_state_key, 32);
  memcpy(record + ANC_PV_ROT_OFF_ACTIVE_EPOCH_KEY, captured.active_epoch_key,
         32);
  memcpy(record + ANC_PV_ROT_OFF_PENDING_EPOCH_KEY, captured.pending_epoch_key,
         32);
  uint8_t checksum[32] = {0};
  AncPrivateVaultRotationCustodyRecordStatus status =
      AncRotationChecksum(checksum, record);
  if (status == ANC_PV_ROTATION_CUSTODY_OK)
    memcpy(record + ANC_PV_ROT_OFF_CHECKSUM, checksum, 32);
  else
    anc_pv_zeroize(record, record_length);
  anc_pv_zeroize(checksum, sizeof checksum);
  return status;
}

AncPrivateVaultRotationCustodyRecordStatus
anc_pv_rotation_custody_record_decode(
    const uint8_t *record, size_t record_length,
    AncPrivateVaultRotationCustodySnapshot *snapshot,
    const AncPrivateVaultRotationCustodySecretOutputs *secret_outputs) {
  if (record == NULL || record_length != ANC_PV_ROTATION_CUSTODY_RECORD_BYTES ||
      snapshot == NULL || secret_outputs == NULL)
    return ANC_PV_ROTATION_CUSTODY_INVALID_ARGUMENT;
  const AncRotationRange fixedRanges[] = {
      {record, record_length},
      {snapshot, sizeof *snapshot},
      {secret_outputs, sizeof *secret_outputs},
  };
  if (AncRotationAnyOverlap(fixedRanges,
                            sizeof fixedRanges / sizeof fixedRanges[0]))
    return ANC_PV_ROTATION_CUSTODY_INVALID_ARGUMENT;
  AncPrivateVaultRotationCustodySecretOutputs captured = *secret_outputs;
  if (!AncRotationValidOutputs(&captured))
    return ANC_PV_ROTATION_CUSTODY_INVALID_ARGUMENT;
  const AncRotationRange allRanges[] = {
      fixedRanges[0], fixedRanges[1], fixedRanges[2],
      {captured.signing_seed, 32}, {captured.box_seed, 32},
      {captured.local_state_key, 32}, {captured.active_epoch_key, 32},
      {captured.pending_epoch_key, 32},
  };
  if (AncRotationAnyOverlap(allRanges,
                            sizeof allRanges / sizeof allRanges[0]))
    return ANC_PV_ROTATION_CUSTODY_INVALID_ARGUMENT;
  anc_pv_rotation_custody_snapshot_zero(snapshot);
  AncRotationClearOutputs(&captured);
  if (memcmp(record + ANC_PV_ROT_OFF_MAGIC, kAncRotationCustodyMagic, 4) != 0 ||
      AncRotationReadU16(record + ANC_PV_ROT_OFF_VERSION) !=
          ANC_PV_ROTATION_CUSTODY_VERSION ||
      AncRotationReadU16(record + ANC_PV_ROT_OFF_LENGTH) !=
          ANC_PV_ROTATION_CUSTODY_RECORD_BYTES ||
      !AncRotationIsZero(record + ANC_PV_ROT_OFF_VAULT_ID_LENGTH + 2, 6) ||
      !AncRotationIsZero(record + ANC_PV_ROT_OFF_RESERVED,
                         ANC_PV_ROT_OFF_CHECKSUM - ANC_PV_ROT_OFF_RESERVED))
    return ANC_PV_ROTATION_CUSTODY_INVALID_RECORD;
  uint8_t checksum[32] = {0};
  AncPrivateVaultRotationCustodyRecordStatus checksumStatus =
      AncRotationChecksum(checksum, record);
  if (checksumStatus != ANC_PV_ROTATION_CUSTODY_OK)
    return checksumStatus;
  if (anc_pv_memcmp(checksum, record + ANC_PV_ROT_OFF_CHECKSUM, 32) !=
      ANC_PV_CRYPTO_OK) {
    anc_pv_zeroize(checksum, sizeof checksum);
    return ANC_PV_ROTATION_CUSTODY_CHECKSUM_FAILED;
  }
  anc_pv_zeroize(checksum, sizeof checksum);

  snapshot->record_version = ANC_PV_ROTATION_CUSTODY_VERSION;
  snapshot->base_custody_generation =
      AncRotationReadU64(record + ANC_PV_ROT_OFF_BASE_GENERATION);
  snapshot->target_custody_generation =
      AncRotationReadU64(record + ANC_PV_ROT_OFF_TARGET_GENERATION);
  snapshot->active_epoch = AncRotationReadU64(record + ANC_PV_ROT_OFF_ACTIVE_EPOCH);
  snapshot->pending_epoch =
      AncRotationReadU64(record + ANC_PV_ROT_OFF_PENDING_EPOCH);
  snapshot->expected_next_sequence =
      AncRotationReadU64(record + ANC_PV_ROT_OFF_EXPECTED_SEQUENCE);
  snapshot->preparation_fence_generation =
      AncRotationReadU64(record + ANC_PV_ROT_OFF_PREPARATION_FENCE);
  snapshot->vault_id_length =
      AncRotationReadU16(record + ANC_PV_ROT_OFF_VAULT_ID_LENGTH);
  if (snapshot->vault_id_length <= ANC_PV_ROTATION_CUSTODY_VAULT_ID_BYTES)
    memcpy(snapshot->vault_id, record + ANC_PV_ROT_OFF_VAULT_ID,
           snapshot->vault_id_length);
  memcpy(snapshot->target_endpoint_id,
         record + ANC_PV_ROT_OFF_TARGET_ENDPOINT, 16);
  memcpy(snapshot->ceremony_id, record + ANC_PV_ROT_OFF_CEREMONY, 16);
  memcpy(snapshot->base_snapshot_digest, record + ANC_PV_ROT_OFF_BASE_DIGEST,
         32);
  memcpy(snapshot->expected_previous_head, record + ANC_PV_ROT_OFF_PREVIOUS_HEAD,
         32);
  memcpy(snapshot->successor_membership_digest,
         record + ANC_PV_ROT_OFF_MEMBERSHIP, 32);
  memcpy(snapshot->preparation_record_digest,
         record + ANC_PV_ROT_OFF_PREPARATION_DIGEST, 32);
  memcpy(snapshot->signing_public_key, record + ANC_PV_ROT_OFF_SIGNING_PUBLIC,
         32);
  memcpy(snapshot->box_public_key, record + ANC_PV_ROT_OFF_BOX_PUBLIC, 32);
  if (!AncRotationValidSnapshot(snapshot))
    goto invalid;
  memcpy(captured.signing_seed, record + ANC_PV_ROT_OFF_SIGNING_SEED, 32);
  memcpy(captured.box_seed, record + ANC_PV_ROT_OFF_BOX_SEED, 32);
  memcpy(captured.local_state_key,
         record + ANC_PV_ROT_OFF_LOCAL_STATE_KEY, 32);
  memcpy(captured.active_epoch_key,
         record + ANC_PV_ROT_OFF_ACTIVE_EPOCH_KEY, 32);
  memcpy(captured.pending_epoch_key,
         record + ANC_PV_ROT_OFF_PENDING_EPOCH_KEY, 32);
  if (AncRotationIsZero(captured.signing_seed, 32) ||
      AncRotationIsZero(captured.box_seed, 32) ||
      AncRotationIsZero(captured.local_state_key, 32) ||
      AncRotationIsZero(captured.active_epoch_key, 32) ||
      AncRotationIsZero(captured.pending_epoch_key, 32) ||
      anc_pv_memcmp(captured.active_epoch_key, captured.pending_epoch_key, 32) ==
          ANC_PV_CRYPTO_OK)
    goto invalid;
  AncPrivateVaultRotationCustodySecretInputs inputs = {
      .signing_seed = captured.signing_seed,
      .box_seed = captured.box_seed,
      .local_state_key = captured.local_state_key,
      .active_epoch_key = captured.active_epoch_key,
      .pending_epoch_key = captured.pending_epoch_key,
  };
  if (AncRotationValidateKeys(snapshot, &inputs) !=
      ANC_PV_ROTATION_CUSTODY_OK)
    goto invalid;
  return ANC_PV_ROTATION_CUSTODY_OK;

invalid:
  anc_pv_rotation_custody_snapshot_zero(snapshot);
  AncRotationClearOutputs(&captured);
  return ANC_PV_ROTATION_CUSTODY_INVALID_RECORD;
}

void anc_pv_rotation_custody_snapshot_zero(
    AncPrivateVaultRotationCustodySnapshot *snapshot) {
  if (snapshot != NULL)
    anc_pv_zeroize(snapshot, sizeof *snapshot);
}
