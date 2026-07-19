#ifndef AGENT_NATIVE_PRIVATE_VAULT_ROTATION_CUSTODY_RECORD_H
#define AGENT_NATIVE_PRIVATE_VAULT_ROTATION_CUSTODY_RECORD_H

#include <stddef.h>
#include <stdint.h>

#include "../crypto/PrivateVaultCrypto.h"

#ifdef __cplusplus
extern "C" {
#endif

enum {
  ANC_PV_ROTATION_CUSTODY_RECORD_BYTES = 1088,
  ANC_PV_ROTATION_CUSTODY_VERSION = 1,
  ANC_PV_ROTATION_CUSTODY_VAULT_ID_BYTES = 160,
};

typedef enum AncPrivateVaultRotationCustodyRecordStatus {
  ANC_PV_ROTATION_CUSTODY_OK = 0,
  ANC_PV_ROTATION_CUSTODY_INVALID_ARGUMENT = 1,
  ANC_PV_ROTATION_CUSTODY_INVALID_RECORD = 2,
  ANC_PV_ROTATION_CUSTODY_CHECKSUM_FAILED = 3,
  ANC_PV_ROTATION_CUSTODY_CRYPTO_FAILED = 4,
} AncPrivateVaultRotationCustodyRecordStatus;

typedef struct AncPrivateVaultRotationCustodySnapshot {
  uint16_t record_version;
  uint64_t base_custody_generation;
  uint64_t target_custody_generation;
  uint64_t active_epoch;
  uint64_t pending_epoch;
  uint64_t expected_next_sequence;
  uint64_t preparation_fence_generation;
  uint8_t vault_id[ANC_PV_ROTATION_CUSTODY_VAULT_ID_BYTES];
  size_t vault_id_length;
  uint8_t target_endpoint_id[16];
  uint8_t ceremony_id[16];
  uint8_t base_snapshot_digest[32];
  uint8_t expected_previous_head[32];
  uint8_t successor_membership_digest[32];
  uint8_t preparation_record_digest[32];
  uint8_t signing_public_key[32];
  uint8_t box_public_key[32];
} AncPrivateVaultRotationCustodySnapshot;

typedef struct AncPrivateVaultRotationCustodySecretInputs {
  const uint8_t *signing_seed;
  const uint8_t *box_seed;
  const uint8_t *local_state_key;
  const uint8_t *active_epoch_key;
  const uint8_t *pending_epoch_key;
} AncPrivateVaultRotationCustodySecretInputs;

typedef struct AncPrivateVaultRotationCustodySecretOutputs {
  uint8_t *signing_seed;
  uint8_t *box_seed;
  uint8_t *local_state_key;
  uint8_t *active_epoch_key;
  uint8_t *pending_epoch_key;
} AncPrivateVaultRotationCustodySecretOutputs;

AncPrivateVaultRotationCustodyRecordStatus
anc_pv_rotation_custody_record_encode(
    const AncPrivateVaultRotationCustodySnapshot *snapshot,
    const AncPrivateVaultRotationCustodySecretInputs *secrets, uint8_t *record,
    size_t record_length);

AncPrivateVaultRotationCustodyRecordStatus
anc_pv_rotation_custody_record_decode(
    const uint8_t *record, size_t record_length,
    AncPrivateVaultRotationCustodySnapshot *snapshot,
    const AncPrivateVaultRotationCustodySecretOutputs *secret_outputs);

void anc_pv_rotation_custody_snapshot_zero(
    AncPrivateVaultRotationCustodySnapshot *snapshot);

#ifdef __cplusplus
}
#endif

#endif
