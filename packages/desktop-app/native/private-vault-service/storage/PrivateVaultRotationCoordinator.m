#import "PrivateVaultRotationCoordinator.h"

#import "PrivateVaultRotationCoordinatorInternal.h"
#import "PrivateVaultRotationPreparationStoreInternal.h"
#import "PrivateVaultAuthorityStoreInternal.h"
#import "PrivateVaultAuthorityStoreRotationInternal.h"
#import "PrivateVaultCustodyRepositoryRotationInternal.h"
#import "PrivateVaultControlLogInternal.h"
#import "PrivateVaultBrokerReplacementBuilder.h"
#import "PrivateVaultEndpointRequest.h"
#import "PrivateVaultEndpointRemovalBuilder.h"
#import "PrivateVaultRecoveryWrapInternal.h"
#import "PrivateVaultAncCanonical.h"

#import <math.h>
#import <objc/runtime.h>
#import <Security/SecRandom.h>

static const uint64_t kAncRotationCoordinatorMaximumSafeInteger =
    UINT64_C(9007199254740991);

@interface AncPrivateVaultRotationCoordinatorResult ()
@property(nonatomic, readwrite) NSString *vaultId;
@property(nonatomic, readwrite)
    AncPrivateVaultRotationPreparationCheckpoint *preparationCheckpoint;
@property(nonatomic, readwrite)
    AncPrivateVaultAuthorityCheckpoint *authorityCheckpoint;
@property(nonatomic, readwrite) uint64_t custodyGeneration;
@property(nonatomic, readwrite) uint64_t activeEpoch;
@property(nonatomic, readwrite) uint64_t sequence;
@property(nonatomic, readwrite) NSData *headHash;
@property(nonatomic, readwrite) NSData *membershipHash;
@property(nonatomic, readwrite) uint64_t recoveryGeneration;
@property(nonatomic, readwrite) NSData *recoveryWrapHash;
@end

@interface AncPrivateVaultImmutableRotationCoordinatorResult
    : AncPrivateVaultRotationCoordinatorResult
@end

static void AncRotationCoordinatorRaiseImmutableMutation(void) {
  [NSException raise:NSInternalInconsistencyException
              format:@"rotation coordinator results are immutable"];
}

@implementation AncPrivateVaultImmutableRotationCoordinatorResult
- (void)setVaultId:(NSString *)value { (void)value; AncRotationCoordinatorRaiseImmutableMutation(); }
- (void)setPreparationCheckpoint:(AncPrivateVaultRotationPreparationCheckpoint *)value { (void)value; AncRotationCoordinatorRaiseImmutableMutation(); }
- (void)setAuthorityCheckpoint:(AncPrivateVaultAuthorityCheckpoint *)value { (void)value; AncRotationCoordinatorRaiseImmutableMutation(); }
- (void)setCustodyGeneration:(uint64_t)value { (void)value; AncRotationCoordinatorRaiseImmutableMutation(); }
- (void)setActiveEpoch:(uint64_t)value { (void)value; AncRotationCoordinatorRaiseImmutableMutation(); }
- (void)setSequence:(uint64_t)value { (void)value; AncRotationCoordinatorRaiseImmutableMutation(); }
- (void)setHeadHash:(NSData *)value { (void)value; AncRotationCoordinatorRaiseImmutableMutation(); }
- (void)setMembershipHash:(NSData *)value { (void)value; AncRotationCoordinatorRaiseImmutableMutation(); }
- (void)setRecoveryGeneration:(uint64_t)value { (void)value; AncRotationCoordinatorRaiseImmutableMutation(); }
- (void)setRecoveryWrapHash:(NSData *)value { (void)value; AncRotationCoordinatorRaiseImmutableMutation(); }
- (void)setValue:(id)value forKey:(NSString *)key { (void)value; (void)key; AncRotationCoordinatorRaiseImmutableMutation(); }
@end

@implementation AncPrivateVaultRotationCoordinatorResult
@end

@interface AncPrivateVaultHostedAppendRequest ()
@property(nonatomic, readwrite) NSString *vaultId;
@property(nonatomic, readwrite) NSString *endpointId;
@property(nonatomic, readwrite) NSData *body;
@property(nonatomic, readwrite) NSString *proofHeader;
@end

@interface AncPrivateVaultImmutableHostedAppendRequest
    : AncPrivateVaultHostedAppendRequest
@end

@implementation AncPrivateVaultImmutableHostedAppendRequest
- (void)setVaultId:(NSString *)value {
  (void)value;
  AncRotationCoordinatorRaiseImmutableMutation();
}
- (void)setEndpointId:(NSString *)value {
  (void)value;
  AncRotationCoordinatorRaiseImmutableMutation();
}
- (void)setBody:(NSData *)value {
  (void)value;
  AncRotationCoordinatorRaiseImmutableMutation();
}
- (void)setProofHeader:(NSString *)value {
  (void)value;
  AncRotationCoordinatorRaiseImmutableMutation();
}
- (void)setValue:(id)value forKey:(NSString *)key {
  (void)value;
  (void)key;
  AncRotationCoordinatorRaiseImmutableMutation();
}
@end

@implementation AncPrivateVaultHostedAppendRequest
@end

@implementation AncPrivateVaultSystemTrustedClock
- (BOOL)readNowMilliseconds:(uint64_t *)milliseconds {
  if (milliseconds == NULL)
    return NO;
  NSTimeInterval interval = NSDate.date.timeIntervalSince1970;
  if (!isfinite(interval) || interval <= 0 ||
      interval > (double)kAncRotationCoordinatorMaximumSafeInteger / 1000.0)
    return NO;
  uint64_t value = (uint64_t)floor(interval * 1000.0);
  if (value == 0 || value > kAncRotationCoordinatorMaximumSafeInteger)
    return NO;
  *milliseconds = value;
  return YES;
}
@end

@interface AncPrivateVaultRotationCoordinator ()
@property(nonatomic) AncPrivateVaultRotationPreparationStore *preparationStore;
@property(nonatomic) AncPrivateVaultAuthorityStore *authorityStore;
@property(nonatomic) AncPrivateVaultCustodyRepository *custodyRepository;
@property(nonatomic) AncPrivateVaultRotationEvidenceStore *evidenceStore;
@property(nonatomic) AncPrivateVaultControlLog *controlLog;
@property(nonatomic) id<AncPrivateVaultTrustedClock> trustedClock;
@end

#if ANC_PRIVATE_VAULT_TESTING
static AncPrivateVaultRotationCoordinatorFaultHook
    gAncPrivateVaultRotationCoordinatorFaultHook;
void AncPrivateVaultRotationCoordinatorSetFaultHookForTesting(
    AncPrivateVaultRotationCoordinatorFaultHook hook) {
  gAncPrivateVaultRotationCoordinatorFaultHook = [hook copy];
}
#endif

static BOOL AncRotationCoordinatorFault(
    AncPrivateVaultRotationCoordinatorFaultPoint point) {
#if ANC_PRIVATE_VAULT_TESTING
  return gAncPrivateVaultRotationCoordinatorFaultHook != nil &&
         gAncPrivateVaultRotationCoordinatorFaultHook(point);
#else
  (void)point;
  return NO;
#endif
}

static NSArray<NSRecursiveLock *> *AncRotationCoordinatorLocks(void) {
  static NSArray<NSRecursiveLock *> *locks;
  static dispatch_once_t once;
  dispatch_once(&once, ^{
    NSMutableArray<NSRecursiveLock *> *values =
        [NSMutableArray arrayWithCapacity:64];
    for (NSUInteger index = 0; index < 64; index++)
      [values addObject:[NSRecursiveLock new]];
    locks = [values copy];
  });
  return locks;
}

static NSRecursiveLock *AncRotationCoordinatorLockForVault(NSString *vaultId) {
  NSData *bytes = [vaultId dataUsingEncoding:NSASCIIStringEncoding];
  const uint8_t *raw = bytes.bytes;
  uint64_t hash = UINT64_C(1469598103934665603);
  for (NSUInteger index = 0; index < bytes.length; index++) {
    hash ^= raw[index];
    hash *= UINT64_C(1099511628211);
  }
  return AncRotationCoordinatorLocks()[hash % 64];
}

static BOOL AncRotationCoordinatorHasExactCollaborators(
    AncPrivateVaultRotationPreparationStore *preparationStore,
    AncPrivateVaultAuthorityStore *authorityStore,
    AncPrivateVaultCustodyRepository *custodyRepository,
    AncPrivateVaultRotationEvidenceStore *evidenceStore,
    AncPrivateVaultControlLog *controlLog) {
  return object_getClass(preparationStore) ==
             AncPrivateVaultRotationPreparationStore.class &&
         object_getClass(authorityStore) == AncPrivateVaultAuthorityStore.class &&
         object_getClass(custodyRepository) ==
             AncPrivateVaultCustodyRepository.class &&
         object_getClass(evidenceStore) ==
             AncPrivateVaultRotationEvidenceStore.class &&
         object_getClass(controlLog) == AncPrivateVaultControlLog.class;
}

static NSString *AncRotationCoordinatorHex(const uint8_t *bytes,
                                            size_t length) {
  if (bytes == NULL || length == 0)
    return nil;
  NSMutableString *value = [NSMutableString stringWithCapacity:length * 2];
  for (size_t index = 0; index < length; index++)
    [value appendFormat:@"%02x", bytes[index]];
  return value;
}

static NSData *AncRotationCoordinatorDataFromHex(NSString *value,
                                                  NSUInteger length) {
  if (![value isKindOfClass:NSString.class] || value.length != length * 2)
    return nil;
  NSMutableData *result = [NSMutableData dataWithLength:length];
  uint8_t *bytes = result.mutableBytes;
  for (NSUInteger index = 0; index < length; index++) {
    unichar high = [value characterAtIndex:index * 2];
    unichar low = [value characterAtIndex:index * 2 + 1];
    int left = high >= '0' && high <= '9' ? high - '0'
               : high >= 'a' && high <= 'f' ? high - 'a' + 10 : -1;
    int right = low >= '0' && low <= '9' ? low - '0'
                : low >= 'a' && low <= 'f' ? low - 'a' + 10 : -1;
    if (left < 0 || right < 0)
      return nil;
    bytes[index] = (uint8_t)((left << 4) | right);
  }
  return result;
}

static BOOL AncRotationCoordinatorBytesEqualData(const uint8_t *bytes,
                                                  NSData *data,
                                                  size_t length) {
  return bytes != NULL && data.length == length &&
         anc_pv_memcmp(bytes, data.bytes, length) == ANC_PV_CRYPTO_OK;
}

static BOOL AncRotationCoordinatorBytesEqual(const uint8_t *left,
                                              const uint8_t *right,
                                              size_t length) {
  return left != NULL && right != NULL &&
         anc_pv_memcmp(left, right, length) == ANC_PV_CRYPTO_OK;
}

static BOOL AncRotationCoordinatorDeriveBytes(
    uint8_t *output, size_t length, const char *label,
    const uint8_t key[ANC_PV_KEY_BYTES], NSData *binding) {
  if (output == NULL || length == 0 || length > ANC_PV_HASH_BYTES ||
      label == NULL || key == NULL || binding == nil)
    return NO;
  NSMutableData *input =
      [NSMutableData dataWithBytes:label length:strlen(label) + 1];
  [input appendBytes:key length:ANC_PV_KEY_BYTES];
  [input appendData:binding];
  uint8_t digest[ANC_PV_HASH_BYTES] = {0};
  BOOL okay = anc_pv_blake2b_256(digest, input.bytes, input.length) ==
      ANC_PV_CRYPTO_OK;
  if (okay)
    memcpy(output, digest, length);
  anc_pv_zeroize(digest, sizeof digest);
  anc_pv_zeroize(input.mutableBytes, input.length);
  return okay;
}

static BOOL AncRotationCoordinatorDeterministicCreatedAt(
    NSString *signedAt, uint64_t trustedNowMilliseconds,
    uint64_t *createdAtSeconds) {
  if (createdAtSeconds == NULL || ![signedAt isKindOfClass:NSString.class])
    return NO;
  NSISO8601DateFormatter *formatter = [NSISO8601DateFormatter new];
  formatter.formatOptions = NSISO8601DateFormatWithInternetDateTime |
                            NSISO8601DateFormatWithFractionalSeconds;
  NSDate *date = [formatter dateFromString:signedAt];
  if (date == nil) {
    formatter.formatOptions = NSISO8601DateFormatWithInternetDateTime;
    date = [formatter dateFromString:signedAt];
  }
  NSTimeInterval interval = date.timeIntervalSince1970;
  if (date == nil || !isfinite(interval) || interval < 1 ||
      interval > (double)kAncRotationCoordinatorMaximumSafeInteger - 1)
    return NO;
  uint64_t seconds = (uint64_t)ceil(interval);
  if (seconds == 0 || seconds > UINT64_MAX / 1000 ||
      seconds * 1000 > trustedNowMilliseconds)
    return NO;
  *createdAtSeconds = seconds;
  return YES;
}

#if ANC_PRIVATE_VAULT_TESTING
BOOL AncPrivateVaultRotationEndpointRemovalTargetMatchesPreparedForTesting(
    const AncPrivateVaultRotationPreparationSnapshot *snapshot,
    NSData *targetEndpointId, NSData *authorityFrameDigest,
    const uint8_t pendingEpochKey[32]) {
  if (snapshot == NULL || snapshot->phase !=
                              ANC_PV_ROTATION_PREPARATION_PHASE_PREPARED ||
      targetEndpointId.length != 16 || authorityFrameDigest.length != 32 ||
      pendingEpochKey == NULL)
    return NO;
  NSMutableData *binding = [NSMutableData dataWithData:authorityFrameDigest];
  [binding appendData:targetEndpointId];
  uint8_t ceremony[16] = {0};
  BOOL derived = AncRotationCoordinatorDeriveBytes(
      ceremony, sizeof ceremony, "endpoint-removal/ceremony", pendingEpochKey,
      binding);
  BOOL matches = derived &&
      anc_pv_memcmp(ceremony, snapshot->ceremony_id, sizeof ceremony) ==
          ANC_PV_CRYPTO_OK;
  anc_pv_zeroize(ceremony, sizeof ceremony);
  return matches;
}
#endif

static BOOL AncRotationCoordinatorCustodyIdentifier(const uint8_t *bytes,
                                                     size_t length,
                                                     NSString *expected) {
  NSData *encoded = [expected dataUsingEncoding:NSUTF8StringEncoding];
  return bytes != NULL && encoded.length == length &&
         anc_pv_memcmp(bytes, encoded.bytes, length) == ANC_PV_CRYPTO_OK;
}

static AncPrivateVaultAuthorityMember *AncRotationCoordinatorMember(
    AncPrivateVaultAuthoritySnapshot *authority, NSString *endpointId) {
  for (AncPrivateVaultAuthorityMember *member in authority.activeMembers)
    if ([member.endpointId isEqualToString:endpointId])
      return member;
  return nil;
}

static BOOL AncRotationCoordinatorPreparationValid(
    const uint8_t *requestedVault,
    const AncPrivateVaultRotationPreparationSnapshot *preparation,
    NSString *vaultHex) {
  if (requestedVault == NULL || preparation == NULL || vaultHex.length != 32 ||
      !AncRotationCoordinatorBytesEqual(
          requestedVault, preparation->vault_id,
          ANC_PV_ROTATION_PREPARATION_ID_BYTES) ||
      (preparation->phase !=
           ANC_PV_ROTATION_PREPARATION_PHASE_AWAITING_CONTROL_COMMIT &&
       preparation->phase != ANC_PV_ROTATION_PREPARATION_PHASE_CONSUMED) ||
      preparation->flags !=
          (ANC_PV_ROTATION_PREPARATION_FLAG_EDGE_BOUND |
           ANC_PV_ROTATION_PREPARATION_FLAG_SPOOL_DURABLE) ||
      preparation->preparation_generation == 0 ||
      preparation->base_custody_generation == 0 ||
      preparation->base_custody_generation == UINT64_MAX ||
      preparation->base_sequence == UINT64_MAX ||
      preparation->base_epoch == UINT64_MAX ||
      preparation->base_recovery_generation == 0 ||
      preparation->pending_epoch != preparation->base_epoch + 1 ||
      preparation->expected_sequence != preparation->base_sequence + 1 ||
      !AncRotationCoordinatorBytesEqual(preparation->expected_previous_head,
                                        preparation->base_head, 32) ||
      preparation->signed_entry_length == 0 ||
      preparation->signed_entry_length >
          ANC_PV_ROTATION_SIGNED_ENTRY_MAX_BYTES ||
      preparation->recovery_wrap_length == 0 ||
      preparation->recovery_wrap_length >
          ANC_PV_ROTATION_RECOVERY_WRAP_MAX_BYTES)
    return NO;
  BOOL endpoint = preparation->role ==
                      ANC_PV_ROTATION_PREPARATION_ROLE_ENDPOINT &&
                  preparation->unattended == 0;
  BOOL broker = preparation->role == ANC_PV_ROTATION_PREPARATION_ROLE_BROKER &&
                preparation->unattended == 1;
  return endpoint || broker;
}

static BOOL AncRotationCoordinatorIdentityValid(
    const AncPrivateVaultRotationPreparationSnapshot *preparation,
    AncPrivateVaultAuthoritySnapshot *authority,
    const AncPrivateVaultCustodySnapshot *custody) {
  NSString *endpointId = AncRotationCoordinatorHex(
      preparation->endpoint_id, ANC_PV_ROTATION_PREPARATION_ID_BYTES);
  NSString *enrollmentRef = AncRotationCoordinatorHex(
      preparation->enrollment_ref, ANC_PV_ROTATION_PREPARATION_ID_BYTES);
  NSString *role =
      preparation->role == ANC_PV_ROTATION_PREPARATION_ROLE_ENDPOINT
          ? @"endpoint"
          : preparation->role == ANC_PV_ROTATION_PREPARATION_ROLE_BROKER
                ? @"broker"
                : nil;
  AncPrivateVaultAuthorityMember *member =
      AncRotationCoordinatorMember(authority, endpointId);
  return endpointId != nil && enrollmentRef != nil && role != nil &&
         member != nil && [member.role isEqualToString:role] &&
         member.unattended == (preparation->unattended != 0) &&
         [member.enrollmentRef isEqualToString:enrollmentRef] &&
         AncRotationCoordinatorBytesEqualData(preparation->signing_public_key,
                                              member.signingPublicKey, 32) &&
         AncRotationCoordinatorBytesEqualData(preparation->agreement_public_key,
                                              member.keyAgreementPublicKey, 32) &&
         AncRotationCoordinatorCustodyIdentifier(
             custody->endpoint_id, custody->endpoint_id_length, endpointId) &&
         custody->role ==
             (preparation->role == ANC_PV_ROTATION_PREPARATION_ROLE_ENDPOINT
                  ? ANC_PV_CUSTODY_ROLE_ENDPOINT
                  : ANC_PV_CUSTODY_ROLE_BROKER) &&
         AncRotationCoordinatorBytesEqual(preparation->signing_public_key,
                                          custody->signing_public_key, 32) &&
         AncRotationCoordinatorBytesEqual(preparation->agreement_public_key,
                                          custody->box_public_key, 32);
}

static BOOL AncRotationCoordinatorBaseTupleValid(
    const AncPrivateVaultRotationPreparationSnapshot *preparation,
    NSString *vaultHex, AncPrivateVaultAuthorityCheckpoint *authority,
    const AncPrivateVaultCustodySnapshot *custody) {
  AncPrivateVaultAuthoritySnapshot *snapshot = authority.snapshot;
  if (authority == nil || snapshot == nil || custody == NULL ||
      ![authority.vaultId isEqualToString:vaultHex] ||
      ![snapshot.vaultId isEqualToString:vaultHex] ||
      authority.custodyGeneration != preparation->base_custody_generation ||
      snapshot.targetCustodyGeneration !=
          preparation->base_custody_generation ||
      !AncRotationCoordinatorBytesEqualData(preparation->base_frame_digest,
                                             authority.frameDigest, 32) ||
      snapshot.sequence != preparation->base_sequence ||
      !AncRotationCoordinatorBytesEqualData(preparation->base_head,
                                             snapshot.headHash, 32) ||
      !AncRotationCoordinatorBytesEqualData(preparation->base_membership,
                                             snapshot.membershipHash, 32) ||
      snapshot.epoch != preparation->base_epoch ||
      snapshot.recoveryGeneration !=
          preparation->base_recovery_generation ||
      custody->record_version != ANC_PV_CUSTODY_VERSION ||
      custody->authority_anchor_present != 1 ||
      custody->custody_generation != preparation->base_custody_generation ||
      !AncRotationCoordinatorCustodyIdentifier(custody->vault_id,
                                               custody->vault_id_length,
                                               vaultHex) ||
      !AncRotationCoordinatorBytesEqualData(custody->snapshot_digest,
                                             authority.frameDigest, 32) ||
      custody->anchored_sequence != snapshot.sequence ||
      !AncRotationCoordinatorBytesEqualData(custody->anchored_head,
                                             snapshot.headHash, 32) ||
      !AncRotationCoordinatorBytesEqualData(custody->membership_digest,
                                             snapshot.membershipHash, 32) ||
      custody->signed_at_ms != snapshot.signedAtMs ||
      custody->freshness_ms != snapshot.verifiedAtMs ||
      custody->active_epoch != preparation->base_epoch ||
      custody->lifecycle != ANC_PV_CUSTODY_LIFECYCLE_ACTIVE ||
      custody->pending_kind != ANC_PV_CUSTODY_PENDING_NONE ||
      custody->rotation_phase != ANC_PV_CUSTODY_ROTATION_NONE ||
      custody->pending_epoch != 0 || custody->expected_edge_present != 0 ||
      custody->expected_next_sequence != 0 ||
      custody->ceremony_id_length != 0 ||
      !AncRotationCoordinatorBytesEqual(
          custody->expected_previous_head, (const uint8_t[32]){0}, 32) ||
      !AncRotationCoordinatorBytesEqual(
          custody->pending_transcript_digest, (const uint8_t[32]){0}, 32))
    return NO;
  return AncRotationCoordinatorIdentityValid(preparation, snapshot, custody);
}

static AncPrivateVaultRotationCoordinatorStatus
AncRotationCoordinatorStatusForPreparation(
    AncPrivateVaultRotationPreparationStoreStatus status) {
  switch (status) {
  case AncPrivateVaultRotationPreparationStoreStatusOK:
    return AncPrivateVaultRotationCoordinatorStatusOK;
  case AncPrivateVaultRotationPreparationStoreStatusNotFound:
    return AncPrivateVaultRotationCoordinatorStatusNotFound;
  case AncPrivateVaultRotationPreparationStoreStatusInvalid:
    return AncPrivateVaultRotationCoordinatorStatusInvalid;
  case AncPrivateVaultRotationPreparationStoreStatusConflict:
    return AncPrivateVaultRotationCoordinatorStatusConflict;
  case AncPrivateVaultRotationPreparationStoreStatusRollbackDetected:
    return AncPrivateVaultRotationCoordinatorStatusRollbackDetected;
  case AncPrivateVaultRotationPreparationStoreStatusCorrupt:
    return AncPrivateVaultRotationCoordinatorStatusCorrupt;
  case AncPrivateVaultRotationPreparationStoreStatusInaccessible:
    return AncPrivateVaultRotationCoordinatorStatusInaccessible;
  case AncPrivateVaultRotationPreparationStoreStatusStorageFailed:
    return AncPrivateVaultRotationCoordinatorStatusStorageFailed;
  }
  return AncPrivateVaultRotationCoordinatorStatusStorageFailed;
}

static AncPrivateVaultRotationCoordinatorStatus
AncRotationCoordinatorStatusForAuthority(AncPrivateVaultAuthorityStoreStatus status) {
  switch (status) {
  case AncPrivateVaultAuthorityStoreStatusOK:
    return AncPrivateVaultRotationCoordinatorStatusOK;
  case AncPrivateVaultAuthorityStoreStatusNotFound:
    return AncPrivateVaultRotationCoordinatorStatusNotFound;
  case AncPrivateVaultAuthorityStoreStatusRemoved:
    return AncPrivateVaultRotationCoordinatorStatusConflict;
  case AncPrivateVaultAuthorityStoreStatusInvalid:
    return AncPrivateVaultRotationCoordinatorStatusInvalid;
  case AncPrivateVaultAuthorityStoreStatusCorrupt:
    return AncPrivateVaultRotationCoordinatorStatusCorrupt;
  case AncPrivateVaultAuthorityStoreStatusRollbackDetected:
    return AncPrivateVaultRotationCoordinatorStatusRollbackDetected;
  case AncPrivateVaultAuthorityStoreStatusConflict:
    return AncPrivateVaultRotationCoordinatorStatusConflict;
  case AncPrivateVaultAuthorityStoreStatusProtectionFailed:
    return AncPrivateVaultRotationCoordinatorStatusProtectionFailed;
  case AncPrivateVaultAuthorityStoreStatusStorageFailed:
    return AncPrivateVaultRotationCoordinatorStatusStorageFailed;
  }
  return AncPrivateVaultRotationCoordinatorStatusAuthorityRejected;
}

static AncPrivateVaultRotationCoordinatorStatus
AncRotationCoordinatorStatusForCustody(
    AncPrivateVaultCustodyRepositoryStatus status) {
  switch (status) {
  case AncPrivateVaultCustodyRepositoryStatusOK:
    return AncPrivateVaultRotationCoordinatorStatusOK;
  case AncPrivateVaultCustodyRepositoryStatusNotFound:
    return AncPrivateVaultRotationCoordinatorStatusNotFound;
  case AncPrivateVaultCustodyRepositoryStatusInvalid:
    return AncPrivateVaultRotationCoordinatorStatusInvalid;
  case AncPrivateVaultCustodyRepositoryStatusConflict:
    return AncPrivateVaultRotationCoordinatorStatusConflict;
  case AncPrivateVaultCustodyRepositoryStatusRollbackDetected:
    return AncPrivateVaultRotationCoordinatorStatusRollbackDetected;
  case AncPrivateVaultCustodyRepositoryStatusCorrupt:
    return AncPrivateVaultRotationCoordinatorStatusCorrupt;
  case AncPrivateVaultCustodyRepositoryStatusInaccessible:
    return AncPrivateVaultRotationCoordinatorStatusInaccessible;
  case AncPrivateVaultCustodyRepositoryStatusFailed:
    return AncPrivateVaultRotationCoordinatorStatusStorageFailed;
  }
  return AncPrivateVaultRotationCoordinatorStatusCustodyRejected;
}

static AncPrivateVaultRotationCoordinatorResult *
AncRotationCoordinatorMakeResult(
    NSString *vaultId,
    AncPrivateVaultRotationPreparationCheckpoint *preparation,
    AncPrivateVaultAuthorityCheckpoint *authority,
    const AncPrivateVaultCustodySnapshot *custody) {
  if (vaultId == nil || preparation == nil || authority == nil ||
      custody == NULL)
    return nil;
  AncPrivateVaultRotationCoordinatorResult *result =
      class_createInstance(AncPrivateVaultRotationCoordinatorResult.class, 0);
  result.vaultId = [vaultId copy];
  result.preparationCheckpoint = preparation;
  result.authorityCheckpoint = authority;
  result.custodyGeneration = custody->custody_generation;
  result.activeEpoch = custody->active_epoch;
  result.sequence = authority.snapshot.sequence;
  result.headHash = [authority.snapshot.headHash copy];
  result.membershipHash = [authority.snapshot.membershipHash copy];
  result.recoveryGeneration = authority.snapshot.recoveryGeneration;
  result.recoveryWrapHash = [authority.snapshot.recoveryWrapHash copy];
  object_setClass(result,
                  AncPrivateVaultImmutableRotationCoordinatorResult.class);
  return result;
}

static AncPrivateVaultHostedAppendRequest *
AncRotationCoordinatorMakeHostedAppendRequest(NSString *vaultId,
                                               NSString *endpointId,
                                               NSData *body,
                                               NSString *proofHeader) {
  if (vaultId.length == 0 || endpointId.length == 0 || body.length == 0 ||
      proofHeader.length == 0)
    return nil;
  AncPrivateVaultHostedAppendRequest *request =
      class_createInstance(AncPrivateVaultHostedAppendRequest.class, 0);
  request.vaultId = [vaultId copy];
  request.endpointId = [endpointId copy];
  request.body = [body copy];
  request.proofHeader = [proofHeader copy];
  object_setClass(request, AncPrivateVaultImmutableHostedAppendRequest.class);
  return request;
}

static NSString *AncRotationCoordinatorTimestamp(uint64_t milliseconds) {
  NSDate *date = [NSDate
      dateWithTimeIntervalSince1970:(NSTimeInterval)milliseconds / 1000.0];
  if (date == nil)
    return nil;
  NSDateFormatter *formatter = [[NSDateFormatter alloc] init];
  formatter.locale = [[NSLocale alloc] initWithLocaleIdentifier:@"en_US_POSIX"];
  formatter.timeZone = [NSTimeZone timeZoneForSecondsFromGMT:0];
  formatter.dateFormat = @"yyyy-MM-dd'T'HH:mm:ss.SSS'Z'";
  NSString *value = [formatter stringFromDate:date];
  return value.length == 24 ? value : nil;
}

@interface AncPrivateVaultEndpointRemovalAssembly : NSObject
@property(nonatomic) AncPrivateVaultRotationPreparationCheckpoint *preparation;
@property(nonatomic) AncPrivateVaultRotationPreparationKeyHandle *keyHandle;
@property(nonatomic) AncPrivateVaultCustodyHandle *custodyHandle;
@property(nonatomic) AncPrivateVaultPreparedEndpointRemoval *prepared;
@property(nonatomic) AncPrivateVaultControlLogState *baseState;
@property(nonatomic) NSData *targetEndpointId;
@property(nonatomic) uint64_t createdAtSeconds;
@property(nonatomic) uint64_t nowSeconds;
@end

@implementation AncPrivateVaultEndpointRemovalAssembly
@end

static AncPrivateVaultRotationCoordinatorStatus
AncRotationCoordinatorStagePreparedCustody(
    AncPrivateVaultCustodyRepository *custodyRepository,
    AncPrivateVaultRotationPreparationCheckpoint *preparation,
    AncPrivateVaultRotationPreparationKeyHandle *keyHandle,
    NSData *targetEndpointId, NSData *successorMembershipDigest,
    uint64_t preparationFenceGeneration,
    NSData *preparationRecordDigest,
    AncPrivateVaultPreparedRotationCustodyCheckpoint **checkpoint) {
  if (checkpoint != NULL)
    *checkpoint = nil;
  if (custodyRepository == nil || preparation == nil || keyHandle == nil ||
      targetEndpointId.length != 16 || preparationFenceGeneration == 0 ||
      successorMembershipDigest.length != ANC_PV_HASH_BYTES ||
      preparationRecordDigest.length != ANC_PV_HASH_BYTES)
    return AncPrivateVaultRotationCoordinatorStatusInvalid;
  AncPrivateVaultRotationPreparationSnapshot snapshot = preparation.snapshot;
  NSString *vaultId = AncRotationCoordinatorHex(
      snapshot.vault_id, ANC_PV_ROTATION_PREPARATION_ID_BYTES);
  NSData *ceremonyId =
      [NSData dataWithBytes:snapshot.ceremony_id
                    length:ANC_PV_ROTATION_PREPARATION_ID_BYTES];
  NSData *baseDigest =
      [NSData dataWithBytes:snapshot.base_frame_digest length:ANC_PV_HASH_BYTES];
  NSData *previousHead =
      [NSData dataWithBytes:snapshot.base_head length:ANC_PV_HASH_BYTES];
  __block AncPrivateVaultPreparedRotationCustodyCheckpoint *staged = nil;
  __block AncPrivateVaultCustodyRepositoryStatus custodyStatus =
      AncPrivateVaultCustodyRepositoryStatusInvalid;
  AncPrivateVaultRotationPreparationStoreStatus borrowStatus =
      [keyHandle borrow:^BOOL(const uint8_t *pendingEpochKey) {
        custodyStatus = [custodyRepository
            stagePreparedRotationVaultId:vaultId
                        targetEndpointId:targetEndpointId
                              ceremonyId:ceremonyId
                      expectedGeneration:snapshot.base_custody_generation
                  expectedSnapshotDigest:baseDigest
                            pendingEpoch:snapshot.pending_epoch
                    expectedNextSequence:snapshot.base_sequence + 1
                    expectedPreviousHead:previousHead
               successorMembershipDigest:successorMembershipDigest
              preparationFenceGeneration:preparationFenceGeneration
                  preparationRecordDigest:preparationRecordDigest
                          pendingEpochKey:pendingEpochKey
                               checkpoint:&staged];
        return custodyStatus == AncPrivateVaultCustodyRepositoryStatusOK &&
               staged != nil;
      }];
  anc_pv_rotation_preparation_snapshot_zero(&snapshot);
  if (borrowStatus != AncPrivateVaultRotationPreparationStoreStatusOK)
    return AncPrivateVaultRotationCoordinatorStatusProtectionFailed;
  if (custodyStatus != AncPrivateVaultCustodyRepositoryStatusOK || staged == nil)
    return AncRotationCoordinatorStatusForCustody(custodyStatus);
  if (checkpoint != NULL)
    *checkpoint = staged;
  return AncPrivateVaultRotationCoordinatorStatusOK;
}

static AncPrivateVaultRotationCoordinatorStatus
AncRotationCoordinatorStatusForEvidenceStore(
    AncPrivateVaultRotationEvidenceStoreStatus status) {
  switch (status) {
  case AncPrivateVaultRotationEvidenceStoreStatusOK:
    return AncPrivateVaultRotationCoordinatorStatusOK;
  case AncPrivateVaultRotationEvidenceStoreStatusNotFound:
    return AncPrivateVaultRotationCoordinatorStatusNotFound;
  case AncPrivateVaultRotationEvidenceStoreStatusInvalid:
    return AncPrivateVaultRotationCoordinatorStatusInvalid;
  case AncPrivateVaultRotationEvidenceStoreStatusConflict:
    return AncPrivateVaultRotationCoordinatorStatusConflict;
  case AncPrivateVaultRotationEvidenceStoreStatusCorrupt:
    return AncPrivateVaultRotationCoordinatorStatusCorrupt;
  case AncPrivateVaultRotationEvidenceStoreStatusStorageFailed:
    return AncPrivateVaultRotationCoordinatorStatusStorageFailed;
  }
  return AncPrivateVaultRotationCoordinatorStatusStorageFailed;
}

static NSData *AncRotationCoordinatorEEKWrapHash(NSData *encodedWrap) {
  static const uint8_t domain[] = "anc/v1/eek-wrap";
  if (![encodedWrap isKindOfClass:NSData.class] || encodedWrap.length == 0)
    return nil;
  uint8_t digest[32] = {0};
  BOOL okay = anc_pv_blake2b_256_two_part(
                  digest, domain, sizeof domain, encodedWrap.bytes,
                  encodedWrap.length) == ANC_PV_CRYPTO_OK;
  NSData *result =
      okay ? [NSData dataWithBytes:digest length:sizeof digest] : nil;
  anc_pv_zeroize(digest, sizeof digest);
  return result;
}

static BOOL AncRotationCoordinatorLedgerMatchesPreparation(
    AncPrivateVaultRotationEvidenceStoreCheckpoint *ledger,
    AncPrivateVaultRotationPreparationCheckpoint *preparation,
    NSData *targetEndpointId) {
  if (ledger == nil || preparation == nil || targetEndpointId.length != 16)
    return NO;
  AncPrivateVaultRotationPreparationSnapshot snapshot = preparation.snapshot;
  uint64_t delta =
      snapshot.phase == ANC_PV_ROTATION_PREPARATION_PHASE_PREPARED ? 0 :
      snapshot.phase == ANC_PV_ROTATION_PREPARATION_PHASE_REWRAPPED ? 1 :
      snapshot.phase == ANC_PV_ROTATION_PREPARATION_PHASE_ACKNOWLEDGED ? 2 :
      snapshot.phase == ANC_PV_ROTATION_PREPARATION_PHASE_AWAITING_CONTROL_COMMIT ? 3 :
      snapshot.phase == ANC_PV_ROTATION_PREPARATION_PHASE_CONSUMED ? 4 : UINT64_MAX;
  return delta != UINT64_MAX &&
      [ledger.vaultId isEqualToData:[NSData dataWithBytes:snapshot.vault_id length:16]] &&
      [ledger.ceremonyId isEqualToData:[NSData dataWithBytes:snapshot.ceremony_id length:16]] &&
      [ledger.targetEndpointId isEqualToData:targetEndpointId] &&
      preparation.fenceGeneration >= delta &&
      ledger.preparationFenceGeneration == preparation.fenceGeneration - delta;
}

static BOOL AncRotationCoordinatorPreparedCustodyMatches(
    AncPrivateVaultPreparedRotationCustodyCheckpoint *preparedCustody,
    const AncPrivateVaultRotationPreparationSnapshot *preparation,
    NSString *vaultId,
    AncPrivateVaultRotationEvidenceStoreCheckpoint *evidenceLedger) {
  if (preparedCustody == nil || preparation == NULL || vaultId.length == 0 ||
      evidenceLedger == nil || preparation->base_custody_generation == UINT64_MAX ||
      preparation->base_sequence == UINT64_MAX)
    return NO;
  NSData *baseDigest =
      [NSData dataWithBytes:preparation->base_frame_digest
                     length:ANC_PV_HASH_BYTES];
  NSData *previousHead =
      [NSData dataWithBytes:preparation->base_head length:ANC_PV_HASH_BYTES];
  NSData *successorMembership =
      [NSData dataWithBytes:preparation->transcript_digest
                     length:ANC_PV_HASH_BYTES];
  return [preparedCustody.vaultId isEqualToString:vaultId] &&
         [preparedCustody.targetEndpointId
             isEqualToData:evidenceLedger.targetEndpointId] &&
         [preparedCustody.ceremonyId
             isEqualToData:evidenceLedger.ceremonyId] &&
         preparedCustody.baseCustodyGeneration ==
             preparation->base_custody_generation &&
         preparedCustody.targetCustodyGeneration ==
             preparation->base_custody_generation + 1 &&
         [preparedCustody.baseSnapshotDigest isEqualToData:baseDigest] &&
         preparedCustody.activeEpoch == preparation->base_epoch &&
         preparedCustody.pendingEpoch == preparation->pending_epoch &&
         preparedCustody.expectedNextSequence ==
             preparation->base_sequence + 1 &&
         [preparedCustody.expectedPreviousHead isEqualToData:previousHead] &&
         [preparedCustody.successorMembershipDigest
             isEqualToData:successorMembership] &&
         preparedCustody.preparationFenceGeneration ==
             evidenceLedger.preparationFenceGeneration &&
         [preparedCustody.preparationRecordDigest
             isEqualToData:evidenceLedger.preparationRecordDigest];
}

static AncPrivateVaultRotationPreparationEvidence *
AncRotationCoordinatorPreparationEvidenceFromLedger(
    AncPrivateVaultRotationEvidenceStoreCheckpoint *ledger,
    const AncPrivateVaultRotationPreparationSnapshot *snapshot, uint64_t now) {
  if (ledger == nil || snapshot == NULL || now == 0)
    return nil;
  NSMutableArray<AncPrivateVaultRotationEvidenceRecipient *> *recipients =
      [NSMutableArray arrayWithCapacity:ledger.recipients.count];
  for (AncPrivateVaultRotationEvidenceStoreRecipient *stored in ledger.recipients) {
    NSData *wrapHash = AncRotationCoordinatorEEKWrapHash(stored.encodedEEKWrap);
    AncPrivateVaultRotationEvidenceRecipient *recipient =
        [[AncPrivateVaultRotationEvidenceRecipient alloc]
            initWithEndpointId:stored.endpointId
               signingPublicKey:stored.signingPublicKey
          keyAgreementPublicKey:stored.keyAgreementPublicKey
                    eekWrapHash:wrapHash
                   encodedOffer:stored.encodedOffer];
    if (recipient == nil)
      return nil;
    [recipients addObject:recipient];
  }
  NSMutableArray<AncPrivateVaultRotationLiveRevision *> *live =
      [NSMutableArray arrayWithCapacity:ledger.liveRevisions.count];
  for (AncPrivateVaultRotationEvidenceStoreLiveRevision *stored in
       ledger.liveRevisions) {
    AncPrivateVaultRotationLiveRevision *revision =
        [[AncPrivateVaultRotationLiveRevision alloc]
            initWithObjectId:stored.objectId
                    revision:stored.revision
             priorRevisionId:stored.priorRevisionId
           rotatedRevisionId:stored.rotatedRevisionId];
    if (revision == nil)
      return nil;
    [live addObject:revision];
  }
  return AncPrivateVaultVerifyRotationPreparationEvidence(
      ledger.encodedCheckpoint, ledger.vaultId,
      [NSData dataWithBytes:snapshot->endpoint_id length:16],
      [NSData dataWithBytes:snapshot->signing_public_key length:32], recipients,
      live, now, NULL);
}

static NSData *AncRotationCoordinatorArtifactEndpoint(NSData *encoded,
                                                       NSNumber *field) {
  if (![encoded isKindOfClass:NSData.class] || encoded.length == 0 ||
      encoded.length > ANC_PV_ROTATION_EVIDENCE_STORE_MAX_ARTIFACT_BYTES)
    return nil;
  AncPrivateVaultCanonicalStatus status;
  AncPrivateVaultCanonicalValue *root = AncPrivateVaultCanonicalDecode(
      encoded, ANC_PV_ROTATION_EVIDENCE_STORE_MAX_ARTIFACT_BYTES, &status);
  AncPrivateVaultCanonicalValue *value = root.mapValue[field];
  return status == AncPrivateVaultCanonicalStatusOK &&
                 root.type == AncPrivateVaultCanonicalTypeMap &&
                 value.type == AncPrivateVaultCanonicalTypeBytes &&
                 value.bytesValue.length == 16
             ? value.bytesValue
             : nil;
}

static NSDictionary<NSData *, NSData *> *AncRotationCoordinatorArtifactMap(
    NSArray<NSData *> *encodedArtifacts, NSNumber *endpointField) {
  if (![encodedArtifacts isKindOfClass:NSArray.class])
    return nil;
  NSMutableDictionary<NSData *, NSData *> *result = [NSMutableDictionary dictionary];
  for (NSData *encoded in encodedArtifacts) {
    NSData *endpoint = AncRotationCoordinatorArtifactEndpoint(encoded, endpointField);
    if (endpoint == nil || result[endpoint] != nil)
      return nil;
    result[endpoint] = encoded;
  }
  return result;
}

static AncPrivateVaultRotationCoordinatorStatus
AncRotationCoordinatorRebuildEndpointRemoval(
    AncPrivateVaultRotationPreparationStore *preparationStore,
    AncPrivateVaultAuthorityStore *authorityStore,
    AncPrivateVaultCustodyRepository *custodyRepository,
    id<AncPrivateVaultTrustedClock> trustedClock, const uint8_t vaultId[16],
    NSData *targetEndpointId,
    AncPrivateVaultEndpointRemovalAssembly **assembly) {
  if (assembly != NULL)
    *assembly = nil;
  if (vaultId == NULL || targetEndpointId.length != 16)
    return AncPrivateVaultRotationCoordinatorStatusInvalid;
  NSString *vaultHex = AncRotationCoordinatorHex(vaultId, 16);
  AncPrivateVaultRotationPreparationCheckpoint *preparation = nil;
  AncPrivateVaultRotationPreparationKeyHandle *keyHandle = nil;
  AncPrivateVaultRotationPreparationStoreStatus preparationStatus =
      [preparationStore readVaultId:vaultId
                         checkpoint:&preparation
                             handle:&keyHandle];
  if (preparationStatus != AncPrivateVaultRotationPreparationStoreStatusOK ||
      preparation == nil || keyHandle == nil)
    return AncRotationCoordinatorStatusForPreparation(preparationStatus);
  AncPrivateVaultRotationPreparationSnapshot snapshot = preparation.snapshot;
  BOOL phase = snapshot.phase == ANC_PV_ROTATION_PREPARATION_PHASE_PREPARED ||
      snapshot.phase == ANC_PV_ROTATION_PREPARATION_PHASE_REWRAPPED ||
      snapshot.phase == ANC_PV_ROTATION_PREPARATION_PHASE_ACKNOWLEDGED ||
      snapshot.phase ==
          ANC_PV_ROTATION_PREPARATION_PHASE_AWAITING_CONTROL_COMMIT;
  if (!phase || snapshot.role != ANC_PV_ROTATION_PREPARATION_ROLE_ENDPOINT ||
      snapshot.unattended != 0 ||
      !AncRotationCoordinatorBytesEqual(vaultId, snapshot.vault_id, 16)) {
    [keyHandle close];
    anc_pv_rotation_preparation_snapshot_zero(&snapshot);
    return AncPrivateVaultRotationCoordinatorStatusConflict;
  }
  AncPrivateVaultAuthorityCheckpoint *authority = nil;
  NSError *authorityError = nil;
  AncPrivateVaultAuthorityStoreStatus authorityStatus =
      [authorityStore loadVaultId:vaultHex
                       checkpoint:&authority
                            error:&authorityError];
  AncPrivateVaultControlLogState *state =
      authority == nil
          ? nil
          : AncPrivateVaultControlLogStateCreateFromAuthenticatedCheckpoint(
                authority);
  uint64_t nowMilliseconds = 0;
  uint64_t createdAtSeconds = 0;
  BOOL base = authorityStatus == AncPrivateVaultAuthorityStoreStatusOK &&
      authorityError == nil && authority != nil && state != nil &&
      authority.custodyGeneration == snapshot.base_custody_generation &&
      [authority.frameDigest
          isEqualToData:[NSData dataWithBytes:snapshot.base_frame_digest
                                       length:32]] &&
      state.sequence == snapshot.base_sequence &&
      [state.headHash
          isEqualToData:[NSData dataWithBytes:snapshot.base_head length:32]] &&
      [state.membershipHash
          isEqualToData:[NSData dataWithBytes:snapshot.base_membership
                                       length:32]] &&
      state.epoch == snapshot.base_epoch &&
      state.recoveryGeneration == snapshot.base_recovery_generation &&
      snapshot.pending_epoch == snapshot.base_epoch + 1 &&
      [trustedClock readNowMilliseconds:&nowMilliseconds] &&
      AncRotationCoordinatorDeterministicCreatedAt(
          state.signedAt, nowMilliseconds, &createdAtSeconds);
  if (!base) {
    [keyHandle close];
    anc_pv_rotation_preparation_snapshot_zero(&snapshot);
    return authorityStatus != AncPrivateVaultAuthorityStoreStatusOK
               ? AncRotationCoordinatorStatusForAuthority(authorityStatus)
               : AncPrivateVaultRotationCoordinatorStatusConflict;
  }
  AncPrivateVaultCustodySnapshot custody;
  AncPrivateVaultCustodyHandle *custodyHandle = nil;
  AncPrivateVaultCustodyRepositoryStatus custodyStatus =
      [custodyRepository readVaultId:vaultHex
                            snapshot:&custody
                              handle:&custodyHandle];
  BOOL custodyValid =
      custodyStatus == AncPrivateVaultCustodyRepositoryStatusOK &&
      custodyHandle != nil && custody.lifecycle == ANC_PV_CUSTODY_LIFECYCLE_ACTIVE &&
      custody.role == ANC_PV_CUSTODY_ROLE_ENDPOINT &&
      custody.custody_generation == snapshot.base_custody_generation &&
      custody.active_epoch == snapshot.base_epoch &&
      AncRotationCoordinatorBytesEqualData(custody.snapshot_digest,
                                            authority.frameDigest, 32) &&
      AncRotationCoordinatorBytesEqualData(custody.anchored_head,
                                            state.headHash, 32) &&
      AncRotationCoordinatorBytesEqualData(custody.membership_digest,
                                            state.membershipHash, 32) &&
      AncRotationCoordinatorIdentityValid(&snapshot, authority.snapshot,
                                           &custody);
  if (!custodyValid) {
    [custodyHandle close];
    [keyHandle close];
    anc_pv_custody_snapshot_zero(&custody);
    anc_pv_rotation_preparation_snapshot_zero(&snapshot);
    return custodyStatus != AncPrivateVaultCustodyRepositoryStatusOK
               ? AncRotationCoordinatorStatusForCustody(custodyStatus)
               : AncPrivateVaultRotationCoordinatorStatusConflict;
  }
  NSMutableData *binding = [NSMutableData dataWithData:authority.frameDigest];
  [binding appendData:targetEndpointId];
  uint8_t ceremony[16] = {0}, wrapEnvelope[16] = {0}, entryEnvelope[16] = {0},
          wrapNonce[24] = {0};
  uint8_t *ceremonyBytes = ceremony;
  uint8_t *wrapEnvelopeBytes = wrapEnvelope;
  uint8_t *entryEnvelopeBytes = entryEnvelope;
  uint8_t *wrapNonceBytes = wrapNonce;
  __block AncPrivateVaultPreparedEndpointRemoval *built = nil;
  __block BOOL derived = NO;
  __block AncPrivateVaultEndpointRemovalBuilderStatus builderStatus =
      AncPrivateVaultEndpointRemovalBuilderStatusInvalidArgument;
  AncPrivateVaultRotationPreparationStoreStatus borrowed =
      [keyHandle borrow:^BOOL(const uint8_t *pendingKey) {
    derived = AncRotationCoordinatorDeriveBytes(
                  ceremonyBytes, sizeof ceremony, "endpoint-removal/ceremony",
                  pendingKey, binding) &&
        AncRotationCoordinatorDeriveBytes(
                  wrapEnvelopeBytes, sizeof wrapEnvelope,
                  "endpoint-removal/wrap-envelope", pendingKey, binding) &&
        AncRotationCoordinatorDeriveBytes(
                  entryEnvelopeBytes, sizeof entryEnvelope,
                  "endpoint-removal/entry-envelope", pendingKey, binding) &&
        AncRotationCoordinatorDeriveBytes(
                  wrapNonceBytes, sizeof wrapNonce, "endpoint-removal/wrap-nonce",
                  pendingKey, binding) &&
        anc_pv_memcmp(ceremonyBytes, snapshot.ceremony_id, sizeof ceremony) ==
            ANC_PV_CRYPTO_OK;
    if (!derived)
      return NO;
    AncPrivateVaultCustodyRepositoryStatus secretStatus =
        [custodyHandle borrow:^BOOL(
                           const AncPrivateVaultCustodySecretInputs *secrets) {
      built = AncPrivateVaultBuildEndpointRemoval(
          state, targetEndpointId,
          [NSData dataWithBytes:ceremonyBytes length:sizeof ceremony],
          [NSData dataWithBytes:wrapEnvelopeBytes length:sizeof wrapEnvelope],
          [NSData dataWithBytes:entryEnvelopeBytes length:sizeof entryEnvelope],
          [NSData dataWithBytes:wrapNonceBytes length:sizeof wrapNonce],
          createdAtSeconds, pendingKey, secrets->signing_seed,
          secrets->box_seed, &builderStatus);
      return built != nil;
    }];
    return secretStatus == AncPrivateVaultCustodyRepositoryStatusOK &&
           built != nil;
  }];
  anc_pv_zeroize(ceremony, sizeof ceremony);
  anc_pv_zeroize(wrapEnvelope, sizeof wrapEnvelope);
  anc_pv_zeroize(entryEnvelope, sizeof entryEnvelope);
  anc_pv_zeroize(wrapNonce, sizeof wrapNonce);
  anc_pv_zeroize(binding.mutableBytes, binding.length);
  anc_pv_custody_snapshot_zero(&custody);
  anc_pv_rotation_preparation_snapshot_zero(&snapshot);
  if (borrowed != AncPrivateVaultRotationPreparationStoreStatusOK ||
      !derived || built == nil) {
    AncPrivateVaultCustodyRepositoryStatus custodyClosed =
        [custodyHandle close];
    [keyHandle close];
    return custodyClosed != AncPrivateVaultCustodyRepositoryStatusOK
               ? AncPrivateVaultRotationCoordinatorStatusProtectionFailed
           : builderStatus ==
                     AncPrivateVaultEndpointRemovalBuilderStatusTargetRejected
               ? AncPrivateVaultRotationCoordinatorStatusControlRejected
               : AncPrivateVaultRotationCoordinatorStatusConflict;
  }
  AncPrivateVaultEndpointRemovalAssembly *result =
      [AncPrivateVaultEndpointRemovalAssembly new];
  result.preparation = preparation;
  result.keyHandle = keyHandle;
  result.custodyHandle = custodyHandle;
  result.prepared = built;
  result.baseState = state;
  result.targetEndpointId = [targetEndpointId copy];
  result.createdAtSeconds = createdAtSeconds;
  result.nowSeconds = nowMilliseconds / 1000;
  if (assembly != NULL)
    *assembly = result;
  return AncPrivateVaultRotationCoordinatorStatusOK;
}

@implementation AncPrivateVaultRotationCoordinator

- (instancetype)
    initWithPreparationStore:
        (AncPrivateVaultRotationPreparationStore *)preparationStore
              authorityStore:(AncPrivateVaultAuthorityStore *)authorityStore
           custodyRepository:
               (AncPrivateVaultCustodyRepository *)custodyRepository
               evidenceStore:
                   (AncPrivateVaultRotationEvidenceStore *)evidenceStore
                  controlLog:(AncPrivateVaultControlLog *)controlLog {
  self = [super init];
  if (self == nil)
    return nil;
  if (!AncRotationCoordinatorHasExactCollaborators(
          preparationStore, authorityStore, custodyRepository, evidenceStore,
          controlLog))
    return nil;
  _preparationStore = preparationStore;
  _authorityStore = authorityStore;
  _custodyRepository = custodyRepository;
  _evidenceStore = evidenceStore;
  _controlLog = controlLog;
  _trustedClock = [AncPrivateVaultSystemTrustedClock new];
  return self;
}

#if ANC_PRIVATE_VAULT_TESTING
- (instancetype)
    initWithPreparationStore:
        (AncPrivateVaultRotationPreparationStore *)preparationStore
              authorityStore:(AncPrivateVaultAuthorityStore *)authorityStore
           custodyRepository:
               (AncPrivateVaultCustodyRepository *)custodyRepository
               evidenceStore:
                   (AncPrivateVaultRotationEvidenceStore *)evidenceStore
                  controlLog:(AncPrivateVaultControlLog *)controlLog
                trustedClock:(id<AncPrivateVaultTrustedClock>)trustedClock {
  if (trustedClock == nil)
    return nil;
  self = [self initWithPreparationStore:preparationStore
                         authorityStore:authorityStore
                      custodyRepository:custodyRepository
                           evidenceStore:evidenceStore
                             controlLog:controlLog];
  if (self == nil)
    return nil;
  _trustedClock = trustedClock;
  return self;
}
#endif

- (AncPrivateVaultRotationCoordinatorStatus)
    startEndpointRemovalVaultId:(const uint8_t[16])vaultId
               targetEndpointId:(NSData *)targetEndpointId
                        prepared:
                            (AncPrivateVaultPreparedEndpointRemoval **)prepared
                      checkpoint:
                          (AncPrivateVaultRotationPreparationCheckpoint **)
                              checkpoint {
  if (prepared != NULL)
    *prepared = nil;
  if (checkpoint != NULL)
    *checkpoint = nil;
  if (vaultId == NULL || ![targetEndpointId isKindOfClass:NSData.class] ||
      targetEndpointId.length != 16)
    return AncPrivateVaultRotationCoordinatorStatusInvalid;
  NSString *vaultHex = AncRotationCoordinatorHex(vaultId, 16);
  if (vaultHex.length != 32)
    return AncPrivateVaultRotationCoordinatorStatusInvalid;
  NSRecursiveLock *operationLock = AncRotationCoordinatorLockForVault(vaultHex);
  [operationLock lock];
  @try {
    NSError *authorityError = nil;
    AncPrivateVaultAuthorityCheckpoint *authority = nil;
    AncPrivateVaultAuthorityStoreStatus authorityStatus =
        [self.authorityStore loadVaultId:vaultHex
                              checkpoint:&authority
                                   error:&authorityError];
    AncPrivateVaultCustodySnapshot custody;
    AncPrivateVaultCustodyHandle *custodyHandle = nil;
    AncPrivateVaultCustodyRepositoryStatus custodyStatus =
        [self.custodyRepository readVaultId:vaultHex
                                   snapshot:&custody
                                     handle:&custodyHandle];
    AncPrivateVaultControlLogState *state =
        authority == nil ? nil
                         : AncPrivateVaultControlLogStateCreateFromAuthenticatedCheckpoint(
                               authority);
    NSString *currentEndpoint =
        custodyStatus == AncPrivateVaultCustodyRepositoryStatusOK
            ? [[NSString alloc]
                  initWithBytes:custody.endpoint_id
                         length:custody.endpoint_id_length
                       encoding:NSUTF8StringEncoding]
            : nil;
    BOOL live = authorityStatus == AncPrivateVaultAuthorityStoreStatusOK &&
        authorityError == nil && authority != nil && state != nil &&
        custodyStatus == AncPrivateVaultCustodyRepositoryStatusOK &&
        custodyHandle != nil && custody.record_version == ANC_PV_CUSTODY_VERSION &&
        custody.authority_anchor_present == 1 &&
        custody.lifecycle == ANC_PV_CUSTODY_LIFECYCLE_ACTIVE &&
        custody.role == ANC_PV_CUSTODY_ROLE_ENDPOINT &&
        custody.rotation_phase == ANC_PV_CUSTODY_ROTATION_NONE &&
        custody.expected_edge_present == 0 &&
        custody.custody_generation == authority.custodyGeneration &&
        custody.anchored_sequence == state.sequence &&
        custody.active_epoch == state.epoch &&
        custody.recovery_generation == state.recoveryGeneration &&
        currentEndpoint.length == 32 &&
        AncRotationCoordinatorBytesEqualData(custody.snapshot_digest,
                                              authority.frameDigest, 32) &&
        AncRotationCoordinatorBytesEqualData(custody.anchored_head,
                                              state.headHash, 32) &&
        AncRotationCoordinatorBytesEqualData(custody.membership_digest,
                                              state.membershipHash, 32);
    if (!live) {
      AncPrivateVaultCustodyRepositoryStatus closed =
          custodyHandle == nil ? AncPrivateVaultCustodyRepositoryStatusOK
                               : [custodyHandle close];
      anc_pv_custody_snapshot_zero(&custody);
      if (closed != AncPrivateVaultCustodyRepositoryStatusOK)
        return AncPrivateVaultRotationCoordinatorStatusProtectionFailed;
      return authorityStatus != AncPrivateVaultAuthorityStoreStatusOK
                 ? AncRotationCoordinatorStatusForAuthority(authorityStatus)
             : custodyStatus != AncPrivateVaultCustodyRepositoryStatusOK
                 ? AncRotationCoordinatorStatusForCustody(custodyStatus)
                 : AncPrivateVaultRotationCoordinatorStatusConflict;
    }

    AncPrivateVaultRotationPreparationCheckpoint *existing = nil;
    AncPrivateVaultRotationPreparationKeyHandle *preparationHandle = nil;
    AncPrivateVaultRotationPreparationStoreStatus preparationStatus =
        [self.preparationStore readVaultId:vaultId
                                checkpoint:&existing
                                    handle:&preparationHandle];
    BOOL first = preparationStatus ==
        AncPrivateVaultRotationPreparationStoreStatusNotFound;
    BOOL restart = preparationStatus ==
                       AncPrivateVaultRotationPreparationStoreStatusOK &&
        existing.snapshot.phase == ANC_PV_ROTATION_PREPARATION_PHASE_PREPARED;
    BOOL next = preparationStatus ==
                    AncPrivateVaultRotationPreparationStoreStatusOK &&
        existing.snapshot.phase == ANC_PV_ROTATION_PREPARATION_PHASE_CLEANED;
    if (!first && !restart && !next) {
      [preparationHandle close];
      [custodyHandle close];
      anc_pv_custody_snapshot_zero(&custody);
      return preparationStatus ==
                     AncPrivateVaultRotationPreparationStoreStatusOK
                 ? AncPrivateVaultRotationCoordinatorStatusConflict
                 : AncRotationCoordinatorStatusForPreparation(
                       preparationStatus);
    }

    uint64_t nowMilliseconds = 0;
    if (![self.trustedClock readNowMilliseconds:&nowMilliseconds] ||
        nowMilliseconds < 1000) {
      [preparationHandle close];
      [custodyHandle close];
      anc_pv_custody_snapshot_zero(&custody);
      return AncPrivateVaultRotationCoordinatorStatusClockFailed;
    }
    uint64_t createdAtSeconds = 0;
    if (!AncRotationCoordinatorDeterministicCreatedAt(
            state.signedAt, nowMilliseconds, &createdAtSeconds)) {
      [preparationHandle close];
      [custodyHandle close];
      anc_pv_custody_snapshot_zero(&custody);
      return AncPrivateVaultRotationCoordinatorStatusClockFailed;
    }
    __block AncPrivateVaultPreparedEndpointRemoval *built = nil;
    __block AncPrivateVaultEndpointRemovalBuilderStatus builderStatus =
        AncPrivateVaultEndpointRemovalBuilderStatusInvalidArgument;
    __block uint8_t pendingKey[32] = {0};
    if (first || next) {
      if (SecRandomCopyBytes(kSecRandomDefault, sizeof pendingKey,
                             pendingKey) != errSecSuccess ||
          anc_pv_memcmp(pendingKey, (uint8_t[32]){0}, 32) ==
              ANC_PV_CRYPTO_OK) {
        [preparationHandle close];
        [custodyHandle close];
        anc_pv_zeroize(pendingKey, sizeof pendingKey);
        anc_pv_custody_snapshot_zero(&custody);
        return AncPrivateVaultRotationCoordinatorStatusProtectionFailed;
      }
    }
    NSData *binding = [NSMutableData dataWithData:authority.frameDigest];
    [(NSMutableData *)binding appendData:targetEndpointId];
    uint8_t ceremony[16] = {0}, wrapEnvelope[16] = {0}, entryEnvelope[16] = {0},
            nonce[24] = {0};
    uint8_t *ceremonyBytes = ceremony;
    uint8_t *wrapEnvelopeBytes = wrapEnvelope;
    uint8_t *entryEnvelopeBytes = entryEnvelope;
    uint8_t *nonceBytes = nonce;
    __block BOOL derived = YES;
    void (^build)(const uint8_t *) = ^(const uint8_t *key) {
      derived = AncRotationCoordinatorDeriveBytes(
                    ceremonyBytes, 16, "endpoint-removal/ceremony",
                    key, binding) &&
          AncRotationCoordinatorDeriveBytes(
                    wrapEnvelopeBytes, 16,
                    "endpoint-removal/wrap-envelope", key, binding) &&
          AncRotationCoordinatorDeriveBytes(
                    entryEnvelopeBytes, 16,
                    "endpoint-removal/entry-envelope", key, binding) &&
          AncRotationCoordinatorDeriveBytes(
                    nonceBytes, 24, "endpoint-removal/wrap-nonce", key,
                    binding);
      if (!derived)
        return;
      if (restart &&
          anc_pv_memcmp(ceremonyBytes, existing.snapshot.ceremony_id, 16) !=
              ANC_PV_CRYPTO_OK) {
        derived = NO;
        return;
      }
      [custodyHandle borrow:^BOOL(
          const AncPrivateVaultCustodySecretInputs *secrets) {
        built = AncPrivateVaultBuildEndpointRemoval(
            state, targetEndpointId,
            [NSData dataWithBytes:ceremonyBytes length:16],
            [NSData dataWithBytes:wrapEnvelopeBytes length:16],
            [NSData dataWithBytes:entryEnvelopeBytes length:16],
            [NSData dataWithBytes:nonceBytes length:24],
            createdAtSeconds, key, secrets->signing_seed,
            secrets->box_seed, &builderStatus);
        return built != nil;
      }];
    };
    if (restart)
      [preparationHandle borrow:^BOOL(const uint8_t *key) {
        build(key);
        return built != nil;
      }];
    else
      build(pendingKey);
    AncPrivateVaultRotationPreparationStoreStatus preparationClosed =
        preparationHandle == nil
            ? AncPrivateVaultRotationPreparationStoreStatusOK
            : [preparationHandle close];
    AncPrivateVaultCustodyRepositoryStatus custodyClosed =
        [custodyHandle close];
    if (built == nil || !derived ||
        preparationClosed != AncPrivateVaultRotationPreparationStoreStatusOK ||
        custodyClosed != AncPrivateVaultCustodyRepositoryStatusOK) {
      anc_pv_zeroize(pendingKey, sizeof pendingKey);
      anc_pv_zeroize(ceremony, sizeof ceremony);
      anc_pv_zeroize(wrapEnvelope, sizeof wrapEnvelope);
      anc_pv_zeroize(entryEnvelope, sizeof entryEnvelope);
      anc_pv_zeroize(nonce, sizeof nonce);
      anc_pv_custody_snapshot_zero(&custody);
      return preparationClosed !=
                     AncPrivateVaultRotationPreparationStoreStatusOK ||
                     custodyClosed !=
                         AncPrivateVaultCustodyRepositoryStatusOK
                 ? AncPrivateVaultRotationCoordinatorStatusProtectionFailed
                 : builderStatus ==
                           AncPrivateVaultEndpointRemovalBuilderStatusTargetRejected
                       ? AncPrivateVaultRotationCoordinatorStatusControlRejected
                       : AncPrivateVaultRotationCoordinatorStatusConflict;
    }
    AncPrivateVaultRotationPreparationCheckpoint *result = existing;
    if (!restart) {
      AncPrivateVaultRotationPreparationSnapshot snapshot = {0};
      snapshot.phase = ANC_PV_ROTATION_PREPARATION_PHASE_PREPARED;
      snapshot.role = ANC_PV_ROTATION_PREPARATION_ROLE_ENDPOINT;
      snapshot.preparation_generation = first
          ? 1 : existing.snapshot.preparation_generation + 1;
      memcpy(snapshot.vault_id, vaultId, 16);
      NSData *currentEndpointData =
          AncRotationCoordinatorDataFromHex(currentEndpoint, 16);
      memcpy(snapshot.endpoint_id, currentEndpointData.bytes, 16);
      memcpy(snapshot.ceremony_id, ceremony, 16);
      snapshot.base_custody_generation = authority.custodyGeneration;
      memcpy(snapshot.base_frame_digest, authority.frameDigest.bytes, 32);
      snapshot.base_sequence = state.sequence;
      memcpy(snapshot.base_head, state.headHash.bytes, 32);
      memcpy(snapshot.base_membership, state.membershipHash.bytes, 32);
      snapshot.base_epoch = state.epoch;
      snapshot.base_recovery_generation = state.recoveryGeneration;
      memcpy(snapshot.signing_public_key, custody.signing_public_key, 32);
      memcpy(snapshot.agreement_public_key, custody.box_public_key, 32);
      AncPrivateVaultAuthorityMember *currentMember =
          AncRotationCoordinatorMember(authority.snapshot, currentEndpoint);
      NSData *enrollment = currentMember == nil
          ? nil
          : AncRotationCoordinatorDataFromHex(currentMember.enrollmentRef, 16);
      if (enrollment.length == 16)
        memcpy(snapshot.enrollment_ref, enrollment.bytes, 16);
      snapshot.pending_epoch = state.epoch + 1;
      preparationStatus = enrollment.length != 16
          ? AncPrivateVaultRotationPreparationStoreStatusInvalid
          : [self.preparationStore createPrepared:&snapshot
                                  pendingEpochKey:pendingKey
                               expectedCheckpoint:next ? existing : nil
                                       checkpoint:&result];
      anc_pv_rotation_preparation_snapshot_zero(&snapshot);
    }
    anc_pv_zeroize(pendingKey, sizeof pendingKey);
    anc_pv_zeroize(ceremony, sizeof ceremony);
    anc_pv_zeroize(wrapEnvelope, sizeof wrapEnvelope);
    anc_pv_zeroize(entryEnvelope, sizeof entryEnvelope);
    anc_pv_zeroize(nonce, sizeof nonce);
    anc_pv_custody_snapshot_zero(&custody);
    if (preparationStatus !=
            AncPrivateVaultRotationPreparationStoreStatusOK ||
        result == nil)
      return AncRotationCoordinatorStatusForPreparation(preparationStatus);
    if (prepared != NULL)
      *prepared = built;
    if (checkpoint != NULL)
      *checkpoint = result;
    return AncPrivateVaultRotationCoordinatorStatusOK;
  } @finally {
    [operationLock unlock];
  }
}

- (AncPrivateVaultRotationCoordinatorStatus)
    verifyEndpointRemovalRewrapVaultId:(const uint8_t[16])vaultId
                      targetEndpointId:(NSData *)targetEndpointId
                       manifestObjectId:(NSData *)manifestObjectId
                              revisionId:(NSData *)revisionId
                               generation:(uint64_t)generation
                           ciphertextHash:(NSData *)ciphertextHash
                            liveRevisions:
                                (NSArray<AncPrivateVaultRotationLiveRevision *> *)
                                    liveRevisions
                               checkpoint:
                                   (AncPrivateVaultRotationEvidenceStoreCheckpoint **)
                                       checkpoint {
  if (checkpoint != NULL)
    *checkpoint = nil;
  if (vaultId == NULL || targetEndpointId.length != 16 ||
      manifestObjectId.length != 16 || revisionId.length != 32 ||
      generation == 0 || generation > kAncRotationCoordinatorMaximumSafeInteger ||
      ciphertextHash.length != 32 ||
      ![liveRevisions isKindOfClass:NSArray.class] ||
      liveRevisions.count > ANC_PV_ROTATION_EVIDENCE_STORE_MAX_LIVE_REVISIONS)
    return AncPrivateVaultRotationCoordinatorStatusInvalid;
  NSString *vaultHex = AncRotationCoordinatorHex(vaultId, 16);
  NSRecursiveLock *operationLock = AncRotationCoordinatorLockForVault(vaultHex);
  [operationLock lock];
  @try {
    AncPrivateVaultEndpointRemovalAssembly *assembly = nil;
    AncPrivateVaultRotationCoordinatorStatus rebuilt =
        AncRotationCoordinatorRebuildEndpointRemoval(
            self.preparationStore, self.authorityStore,
            self.custodyRepository, self.trustedClock, vaultId,
            targetEndpointId, &assembly);
    if (rebuilt != AncPrivateVaultRotationCoordinatorStatusOK ||
        assembly == nil)
      return rebuilt;
    @try {
      NSData *vaultData = [NSData dataWithBytes:vaultId length:16];
      NSData *ceremonyId = [NSData
          dataWithBytes:assembly.preparation.snapshot.ceremony_id
                 length:16];
      NSData *issuerEndpointId = [NSData
          dataWithBytes:assembly.preparation.snapshot.endpoint_id
                 length:16];
      NSData *issuerSigningPublicKey = [NSData
          dataWithBytes:assembly.preparation.snapshot.signing_public_key
                 length:32];
      NSMutableArray<AncPrivateVaultRotationEvidenceStoreLiveRevision *>
          *storedLive = [NSMutableArray arrayWithCapacity:liveRevisions.count];
      for (id value in liveRevisions) {
        if (![value isKindOfClass:AncPrivateVaultRotationLiveRevision.class])
          return AncPrivateVaultRotationCoordinatorStatusInvalid;
        AncPrivateVaultRotationLiveRevision *revision = value;
        AncPrivateVaultRotationEvidenceStoreLiveRevision *stored =
            [[AncPrivateVaultRotationEvidenceStoreLiveRevision alloc]
                initWithObjectId:revision.objectId
                         revision:revision.revision
                  priorRevisionId:revision.priorRevisionId
                rotatedRevisionId:revision.rotatedRevisionId];
        if (stored == nil)
          return AncPrivateVaultRotationCoordinatorStatusInvalid;
        [storedLive addObject:stored];
      }
      NSMutableDictionary<NSData *, AncPrivateVaultEekWrap *> *wraps =
          [NSMutableDictionary dictionary];
      for (AncPrivateVaultEekWrap *wrap in assembly.prepared.eekWraps) {
        if (wraps[wrap.recipientEndpointId] != nil)
          return AncPrivateVaultRotationCoordinatorStatusConflict;
        wraps[wrap.recipientEndpointId] = wrap;
      }
      NSMutableArray<AncPrivateVaultRotationEvidenceRecipient *> *hashRoster =
          [NSMutableArray array];
      NSMutableArray<NSData *> *eekHashes = [NSMutableArray array];
      for (AncPrivateVaultControlLogMember *member in
           assembly.prepared.nextState.activeMembers) {
        NSData *endpoint =
            AncRotationCoordinatorDataFromHex(member.endpointId, 16);
        AncPrivateVaultEekWrap *wrap = wraps[endpoint];
        NSData *eekHash =
            AncRotationCoordinatorEEKWrapHash(wrap.encodedEnvelope);
        AncPrivateVaultRotationEvidenceRecipient *recipient =
            [[AncPrivateVaultRotationEvidenceRecipient alloc]
                initWithEndpointId:endpoint
                   signingPublicKey:member.signingPublicKey
              keyAgreementPublicKey:member.keyAgreementPublicKey
                        eekWrapHash:eekHash
                       encodedOffer:[NSData dataWithBytes:"x" length:1]];
        if (endpoint.length != 16 || wrap == nil || eekHash.length != 32 ||
            recipient == nil)
          return AncPrivateVaultRotationCoordinatorStatusConflict;
        [hashRoster addObject:recipient];
        [eekHashes addObject:eekHash];
      }
      if (hashRoster.count == 0 || hashRoster.count != wraps.count)
        return AncPrivateVaultRotationCoordinatorStatusConflict;
      NSData *liveHash =
          AncPrivateVaultRotationEvidenceHashLiveRevisionSet(liveRevisions);
      NSData *recipientHash =
          AncPrivateVaultRotationEvidenceHashRecipientSet(hashRoster);
      if (liveHash.length != 32 || recipientHash.length != 32)
        return AncPrivateVaultRotationCoordinatorStatusConflict;
      if (assembly.createdAtSeconds >
          kAncRotationCoordinatorMaximumSafeInteger - 300)
        return AncPrivateVaultRotationCoordinatorStatusClockFailed;
      NSMutableData *binding = [NSMutableData dataWithData:ceremonyId];
      [binding appendData:targetEndpointId];
      [binding appendData:manifestObjectId];
      [binding appendData:revisionId];
      uint8_t generationBytes[8] = {0};
      for (NSUInteger index = 0; index < sizeof generationBytes; index += 1)
        generationBytes[index] =
            (uint8_t)(generation >> ((sizeof generationBytes - index - 1) * 8));
      [binding appendBytes:generationBytes length:sizeof generationBytes];
      [binding appendData:ciphertextHash];
      __block NSData *encodedCheckpoint = nil;
      __block NSMutableArray<AncPrivateVaultRotationEvidenceRecipient *>
          *verifiedRecipients = nil;
      __block NSMutableArray<AncPrivateVaultRotationEvidenceStoreRecipient *>
          *storedRecipients = nil;
      __block BOOL built = NO;
      AncPrivateVaultRotationPreparationStoreStatus keyStatus =
          [assembly.keyHandle borrow:^BOOL(const uint8_t *pendingKey) {
        uint8_t checkpointEnvelope[16] = {0};
        uint8_t *checkpointEnvelopeBytes = checkpointEnvelope;
        if (!AncRotationCoordinatorDeriveBytes(
                checkpointEnvelopeBytes, sizeof checkpointEnvelope,
                "endpoint-removal/evidence-checkpoint-envelope", pendingKey,
                binding))
          return NO;
        AncPrivateVaultCustodyRepositoryStatus signingStatus =
            [assembly.custodyHandle borrow:^BOOL(
                const AncPrivateVaultCustodySecretInputs *secrets) {
          AncPrivateVaultRotationEvidenceStatus evidenceStatus;
          encodedCheckpoint = AncPrivateVaultRotationEvidenceBuildCheckpoint(
              vaultData, assembly.createdAtSeconds,
              [NSData dataWithBytes:checkpointEnvelopeBytes
                             length:sizeof checkpointEnvelope],
              ceremonyId, assembly.baseState.sequence,
              assembly.baseState.headHash, assembly.baseState.epoch,
              assembly.prepared.nextState.epoch, manifestObjectId, revisionId,
              generation, ciphertextHash,
              [[NSSet setWithArray:[liveRevisions valueForKey:@"objectId"]]
                  count],
              liveRevisions.count, liveHash, recipientHash,
              assembly.prepared.nextState.headHash, issuerEndpointId,
              targetEndpointId, secrets->signing_seed, &evidenceStatus);
          NSData *checkpointHash =
              AncPrivateVaultRotationEvidenceHashCheckpoint(encodedCheckpoint,
                                                             vaultData);
          if (encodedCheckpoint == nil || checkpointHash.length != 32 ||
              evidenceStatus != AncPrivateVaultRotationEvidenceStatusOK)
            return NO;
          verifiedRecipients = [NSMutableArray arrayWithCapacity:hashRoster.count];
          storedRecipients = [NSMutableArray arrayWithCapacity:hashRoster.count];
          for (NSUInteger index = 0; index < hashRoster.count; index += 1) {
            AncPrivateVaultRotationEvidenceRecipient *base = hashRoster[index];
            AncPrivateVaultEekWrap *wrap = wraps[base.endpointId];
            NSMutableData *offerBinding = [binding mutableCopy];
            [offerBinding appendData:base.endpointId];
            uint8_t offerEnvelope[16] = {0};
            BOOL derived = AncRotationCoordinatorDeriveBytes(
                offerEnvelope, sizeof offerEnvelope,
                "endpoint-removal/evidence-offer-envelope", pendingKey,
                offerBinding);
            anc_pv_zeroize(offerBinding.mutableBytes, offerBinding.length);
            NSData *offer = derived
                ? AncPrivateVaultRotationEvidenceBuildOffer(
                      vaultData, assembly.createdAtSeconds,
                      [NSData dataWithBytes:offerEnvelope
                                     length:sizeof offerEnvelope],
                      ceremonyId, checkpointHash, eekHashes[index],
                      base.endpointId, issuerEndpointId,
                      assembly.prepared.nextState.epoch,
                      assembly.createdAtSeconds + 300, secrets->signing_seed,
                      &evidenceStatus)
                : nil;
            anc_pv_zeroize(offerEnvelope, sizeof offerEnvelope);
            AncPrivateVaultRotationEvidenceRecipient *verified =
                [[AncPrivateVaultRotationEvidenceRecipient alloc]
                    initWithEndpointId:base.endpointId
                       signingPublicKey:base.signingPublicKey
                  keyAgreementPublicKey:base.keyAgreementPublicKey
                            eekWrapHash:eekHashes[index]
                           encodedOffer:offer];
            AncPrivateVaultRotationEvidenceStoreRecipient *stored =
                [[AncPrivateVaultRotationEvidenceStoreRecipient alloc]
                    initWithEndpointId:base.endpointId
                       signingPublicKey:base.signingPublicKey
                  keyAgreementPublicKey:base.keyAgreementPublicKey
                           encodedOffer:offer
                         encodedEEKWrap:wrap.encodedEnvelope];
            if (verified == nil || stored == nil ||
                evidenceStatus != AncPrivateVaultRotationEvidenceStatusOK)
              return NO;
            [verifiedRecipients addObject:verified];
            [storedRecipients addObject:stored];
          }
          built = YES;
          return YES;
        }];
        anc_pv_zeroize(checkpointEnvelope, sizeof checkpointEnvelope);
        return signingStatus == AncPrivateVaultCustodyRepositoryStatusOK &&
               built;
      }];
      anc_pv_zeroize(binding.mutableBytes, binding.length);
      anc_pv_zeroize(generationBytes, sizeof generationBytes);
      if (keyStatus != AncPrivateVaultRotationPreparationStoreStatusOK ||
          !built)
        return AncPrivateVaultRotationCoordinatorStatusProtectionFailed;
      AncPrivateVaultRotationPreparationEvidence *verifiedPreparation =
          AncPrivateVaultVerifyRotationPreparationEvidence(
              encodedCheckpoint, vaultData, issuerEndpointId,
              issuerSigningPublicKey, verifiedRecipients, liveRevisions,
              assembly.nowSeconds, NULL);
      if (verifiedPreparation == nil)
        return assembly.nowSeconds > assembly.createdAtSeconds + 360
                   ? AncPrivateVaultRotationCoordinatorStatusConflict
                   : AncPrivateVaultRotationCoordinatorStatusControlRejected;

      AncPrivateVaultRotationEvidenceStoreCheckpoint *existing = nil;
      AncPrivateVaultRotationEvidenceStoreStatus evidenceStatus =
          [self.evidenceStore readVaultId:vaultData checkpoint:&existing];
      if (evidenceStatus != AncPrivateVaultRotationEvidenceStoreStatusOK &&
          evidenceStatus != AncPrivateVaultRotationEvidenceStoreStatusNotFound)
        return AncRotationCoordinatorStatusForEvidenceStore(evidenceStatus);
      if (existing != nil &&
          !AncRotationCoordinatorLedgerMatchesPreparation(
              existing, assembly.preparation, targetEndpointId))
        return AncPrivateVaultRotationCoordinatorStatusConflict;
      uint64_t fence = existing == nil
          ? assembly.preparation.fenceGeneration
          : existing.preparationFenceGeneration;
      NSData *recordDigest = existing == nil
          ? assembly.preparation.recordDigest
          : existing.preparationRecordDigest;
      AncPrivateVaultRotationEvidenceStoreCheckpoint *ledger = nil;
      evidenceStatus = [self.evidenceStore
          createVaultId:vaultData
             ceremonyId:ceremonyId
        targetEndpointId:targetEndpointId
        preparationFenceGeneration:fence
        preparationRecordDigest:recordDigest
        encodedCheckpoint:encodedCheckpoint
               recipients:storedRecipients
            liveRevisions:storedLive
               checkpoint:&ledger];
      if (evidenceStatus != AncPrivateVaultRotationEvidenceStoreStatusOK ||
          ledger == nil)
        return AncRotationCoordinatorStatusForEvidenceStore(evidenceStatus);
      if (AncRotationCoordinatorFault(
              AncPrivateVaultRotationCoordinatorFaultAfterEvidenceLedger))
        return AncPrivateVaultRotationCoordinatorStatusStorageFailed;
      AncPrivateVaultRotationPreparationPhase phase =
          assembly.preparation.snapshot.phase;
      if (phase == ANC_PV_ROTATION_PREPARATION_PHASE_PREPARED) {
        AncPrivateVaultRotationPreparationCheckpoint *rewrapped = nil;
        AncPrivateVaultRotationPreparationStoreStatus transition =
            [self.preparationStore
                markVerifiedRewrappedVaultId:vaultId
                          expectedCheckpoint:assembly.preparation
                          evidenceCheckpoint:ledger
                                   checkpoint:&rewrapped];
        if (transition != AncPrivateVaultRotationPreparationStoreStatusOK ||
            rewrapped == nil)
          return AncRotationCoordinatorStatusForPreparation(transition);
      } else if (phase != ANC_PV_ROTATION_PREPARATION_PHASE_REWRAPPED &&
                 phase != ANC_PV_ROTATION_PREPARATION_PHASE_ACKNOWLEDGED &&
                 phase != ANC_PV_ROTATION_PREPARATION_PHASE_AWAITING_CONTROL_COMMIT) {
        return AncPrivateVaultRotationCoordinatorStatusConflict;
      }
      if (AncRotationCoordinatorFault(
              AncPrivateVaultRotationCoordinatorFaultAfterEvidencePhase))
        return AncPrivateVaultRotationCoordinatorStatusStorageFailed;
      if (checkpoint != NULL)
        *checkpoint = ledger;
      return AncPrivateVaultRotationCoordinatorStatusOK;
    } @finally {
      [assembly.keyHandle close];
      [assembly.custodyHandle close];
    }
  } @finally {
    [operationLock unlock];
  }
}

- (AncPrivateVaultRotationCoordinatorStatus)
    verifyEndpointRemovalAcknowledgementsVaultId:(const uint8_t[16])vaultId
                              targetEndpointId:(NSData *)targetEndpointId
                              acknowledgements:(NSArray<NSData *> *)acknowledgements
                                  checkpoint:(AncPrivateVaultRotationEvidenceStoreCheckpoint **)checkpoint {
  if (checkpoint != NULL)
    *checkpoint = nil;
  if (vaultId == NULL || targetEndpointId.length != 16 ||
      ![acknowledgements isKindOfClass:NSArray.class])
    return AncPrivateVaultRotationCoordinatorStatusInvalid;
  NSString *vaultHex = AncRotationCoordinatorHex(vaultId, 16);
  NSRecursiveLock *operationLock = AncRotationCoordinatorLockForVault(vaultHex);
  [operationLock lock];
  @try {
    AncPrivateVaultEndpointRemovalAssembly *assembly = nil;
    AncPrivateVaultRotationCoordinatorStatus rebuilt =
        AncRotationCoordinatorRebuildEndpointRemoval(
            self.preparationStore, self.authorityStore, self.custodyRepository,
            self.trustedClock, vaultId, targetEndpointId, &assembly);
    if (rebuilt != AncPrivateVaultRotationCoordinatorStatusOK || assembly == nil)
      return rebuilt;
    @try {
      NSData *vaultData = [NSData dataWithBytes:vaultId length:16];
      AncPrivateVaultRotationEvidenceStoreCheckpoint *ledger = nil;
      AncPrivateVaultRotationEvidenceStoreStatus storeStatus =
          [self.evidenceStore readVaultId:vaultData checkpoint:&ledger];
      if (storeStatus != AncPrivateVaultRotationEvidenceStoreStatusOK ||
          ledger == nil ||
          !AncRotationCoordinatorLedgerMatchesPreparation(
              ledger, assembly.preparation, targetEndpointId) ||
          (ledger.phase != AncPrivateVaultRotationEvidenceStorePhaseAcknowledgements &&
           ledger.phase != AncPrivateVaultRotationEvidenceStorePhaseDestructions))
        return storeStatus == AncPrivateVaultRotationEvidenceStoreStatusOK
                   ? AncPrivateVaultRotationCoordinatorStatusConflict
                   : AncRotationCoordinatorStatusForEvidenceStore(storeStatus);
      AncPrivateVaultRotationPreparationSnapshot snapshot =
          assembly.preparation.snapshot;
      AncPrivateVaultRotationPreparationEvidence *preparationEvidence =
          AncRotationCoordinatorPreparationEvidenceFromLedger(
              ledger, &snapshot, assembly.createdAtSeconds);
      __block AncPrivateVaultRotationAcknowledgementEvidence *verified = nil;
      NSMutableData *nonceBinding = [NSMutableData dataWithData:ledger.ceremonyId];
      [nonceBinding appendData:targetEndpointId];
      NSMutableData *spoolNonce = [NSMutableData dataWithLength:24];
      AncPrivateVaultRotationPreparationStoreStatus borrowed =
          [assembly.keyHandle borrow:^BOOL(const uint8_t *pendingKey) {
        verified = AncPrivateVaultVerifyRotationAcknowledgementEvidence(
            preparationEvidence, acknowledgements, pendingKey,
            assembly.nowSeconds, NULL);
        return verified != nil && AncRotationCoordinatorDeriveBytes(
            spoolNonce.mutableBytes, spoolNonce.length,
            "endpoint-removal/control-spool-nonce", pendingKey, nonceBinding);
      }];
      anc_pv_zeroize(nonceBinding.mutableBytes, nonceBinding.length);
      NSDictionary<NSData *, NSData *> *byEndpoint =
          AncRotationCoordinatorArtifactMap(acknowledgements, @43);
      if (preparationEvidence == nil || verified == nil || byEndpoint == nil ||
          borrowed != AncPrivateVaultRotationPreparationStoreStatusOK)
        return borrowed != AncPrivateVaultRotationPreparationStoreStatusOK
                   ? AncPrivateVaultRotationCoordinatorStatusProtectionFailed
                   : AncPrivateVaultRotationCoordinatorStatusControlRejected;
      if (ledger.phase == AncPrivateVaultRotationEvidenceStorePhaseDestructions) {
        if (![ledger.acknowledgements isEqualToDictionary:byEndpoint])
          return AncPrivateVaultRotationCoordinatorStatusConflict;
      } else {
        for (AncPrivateVaultRotationEvidenceStoreRecipient *recipient in ledger.recipients) {
          AncPrivateVaultRotationEvidenceStoreCheckpoint *next = nil;
          storeStatus = [self.evidenceStore
              storeAcknowledgement:byEndpoint[recipient.endpointId]
                         endpointId:recipient.endpointId
                            vaultId:vaultData
                  expectedCheckpoint:ledger
                          checkpoint:&next];
          if (storeStatus != AncPrivateVaultRotationEvidenceStoreStatusOK || next == nil)
            return AncRotationCoordinatorStatusForEvidenceStore(storeStatus);
          ledger = next;
        }
      }
      if (ledger.phase != AncPrivateVaultRotationEvidenceStorePhaseDestructions)
        return AncPrivateVaultRotationCoordinatorStatusConflict;
      AncPrivateVaultCustodyRepositoryStatus custodyClosed =
          [assembly.custodyHandle close];
      assembly.custodyHandle = nil;
      if (custodyClosed != AncPrivateVaultCustodyRepositoryStatusOK)
        return AncRotationCoordinatorStatusForCustody(custodyClosed);
      AncPrivateVaultPreparedRotationCustodyCheckpoint *stagedCustody = nil;
      AncPrivateVaultRotationCoordinatorStatus stagedStatus =
          AncRotationCoordinatorStagePreparedCustody(
              self.custodyRepository, assembly.preparation,
              assembly.keyHandle, targetEndpointId,
              assembly.prepared.transcriptDigest,
              ledger.preparationFenceGeneration,
              ledger.preparationRecordDigest, &stagedCustody);
      if (stagedStatus != AncPrivateVaultRotationCoordinatorStatusOK ||
          stagedCustody == nil)
        return stagedStatus;
      if (AncRotationCoordinatorFault(AncPrivateVaultRotationCoordinatorFaultAfterEvidenceLedger))
        return AncPrivateVaultRotationCoordinatorStatusStorageFailed;
      AncPrivateVaultRotationPreparationCheckpoint *acknowledged = assembly.preparation;
      if (snapshot.phase == ANC_PV_ROTATION_PREPARATION_PHASE_REWRAPPED) {
        AncPrivateVaultRotationPreparationStoreStatus transition =
            [self.preparationStore markVerifiedAcknowledgedVaultId:vaultId
                                                expectedCheckpoint:assembly.preparation
                                                evidenceCheckpoint:ledger
                                                         checkpoint:&acknowledged];
        if (transition != AncPrivateVaultRotationPreparationStoreStatusOK || acknowledged == nil)
          return AncRotationCoordinatorStatusForPreparation(transition);
      } else if (snapshot.phase != ANC_PV_ROTATION_PREPARATION_PHASE_ACKNOWLEDGED &&
                 snapshot.phase != ANC_PV_ROTATION_PREPARATION_PHASE_AWAITING_CONTROL_COMMIT) {
        return AncPrivateVaultRotationCoordinatorStatusConflict;
      }
      if (AncRotationCoordinatorFault(AncPrivateVaultRotationCoordinatorFaultAfterEvidencePhase))
        return AncPrivateVaultRotationCoordinatorStatusStorageFailed;
      if (acknowledged.snapshot.phase == ANC_PV_ROTATION_PREPARATION_PHASE_ACKNOWLEDGED) {
        uint8_t nonce[24] = {0};
        if (spoolNonce.length != sizeof nonce) {
          anc_pv_zeroize(nonce, sizeof nonce);
          return AncPrivateVaultRotationCoordinatorStatusProtectionFailed;
        }
        memcpy(nonce, spoolNonce.bytes, sizeof nonce);
        AncPrivateVaultRotationPreparationCheckpoint *awaiting = nil;
        AncPrivateVaultRotationPreparationStoreStatus armed =
            [self.preparationStore armAwaitingControlCommitVaultId:vaultId
                                                expectedCheckpoint:acknowledged
                                                  expectedSequence:assembly.baseState.sequence + 1
                                              expectedPreviousHead:assembly.baseState.headHash.bytes
                                                  transcriptDigest:assembly.prepared.transcriptDigest.bytes
                                                       signedEntry:assembly.prepared.signedEntry.bytes
                                                 signedEntryLength:assembly.prepared.signedEntry.length
                                                      recoveryWrap:assembly.prepared.recoveryWrap.bytes
                                                recoveryWrapLength:assembly.prepared.recoveryWrap.length
                                                             nonce:nonce
                                                        checkpoint:&awaiting];
        anc_pv_zeroize(nonce, sizeof nonce);
        if (armed != AncPrivateVaultRotationPreparationStoreStatusOK || awaiting == nil)
          return AncRotationCoordinatorStatusForPreparation(armed);
      }
      if (checkpoint != NULL)
        *checkpoint = ledger;
      return AncPrivateVaultRotationCoordinatorStatusOK;
    } @finally {
      [assembly.keyHandle close];
      [assembly.custodyHandle close];
    }
  } @finally {
    [operationLock unlock];
  }
}

- (AncPrivateVaultRotationCoordinatorStatus)
    verifyEndpointRemovalDestructionsVaultId:(const uint8_t[16])vaultId
                         targetEndpointId:(NSData *)targetEndpointId
                              destructions:(NSArray<NSData *> *)destructions
                                checkpoint:(AncPrivateVaultRotationEvidenceStoreCheckpoint **)checkpoint {
  if (checkpoint != NULL)
    *checkpoint = nil;
  if (vaultId == NULL || targetEndpointId.length != 16 ||
      ![destructions isKindOfClass:NSArray.class])
    return AncPrivateVaultRotationCoordinatorStatusInvalid;
  NSString *vaultHex = AncRotationCoordinatorHex(vaultId, 16);
  NSRecursiveLock *operationLock = AncRotationCoordinatorLockForVault(vaultHex);
  [operationLock lock];
  @try {
    AncPrivateVaultRotationPreparationCheckpoint *preparation = nil;
    AncPrivateVaultRotationPreparationKeyHandle *keyHandle = nil;
    AncPrivateVaultRotationPreparationStoreStatus preparationStatus =
        [self.preparationStore readVaultId:vaultId checkpoint:&preparation handle:&keyHandle];
    if (keyHandle != nil)
      [keyHandle close];
    if (preparationStatus != AncPrivateVaultRotationPreparationStoreStatusOK || preparation == nil)
      return AncRotationCoordinatorStatusForPreparation(preparationStatus);
    AncPrivateVaultRotationPreparationSnapshot snapshot = preparation.snapshot;
    NSData *vaultData = [NSData dataWithBytes:vaultId length:16];
    AncPrivateVaultRotationEvidenceStoreCheckpoint *ledger = nil;
    AncPrivateVaultRotationEvidenceStoreStatus storeStatus =
        [self.evidenceStore readVaultId:vaultData checkpoint:&ledger];
    if (storeStatus != AncPrivateVaultRotationEvidenceStoreStatusOK || ledger == nil ||
        !AncRotationCoordinatorLedgerMatchesPreparation(ledger, preparation, targetEndpointId) ||
        (ledger.phase != AncPrivateVaultRotationEvidenceStorePhaseDestructions &&
         ledger.phase != AncPrivateVaultRotationEvidenceStorePhaseComplete))
      return storeStatus == AncPrivateVaultRotationEvidenceStoreStatusOK
                 ? AncPrivateVaultRotationCoordinatorStatusConflict
                 : AncRotationCoordinatorStatusForEvidenceStore(storeStatus);
    AncPrivateVaultAuthorityCheckpoint *authority = nil;
    AncPrivateVaultAuthorityStoreStatus authorityStatus =
        [self.authorityStore loadVaultId:vaultHex checkpoint:&authority error:nil];
    AncPrivateVaultCustodySnapshot custody;
    AncPrivateVaultCustodyHandle *custodyHandle = nil;
    AncPrivateVaultCustodyRepositoryStatus custodyStatus =
        [self.custodyRepository readVaultId:vaultHex snapshot:&custody handle:&custodyHandle];
    BOOL official = authorityStatus == AncPrivateVaultAuthorityStoreStatusOK &&
        custodyStatus == AncPrivateVaultCustodyRepositoryStatusOK && custodyHandle != nil &&
        AncPrivateVaultRotationPreparationOfficialTupleValid(&snapshot, vaultHex, authority, &custody);
    AncPrivateVaultCustodyRepositoryStatus custodyClosed =
        custodyHandle == nil ? AncPrivateVaultCustodyRepositoryStatusInvalid : [custodyHandle close];
    anc_pv_custody_snapshot_zero(&custody);
    if (!official || custodyClosed != AncPrivateVaultCustodyRepositoryStatusOK)
      return custodyClosed != AncPrivateVaultCustodyRepositoryStatusOK
                 ? AncPrivateVaultRotationCoordinatorStatusProtectionFailed
                 : AncPrivateVaultRotationCoordinatorStatusConflict;
    uint64_t nowMilliseconds = 0;
    if (![self.trustedClock readNowMilliseconds:&nowMilliseconds] || nowMilliseconds == 0)
      return AncPrivateVaultRotationCoordinatorStatusClockFailed;
    /* The owner-only immutable ledger proves offers were fresh at creation.
     * Reconstruct at their signed creation time; do not expire a durable proof
     * while separately checking destruction timestamps against current time. */
    /* Decode the checkpoint's signed createdAt for exact replay. */
    AncPrivateVaultCanonicalStatus canonicalStatus;
    AncPrivateVaultCanonicalValue *checkpointRoot = AncPrivateVaultCanonicalDecode(
        ledger.encodedCheckpoint, ANC_PV_ROTATION_EVIDENCE_STORE_MAX_ARTIFACT_BYTES,
        &canonicalStatus);
    int64_t signedCreatedAt = checkpointRoot.mapValue[@4].integerValue;
    if (canonicalStatus != AncPrivateVaultCanonicalStatusOK || signedCreatedAt <= 0)
      return AncPrivateVaultRotationCoordinatorStatusCorrupt;
    AncPrivateVaultRotationPreparationEvidence *preparationEvidence =
        AncRotationCoordinatorPreparationEvidenceFromLedger(
        ledger, &snapshot, (uint64_t)signedCreatedAt);
    AncPrivateVaultRotationDestructionEvidence *verified =
        AncPrivateVaultVerifyRotationDestructionEvidence(
            preparationEvidence, destructions, nowMilliseconds / 1000, NULL);
    NSDictionary<NSData *, NSData *> *byEndpoint =
        AncRotationCoordinatorArtifactMap(destructions, @53);
    if (preparationEvidence == nil || verified == nil || byEndpoint == nil)
      return AncPrivateVaultRotationCoordinatorStatusControlRejected;
    if (ledger.phase == AncPrivateVaultRotationEvidenceStorePhaseComplete) {
      if (![ledger.destructions isEqualToDictionary:byEndpoint])
        return AncPrivateVaultRotationCoordinatorStatusConflict;
    } else {
      for (AncPrivateVaultRotationEvidenceStoreRecipient *recipient in ledger.recipients) {
        AncPrivateVaultRotationEvidenceStoreCheckpoint *next = nil;
        storeStatus = [self.evidenceStore storeDestruction:byEndpoint[recipient.endpointId]
                                               endpointId:recipient.endpointId
                                                  vaultId:vaultData
                                        expectedCheckpoint:ledger
                                                checkpoint:&next];
        if (storeStatus != AncPrivateVaultRotationEvidenceStoreStatusOK || next == nil)
          return AncRotationCoordinatorStatusForEvidenceStore(storeStatus);
        ledger = next;
      }
    }
    if (ledger.phase != AncPrivateVaultRotationEvidenceStorePhaseComplete)
      return AncPrivateVaultRotationCoordinatorStatusConflict;
    if (checkpoint != NULL)
      *checkpoint = ledger;
    return AncPrivateVaultRotationCoordinatorStatusOK;
  } @finally {
    [operationLock unlock];
  }
}

- (AncPrivateVaultRotationCoordinatorStatus)
    startBrokerReplacementVaultId:(const uint8_t[16])vaultId
               oldBrokerEndpointId:(NSData *)oldBrokerEndpointId
         candidateBrokerEndpointId:(NSData *)candidateBrokerEndpointId
         candidateSigningPublicKey:(NSData *)candidateSigningPublicKey
    candidateKeyAgreementPublicKey:(NSData *)candidateKeyAgreementPublicKey
           candidateEnrollmentRef:(NSData *)candidateEnrollmentRef
                  drainAttestation:(NSData *)drainAttestation
                          prepared:
                              (AncPrivateVaultPreparedBrokerReplacement **)prepared
                        checkpoint:
                            (AncPrivateVaultRotationPreparationCheckpoint **)
                                checkpoint {
  if (prepared != NULL)
    *prepared = nil;
  if (checkpoint != NULL)
    *checkpoint = nil;
  if (vaultId == NULL || oldBrokerEndpointId.length != 16 ||
      candidateBrokerEndpointId.length != 16 ||
      candidateSigningPublicKey.length != 32 ||
      candidateKeyAgreementPublicKey.length != 32 ||
      candidateEnrollmentRef.length != 16 || drainAttestation.length == 0 ||
      drainAttestation.length > 1024)
    return AncPrivateVaultRotationCoordinatorStatusInvalid;
  NSString *vaultHex = AncRotationCoordinatorHex(vaultId, 16);
  if (vaultHex.length != 32)
    return AncPrivateVaultRotationCoordinatorStatusInvalid;
  NSRecursiveLock *operationLock = AncRotationCoordinatorLockForVault(vaultHex);
  [operationLock lock];
  @try {
    NSError *authorityError = nil;
    AncPrivateVaultAuthorityCheckpoint *authority = nil;
    AncPrivateVaultAuthorityStoreStatus authorityStatus =
        [self.authorityStore loadVaultId:vaultHex
                              checkpoint:&authority
                                   error:&authorityError];
    AncPrivateVaultCustodySnapshot custody;
    AncPrivateVaultCustodyHandle *custodyHandle = nil;
    AncPrivateVaultCustodyRepositoryStatus custodyStatus =
        [self.custodyRepository readVaultId:vaultHex
                                   snapshot:&custody
                                     handle:&custodyHandle];
    AncPrivateVaultControlLogState *state =
        authority == nil ? nil
                         : AncPrivateVaultControlLogStateCreateFromAuthenticatedCheckpoint(
                               authority);
    NSString *currentEndpoint =
        custodyStatus == AncPrivateVaultCustodyRepositoryStatusOK
            ? [[NSString alloc]
                  initWithBytes:custody.endpoint_id
                         length:custody.endpoint_id_length
                       encoding:NSUTF8StringEncoding]
            : nil;
    BOOL live = authorityStatus == AncPrivateVaultAuthorityStoreStatusOK &&
        authorityError == nil && authority != nil && state != nil &&
        custodyStatus == AncPrivateVaultCustodyRepositoryStatusOK &&
        custodyHandle != nil && custody.record_version == ANC_PV_CUSTODY_VERSION &&
        custody.authority_anchor_present == 1 &&
        custody.lifecycle == ANC_PV_CUSTODY_LIFECYCLE_ACTIVE &&
        custody.role == ANC_PV_CUSTODY_ROLE_ENDPOINT &&
        custody.rotation_phase == ANC_PV_CUSTODY_ROTATION_NONE &&
        custody.expected_edge_present == 0 &&
        custody.custody_generation == authority.custodyGeneration &&
        custody.anchored_sequence == state.sequence &&
        custody.active_epoch == state.epoch &&
        custody.recovery_generation == state.recoveryGeneration &&
        currentEndpoint.length == 32 &&
        AncRotationCoordinatorBytesEqualData(custody.snapshot_digest,
                                              authority.frameDigest, 32) &&
        AncRotationCoordinatorBytesEqualData(custody.anchored_head,
                                              state.headHash, 32) &&
        AncRotationCoordinatorBytesEqualData(custody.membership_digest,
                                              state.membershipHash, 32);
    if (!live) {
      AncPrivateVaultCustodyRepositoryStatus closed =
          custodyHandle == nil ? AncPrivateVaultCustodyRepositoryStatusOK
                               : [custodyHandle close];
      anc_pv_custody_snapshot_zero(&custody);
      if (closed != AncPrivateVaultCustodyRepositoryStatusOK)
        return AncPrivateVaultRotationCoordinatorStatusProtectionFailed;
      return authorityStatus != AncPrivateVaultAuthorityStoreStatusOK
                 ? AncRotationCoordinatorStatusForAuthority(authorityStatus)
             : custodyStatus != AncPrivateVaultCustodyRepositoryStatusOK
                 ? AncRotationCoordinatorStatusForCustody(custodyStatus)
                 : AncPrivateVaultRotationCoordinatorStatusConflict;
    }

    AncPrivateVaultRotationPreparationCheckpoint *existing = nil;
    AncPrivateVaultRotationPreparationKeyHandle *preparationHandle = nil;
    AncPrivateVaultRotationPreparationStoreStatus preparationStatus =
        [self.preparationStore readVaultId:vaultId
                                checkpoint:&existing
                                    handle:&preparationHandle];
    BOOL first = preparationStatus ==
        AncPrivateVaultRotationPreparationStoreStatusNotFound;
    BOOL restart = preparationStatus ==
                       AncPrivateVaultRotationPreparationStoreStatusOK &&
        existing.snapshot.phase == ANC_PV_ROTATION_PREPARATION_PHASE_PREPARED;
    BOOL next = preparationStatus ==
                    AncPrivateVaultRotationPreparationStoreStatusOK &&
        existing.snapshot.phase == ANC_PV_ROTATION_PREPARATION_PHASE_CLEANED;
    if (!first && !restart && !next) {
      [preparationHandle close];
      [custodyHandle close];
      anc_pv_custody_snapshot_zero(&custody);
      return preparationStatus ==
                     AncPrivateVaultRotationPreparationStoreStatusOK
                 ? AncPrivateVaultRotationCoordinatorStatusConflict
                 : AncRotationCoordinatorStatusForPreparation(preparationStatus);
    }

    uint64_t nowMilliseconds = 0;
    if (![self.trustedClock readNowMilliseconds:&nowMilliseconds] ||
        nowMilliseconds < 1000) {
      [preparationHandle close];
      [custodyHandle close];
      anc_pv_custody_snapshot_zero(&custody);
      return AncPrivateVaultRotationCoordinatorStatusClockFailed;
    }
    uint64_t trustedNowSeconds = nowMilliseconds / 1000;
    if (trustedNowSeconds == 0 ||
        trustedNowSeconds > kAncRotationCoordinatorMaximumSafeInteger) {
      [preparationHandle close];
      [custodyHandle close];
      anc_pv_custody_snapshot_zero(&custody);
      return AncPrivateVaultRotationCoordinatorStatusClockFailed;
    }
    NSData *ceremony =
        AncPrivateVaultBrokerReplacementCeremonyId(drainAttestation);
    if (ceremony.length != 16 ||
        (restart &&
         !AncRotationCoordinatorBytesEqualData(existing.snapshot.ceremony_id,
                                                ceremony, 16))) {
      [preparationHandle close];
      [custodyHandle close];
      anc_pv_custody_snapshot_zero(&custody);
      return AncPrivateVaultRotationCoordinatorStatusConflict;
    }
    __block AncPrivateVaultPreparedBrokerReplacement *built = nil;
    __block AncPrivateVaultBrokerReplacementBuilderStatus builderStatus =
        AncPrivateVaultBrokerReplacementBuilderStatusInvalidArgument;
    __block uint8_t pendingKey[32] = {0};
    if (first || next) {
      if (SecRandomCopyBytes(kSecRandomDefault, sizeof pendingKey, pendingKey) !=
              errSecSuccess ||
          anc_pv_memcmp(pendingKey, (uint8_t[32]){0}, 32) ==
              ANC_PV_CRYPTO_OK) {
        [preparationHandle close];
        [custodyHandle close];
        anc_pv_zeroize(pendingKey, sizeof pendingKey);
        anc_pv_custody_snapshot_zero(&custody);
        return AncPrivateVaultRotationCoordinatorStatusProtectionFailed;
      }
    }
    NSMutableData *binding = [NSMutableData dataWithData:authority.frameDigest];
    [binding appendData:oldBrokerEndpointId];
    [binding appendData:candidateBrokerEndpointId];
    [binding appendData:drainAttestation];
    uint8_t wrapEnvelope[16] = {0}, entryEnvelope[16] = {0}, nonce[24] = {0};
    uint8_t *wrapEnvelopeBytes = wrapEnvelope;
    uint8_t *entryEnvelopeBytes = entryEnvelope;
    uint8_t *nonceBytes = nonce;
    __block BOOL derived = YES;
    void (^build)(const uint8_t *) = ^(const uint8_t *key) {
      derived = AncRotationCoordinatorDeriveBytes(
                    wrapEnvelopeBytes, 16,
                    "broker-replacement/wrap-envelope", key, binding) &&
          AncRotationCoordinatorDeriveBytes(
                    entryEnvelopeBytes, 16,
                    "broker-replacement/entry-envelope", key, binding) &&
          AncRotationCoordinatorDeriveBytes(
                    nonceBytes, 24, "broker-replacement/wrap-nonce", key,
                    binding);
      if (!derived)
        return;
      [custodyHandle borrow:^BOOL(
          const AncPrivateVaultCustodySecretInputs *secrets) {
        built = AncPrivateVaultBuildBrokerReplacement(
            state, oldBrokerEndpointId, candidateBrokerEndpointId,
            candidateSigningPublicKey, candidateKeyAgreementPublicKey,
            candidateEnrollmentRef, drainAttestation,
            [NSData dataWithBytes:wrapEnvelopeBytes length:16],
            [NSData dataWithBytes:entryEnvelopeBytes length:16],
            [NSData dataWithBytes:nonceBytes length:24], trustedNowSeconds, key,
            secrets->signing_seed, secrets->box_seed, &builderStatus);
        return built != nil;
      }];
    };
    if (restart)
      [preparationHandle borrow:^BOOL(const uint8_t *key) {
        build(key);
        return built != nil;
      }];
    else
      build(pendingKey);
    AncPrivateVaultRotationPreparationStoreStatus preparationClosed =
        preparationHandle == nil
            ? AncPrivateVaultRotationPreparationStoreStatusOK
            : [preparationHandle close];
    AncPrivateVaultCustodyRepositoryStatus custodyClosed = [custodyHandle close];
    if (built == nil || !derived ||
        preparationClosed != AncPrivateVaultRotationPreparationStoreStatusOK ||
        custodyClosed != AncPrivateVaultCustodyRepositoryStatusOK) {
      anc_pv_zeroize(pendingKey, sizeof pendingKey);
      anc_pv_zeroize(wrapEnvelope, sizeof wrapEnvelope);
      anc_pv_zeroize(entryEnvelope, sizeof entryEnvelope);
      anc_pv_zeroize(nonce, sizeof nonce);
      anc_pv_custody_snapshot_zero(&custody);
      return preparationClosed !=
                     AncPrivateVaultRotationPreparationStoreStatusOK ||
                     custodyClosed != AncPrivateVaultCustodyRepositoryStatusOK
                 ? AncPrivateVaultRotationCoordinatorStatusProtectionFailed
             : builderStatus ==
                       AncPrivateVaultBrokerReplacementBuilderStatusDrainRejected ||
                       builderStatus ==
                           AncPrivateVaultBrokerReplacementBuilderStatusBrokerRejected ||
                       builderStatus ==
                           AncPrivateVaultBrokerReplacementBuilderStatusIssuerRejected
                 ? AncPrivateVaultRotationCoordinatorStatusControlRejected
                 : AncPrivateVaultRotationCoordinatorStatusConflict;
    }
    AncPrivateVaultRotationPreparationCheckpoint *result = existing;
    if (!restart) {
      AncPrivateVaultRotationPreparationSnapshot snapshot = {0};
      snapshot.phase = ANC_PV_ROTATION_PREPARATION_PHASE_PREPARED;
      snapshot.role = ANC_PV_ROTATION_PREPARATION_ROLE_ENDPOINT;
      snapshot.preparation_generation =
          first ? 1 : existing.snapshot.preparation_generation + 1;
      memcpy(snapshot.vault_id, vaultId, 16);
      NSData *currentEndpointData =
          AncRotationCoordinatorDataFromHex(currentEndpoint, 16);
      memcpy(snapshot.endpoint_id, currentEndpointData.bytes, 16);
      memcpy(snapshot.ceremony_id, ceremony.bytes, 16);
      snapshot.base_custody_generation = authority.custodyGeneration;
      memcpy(snapshot.base_frame_digest, authority.frameDigest.bytes, 32);
      snapshot.base_sequence = state.sequence;
      memcpy(snapshot.base_head, state.headHash.bytes, 32);
      memcpy(snapshot.base_membership, state.membershipHash.bytes, 32);
      snapshot.base_epoch = state.epoch;
      snapshot.base_recovery_generation = state.recoveryGeneration;
      memcpy(snapshot.signing_public_key, custody.signing_public_key, 32);
      memcpy(snapshot.agreement_public_key, custody.box_public_key, 32);
      AncPrivateVaultAuthorityMember *currentMember =
          AncRotationCoordinatorMember(authority.snapshot, currentEndpoint);
      NSData *enrollment = currentMember == nil
          ? nil
          : AncRotationCoordinatorDataFromHex(currentMember.enrollmentRef, 16);
      if (enrollment.length == 16)
        memcpy(snapshot.enrollment_ref, enrollment.bytes, 16);
      snapshot.pending_epoch = state.epoch + 1;
      preparationStatus = enrollment.length != 16
          ? AncPrivateVaultRotationPreparationStoreStatusInvalid
          : [self.preparationStore createPrepared:&snapshot
                                  pendingEpochKey:pendingKey
                               expectedCheckpoint:next ? existing : nil
                                       checkpoint:&result];
      anc_pv_rotation_preparation_snapshot_zero(&snapshot);
    }
    anc_pv_zeroize(pendingKey, sizeof pendingKey);
    anc_pv_zeroize(wrapEnvelope, sizeof wrapEnvelope);
    anc_pv_zeroize(entryEnvelope, sizeof entryEnvelope);
    anc_pv_zeroize(nonce, sizeof nonce);
    anc_pv_custody_snapshot_zero(&custody);
    if (preparationStatus != AncPrivateVaultRotationPreparationStoreStatusOK ||
        result == nil)
      return AncRotationCoordinatorStatusForPreparation(preparationStatus);
    if (prepared != NULL)
      *prepared = built;
    if (checkpoint != NULL)
      *checkpoint = result;
    return AncPrivateVaultRotationCoordinatorStatusOK;
  } @finally {
    [operationLock unlock];
  }
}

- (AncPrivateVaultRotationCoordinatorStatus)
    resumeVaultId:(const uint8_t[16])vaultId
            result:(AncPrivateVaultRotationCoordinatorResult **)result {
  if (result != NULL)
    *result = nil;
  if (vaultId == NULL)
    return AncPrivateVaultRotationCoordinatorStatusInvalid;
  NSString *vaultHex = AncRotationCoordinatorHex(
      vaultId, ANC_PV_ROTATION_PREPARATION_ID_BYTES);
  if (vaultHex.length != 32 ||
      ![vaultHex isEqualToString:vaultHex.lowercaseString])
    return AncPrivateVaultRotationCoordinatorStatusInvalid;
  NSRecursiveLock *operationLock =
      AncRotationCoordinatorLockForVault(vaultHex);
  [operationLock lock];
  @try {
    AncPrivateVaultRotationPreparationCheckpoint *preparationCheckpoint = nil;
    AncPrivateVaultRotationPreparationKeyHandle *preparationHandle = nil;
    AncPrivateVaultRotationPreparationStoreStatus preparationStatus =
        [self.preparationStore readVaultId:vaultId
                                checkpoint:&preparationCheckpoint
                                    handle:&preparationHandle];
    if (preparationStatus !=
            AncPrivateVaultRotationPreparationStoreStatusOK ||
        preparationCheckpoint == nil) {
      if (preparationHandle != nil)
        [preparationHandle close];
      return preparationStatus ==
                     AncPrivateVaultRotationPreparationStoreStatusOK
                 ? AncPrivateVaultRotationCoordinatorStatusProtectionFailed
                 : AncRotationCoordinatorStatusForPreparation(
                       preparationStatus);
    }
    AncPrivateVaultRotationPreparationSnapshot preparation =
        preparationCheckpoint.snapshot;
    if (!AncRotationCoordinatorPreparationValid(vaultId, &preparation,
                                                vaultHex)) {
      AncPrivateVaultRotationPreparationStoreStatus closed =
          preparationHandle == nil
              ? AncPrivateVaultRotationPreparationStoreStatusOK
              : [preparationHandle close];
      anc_pv_rotation_preparation_snapshot_zero(&preparation);
      return closed == AncPrivateVaultRotationPreparationStoreStatusOK
                 ? AncPrivateVaultRotationCoordinatorStatusInvalid
                 : AncPrivateVaultRotationCoordinatorStatusProtectionFailed;
    }

    if (preparation.phase == ANC_PV_ROTATION_PREPARATION_PHASE_CONSUMED) {
      AncPrivateVaultRotationPreparationStoreStatus closed =
          [preparationHandle close];
      if (closed != AncPrivateVaultRotationPreparationStoreStatusOK) {
        anc_pv_rotation_preparation_snapshot_zero(&preparation);
        return AncPrivateVaultRotationCoordinatorStatusProtectionFailed;
      }
      AncPrivateVaultRotationPreparationCheckpoint *consumed = nil;
      preparationStatus = [self.preparationStore
          consumeCommittedVaultId:vaultId
                   authorityStore:self.authorityStore
                custodyRepository:self.custodyRepository
                       checkpoint:&consumed];
      if (preparationStatus !=
          AncPrivateVaultRotationPreparationStoreStatusOK) {
        anc_pv_rotation_preparation_snapshot_zero(&preparation);
        return AncRotationCoordinatorStatusForPreparation(preparationStatus);
      }
      NSData *vaultData = [NSData
          dataWithBytes:vaultId
                 length:ANC_PV_ROTATION_PREPARATION_ID_BYTES];
      AncPrivateVaultRotationEvidenceStoreCheckpoint *evidenceLedger = nil;
      AncPrivateVaultRotationEvidenceStoreStatus evidenceStatus =
          [self.evidenceStore readVaultId:vaultData
                               checkpoint:&evidenceLedger];
      if (evidenceStatus != AncPrivateVaultRotationEvidenceStoreStatusOK ||
          evidenceLedger == nil ||
          (evidenceLedger.phase !=
               AncPrivateVaultRotationEvidenceStorePhaseDestructions &&
           evidenceLedger.phase !=
               AncPrivateVaultRotationEvidenceStorePhaseComplete) ||
          !AncRotationCoordinatorLedgerMatchesPreparation(
              evidenceLedger, consumed, evidenceLedger.targetEndpointId)) {
        anc_pv_rotation_preparation_snapshot_zero(&preparation);
        return evidenceStatus !=
                       AncPrivateVaultRotationEvidenceStoreStatusOK
                   ? AncRotationCoordinatorStatusForEvidenceStore(evidenceStatus)
                   : AncPrivateVaultRotationCoordinatorStatusConflict;
      }
      AncPrivateVaultAuthorityCheckpoint *official = nil;
      AncPrivateVaultAuthorityStoreStatus authorityStatus =
          [self.authorityStore loadVaultId:vaultHex
                                checkpoint:&official
                                     error:nil];
      AncPrivateVaultCustodySnapshot custody;
      AncPrivateVaultCustodyHandle *custodyHandle = nil;
      AncPrivateVaultCustodyRepositoryStatus custodyStatus =
          [self.custodyRepository readVaultId:vaultHex
                                     snapshot:&custody
                                       handle:&custodyHandle];
      BOOL valid = authorityStatus == AncPrivateVaultAuthorityStoreStatusOK &&
                   custodyStatus == AncPrivateVaultCustodyRepositoryStatusOK &&
                   custodyHandle != nil &&
                   AncPrivateVaultRotationPreparationOfficialTupleValid(
                       &preparation, vaultHex, official, &custody);
      AncPrivateVaultCustodyRepositoryStatus custodyClosed =
          custodyHandle == nil ? AncPrivateVaultCustodyRepositoryStatusInvalid
                               : [custodyHandle close];
      AncPrivateVaultPreparedRotationCustodyCheckpoint *preparedCustody = nil;
      AncPrivateVaultCustodyRepositoryStatus preparedCustodyStatus =
          [self.custodyRepository readPreparedRotationVaultId:vaultHex
                                                    checkpoint:&preparedCustody];
      BOOL exactPreparedCustody =
          preparedCustodyStatus == AncPrivateVaultCustodyRepositoryStatusOK &&
          AncRotationCoordinatorPreparedCustodyMatches(
              preparedCustody, &preparation, vaultHex, evidenceLedger);
      BOOL preparedCustodyAbsent =
          preparedCustodyStatus ==
          AncPrivateVaultCustodyRepositoryStatusNotFound;
      AncPrivateVaultCustodyRepositoryStatus cleanupStatus =
          AncPrivateVaultCustodyRepositoryStatusOK;
      if (valid && custodyClosed == AncPrivateVaultCustodyRepositoryStatusOK &&
          exactPreparedCustody) {
        NSData *baseSnapshotDigest = [NSData
            dataWithBytes:preparation.base_frame_digest
                   length:ANC_PV_HASH_BYTES];
        cleanupStatus = [self.custodyRepository
            adoptPreparedRotationAuthorityAnchorVaultId:vaultHex
                                      expectedGeneration:
                                          preparation.base_custody_generation
                                  expectedSnapshotDigest:baseSnapshotDigest
                              preparedRotationCheckpoint:preparedCustody
                                       nextPublicSnapshot:&custody];
      }
      AncPrivateVaultRotationCoordinatorResult *done =
          valid && custodyClosed == AncPrivateVaultCustodyRepositoryStatusOK &&
                  (exactPreparedCustody || preparedCustodyAbsent) &&
                  cleanupStatus == AncPrivateVaultCustodyRepositoryStatusOK
              ? AncRotationCoordinatorMakeResult(vaultHex, consumed, official,
                                                 &custody)
              : nil;
      anc_pv_custody_snapshot_zero(&custody);
      anc_pv_rotation_preparation_snapshot_zero(&preparation);
      if (!valid)
        return AncPrivateVaultRotationCoordinatorStatusConflict;
      if (custodyClosed != AncPrivateVaultCustodyRepositoryStatusOK ||
          done == nil)
        return custodyClosed != AncPrivateVaultCustodyRepositoryStatusOK
                   ? AncPrivateVaultRotationCoordinatorStatusProtectionFailed
               : cleanupStatus != AncPrivateVaultCustodyRepositoryStatusOK
                   ? AncRotationCoordinatorStatusForCustody(cleanupStatus)
               : !exactPreparedCustody && !preparedCustodyAbsent
                   ? preparedCustodyStatus !=
                             AncPrivateVaultCustodyRepositoryStatusOK
                         ? AncRotationCoordinatorStatusForCustody(
                               preparedCustodyStatus)
                         : AncPrivateVaultRotationCoordinatorStatusConflict
                   : AncPrivateVaultRotationCoordinatorStatusProtectionFailed;
      if (result != NULL)
        *result = done;
      return AncPrivateVaultRotationCoordinatorStatusOK;
    }

    if (preparationHandle == nil) {
      anc_pv_rotation_preparation_snapshot_zero(&preparation);
      return AncPrivateVaultRotationCoordinatorStatusProtectionFailed;
    }

    uint64_t nowMilliseconds = 0;
    if (![self.trustedClock readNowMilliseconds:&nowMilliseconds] ||
        nowMilliseconds == 0 ||
        nowMilliseconds > kAncRotationCoordinatorMaximumSafeInteger) {
      AncPrivateVaultRotationPreparationStoreStatus closed =
          [preparationHandle close];
      anc_pv_rotation_preparation_snapshot_zero(&preparation);
      return closed == AncPrivateVaultRotationPreparationStoreStatusOK
                 ? AncPrivateVaultRotationCoordinatorStatusClockFailed
                 : AncPrivateVaultRotationCoordinatorStatusProtectionFailed;
    }

    AncPrivateVaultAuthorityCheckpoint *currentAuthority = nil;
    NSError *authorityError = nil;
    AncPrivateVaultAuthorityStoreStatus authorityStatus =
        [self.authorityStore loadVaultId:vaultHex
                              checkpoint:&currentAuthority
                                   error:&authorityError];
    if (authorityStatus != AncPrivateVaultAuthorityStoreStatusOK ||
        currentAuthority == nil || authorityError != nil) {
      AncPrivateVaultRotationPreparationStoreStatus closed =
          [preparationHandle close];
      anc_pv_rotation_preparation_snapshot_zero(&preparation);
      return closed == AncPrivateVaultRotationPreparationStoreStatusOK
                 ? AncRotationCoordinatorStatusForAuthority(authorityStatus)
                 : AncPrivateVaultRotationCoordinatorStatusProtectionFailed;
    }
    if (nowMilliseconds < currentAuthority.snapshot.verifiedAtMs) {
      AncPrivateVaultRotationPreparationStoreStatus closed =
          [preparationHandle close];
      anc_pv_rotation_preparation_snapshot_zero(&preparation);
      return closed == AncPrivateVaultRotationPreparationStoreStatusOK
                 ? AncPrivateVaultRotationCoordinatorStatusClockFailed
                 : AncPrivateVaultRotationCoordinatorStatusProtectionFailed;
    }

    BOOL basePath = currentAuthority.custodyGeneration ==
                    preparation.base_custody_generation;
    BOOL retryPath =
        currentAuthority.custodyGeneration ==
        preparation.base_custody_generation + 1;
    if (!basePath && !retryPath) {
      AncPrivateVaultRotationPreparationStoreStatus closed =
          [preparationHandle close];
      anc_pv_rotation_preparation_snapshot_zero(&preparation);
      return closed == AncPrivateVaultRotationPreparationStoreStatusOK
                 ? (currentAuthority.custodyGeneration <
                            preparation.base_custody_generation
                        ? AncPrivateVaultRotationCoordinatorStatusRollbackDetected
                        : AncPrivateVaultRotationCoordinatorStatusConflict)
                 : AncPrivateVaultRotationCoordinatorStatusProtectionFailed;
    }

    if (basePath) {
      AncPrivateVaultCustodySnapshot baseCustody;
      AncPrivateVaultCustodyHandle *baseCustodyHandle = nil;
      AncPrivateVaultCustodyRepositoryStatus custodyStatus =
          [self.custodyRepository readVaultId:vaultHex
                                     snapshot:&baseCustody
                                       handle:&baseCustodyHandle];
      BOOL valid = custodyStatus == AncPrivateVaultCustodyRepositoryStatusOK &&
                   baseCustodyHandle != nil &&
                   AncRotationCoordinatorBaseTupleValid(
                       &preparation, vaultHex, currentAuthority, &baseCustody);
      AncPrivateVaultCustodyRepositoryStatus baseClosed =
          baseCustodyHandle == nil
              ? AncPrivateVaultCustodyRepositoryStatusInvalid
              : [baseCustodyHandle close];
      anc_pv_custody_snapshot_zero(&baseCustody);
      if (!valid || baseClosed != AncPrivateVaultCustodyRepositoryStatusOK) {
        AncPrivateVaultRotationPreparationStoreStatus closed =
            [preparationHandle close];
        anc_pv_rotation_preparation_snapshot_zero(&preparation);
        if (closed != AncPrivateVaultRotationPreparationStoreStatusOK ||
            baseClosed != AncPrivateVaultCustodyRepositoryStatusOK)
          return AncPrivateVaultRotationCoordinatorStatusProtectionFailed;
        return valid ? AncRotationCoordinatorStatusForCustody(baseClosed)
                     : AncPrivateVaultRotationCoordinatorStatusConflict;
      }
    } else {
      AncPrivateVaultCustodySnapshot successorCustody;
      AncPrivateVaultCustodyHandle *successorHandle = nil;
      AncPrivateVaultCustodyRepositoryStatus custodyStatus =
          [self.custodyRepository readVaultId:vaultHex
                                     snapshot:&successorCustody
                                       handle:&successorHandle];
      BOOL valid = custodyStatus == AncPrivateVaultCustodyRepositoryStatusOK &&
                   successorHandle != nil &&
                   AncPrivateVaultRotationPreparationOfficialTupleValid(
                       &preparation, vaultHex, currentAuthority,
                       &successorCustody);
      AncPrivateVaultCustodyRepositoryStatus successorClosed =
          successorHandle == nil
              ? AncPrivateVaultCustodyRepositoryStatusInvalid
              : [successorHandle close];
      anc_pv_custody_snapshot_zero(&successorCustody);
      if (!valid ||
          successorClosed != AncPrivateVaultCustodyRepositoryStatusOK) {
        AncPrivateVaultRotationPreparationStoreStatus closed =
            [preparationHandle close];
        anc_pv_rotation_preparation_snapshot_zero(&preparation);
        return closed != AncPrivateVaultRotationPreparationStoreStatusOK ||
                       successorClosed !=
                           AncPrivateVaultCustodyRepositoryStatusOK
                   ? AncPrivateVaultRotationCoordinatorStatusProtectionFailed
                   : AncPrivateVaultRotationCoordinatorStatusConflict;
      }
    }

    NSData *vaultData =
        [NSData dataWithBytes:vaultId
                       length:ANC_PV_ROTATION_PREPARATION_ID_BYTES];
    AncPrivateVaultRotationEvidenceStoreCheckpoint *evidenceLedger = nil;
    AncPrivateVaultRotationEvidenceStoreStatus evidenceStatus =
        [self.evidenceStore readVaultId:vaultData checkpoint:&evidenceLedger];
    if (evidenceStatus != AncPrivateVaultRotationEvidenceStoreStatusOK ||
        evidenceLedger == nil || evidenceLedger.targetEndpointId.length != 16 ||
        (evidenceLedger.phase !=
             AncPrivateVaultRotationEvidenceStorePhaseDestructions &&
         evidenceLedger.phase !=
             AncPrivateVaultRotationEvidenceStorePhaseComplete) ||
        !AncRotationCoordinatorLedgerMatchesPreparation(
            evidenceLedger, preparationCheckpoint,
            evidenceLedger.targetEndpointId)) {
      AncPrivateVaultRotationPreparationStoreStatus closed =
          [preparationHandle close];
      anc_pv_rotation_preparation_snapshot_zero(&preparation);
      return closed != AncPrivateVaultRotationPreparationStoreStatusOK
                 ? AncPrivateVaultRotationCoordinatorStatusProtectionFailed
             : evidenceStatus !=
                       AncPrivateVaultRotationEvidenceStoreStatusOK
                 ? AncRotationCoordinatorStatusForEvidenceStore(evidenceStatus)
                 : AncPrivateVaultRotationCoordinatorStatusConflict;
    }
    AncPrivateVaultPreparedRotationCustodyCheckpoint *preparedCustody = nil;
    AncPrivateVaultCustodyRepositoryStatus preparedCustodyStatus =
        [self.custodyRepository readPreparedRotationVaultId:vaultHex
                                                  checkpoint:&preparedCustody];
    BOOL exactPreparedCustody =
        preparedCustodyStatus == AncPrivateVaultCustodyRepositoryStatusOK &&
        AncRotationCoordinatorPreparedCustodyMatches(
            preparedCustody, &preparation, vaultHex, evidenceLedger);
    BOOL preparedCustodyAbsent =
        preparedCustodyStatus == AncPrivateVaultCustodyRepositoryStatusNotFound;
    if ((basePath && !exactPreparedCustody) ||
        (retryPath && !exactPreparedCustody && !preparedCustodyAbsent)) {
      AncPrivateVaultRotationPreparationStoreStatus closed =
          [preparationHandle close];
      anc_pv_rotation_preparation_snapshot_zero(&preparation);
      return closed != AncPrivateVaultRotationPreparationStoreStatusOK
                 ? AncPrivateVaultRotationCoordinatorStatusProtectionFailed
             : preparedCustodyStatus !=
                       AncPrivateVaultCustodyRepositoryStatusOK
                 ? AncRotationCoordinatorStatusForCustody(preparedCustodyStatus)
                 : AncPrivateVaultRotationCoordinatorStatusConflict;
    }

    __block BOOL artifactsInspected = NO;
    __block BOOL artifactsVerified = NO;
    __block AncPrivateVaultControlLogReplayResult *replayResult = nil;
    __block NSData *artifactEntryHash = nil;
    NSString *preparationCeremony = AncRotationCoordinatorHex(
        preparation.ceremony_id, ANC_PV_ROTATION_PREPARATION_ID_BYTES);
    AncPrivateVaultRotationPreparationStoreStatus artifactStatus =
        [self.preparationStore
            consumeAwaitingArtifactsVaultId:vaultId
                       expectedCheckpoint:preparationCheckpoint
                                 consumer:^BOOL(
                                     const uint8_t *signedEntry,
                                     size_t signedEntryLength,
                                     const uint8_t *recoveryWrap,
                                     size_t recoveryWrapLength) {
      @autoreleasepool {
        artifactsInspected = YES;
        NSData *signedData =
            [NSData dataWithBytesNoCopy:(void *)signedEntry
                                 length:signedEntryLength
                           freeWhenDone:NO];
        NSData *wrapData =
            [NSData dataWithBytesNoCopy:(void *)recoveryWrap
                                 length:recoveryWrapLength
                           freeWhenDone:NO];
        artifactEntryHash =
            AncPrivateVaultControlLogSignedEntryDomainHash(signedData);
        if (artifactEntryHash.length != 32)
          return NO;
        if (basePath) {
          AncPrivateVaultControlLogState *currentState =
              AncPrivateVaultControlLogStateCreateFromAuthenticatedCheckpoint(
                  currentAuthority);
          AncPrivateVaultRecoveryWrapRotationVerifier *verifier =
              [[AncPrivateVaultRecoveryWrapRotationVerifier alloc]
                  initWithEncodedWrap:wrapData
                      trustedNowMilliseconds:nowMilliseconds];
          if (currentState == nil || verifier == nil)
            return NO;
          AncPrivateVaultControlLogStatus replayStatus = [self.controlLog
              replaySignedEntry:signedData
                   currentState:currentState
                       verifier:verifier
                         result:&replayResult];
          AncPrivateVaultControlLogState *prior = nil;
          AncPrivateVaultControlLogState *next = nil;
          NSData *registeredEntryHash = nil;
          BOOL idempotent = YES;
          BOOL evidence =
              replayStatus == AncPrivateVaultControlLogStatusOK &&
              replayResult != nil && verifier.isVerified &&
              AncPrivateVaultControlLogReplayResultCopyEvidence(
                  replayResult, &prior, &next, &registeredEntryHash,
                  &idempotent);
          artifactsVerified =
              evidence && !idempotent && prior != nil && next != nil &&
              [registeredEntryHash isEqualToData:artifactEntryHash] &&
              next.sequence == preparation.expected_sequence &&
              [next.headHash isEqualToData:artifactEntryHash] &&
              AncRotationCoordinatorBytesEqualData(
                  preparation.expected_previous_head, prior.headHash, 32) &&
              next.epoch == preparation.pending_epoch &&
              next.recoveryGeneration ==
                  preparation.base_recovery_generation &&
              AncRotationCoordinatorBytesEqualData(
                  preparation.transcript_digest, next.membershipHash, 32) &&
              [verifier.verifiedWrapHash
                  isEqualToData:next.recoveryWrapHash] &&
              [verifier.verifiedCeremonyId
                  isEqualToString:preparationCeremony];
        } else {
          AncPrivateVaultControlLogState *successorState =
              AncPrivateVaultControlLogStateCreateFromAuthenticatedCheckpoint(
                  currentAuthority);
          NSData *wrapHash = nil;
          NSString *wrapCeremony = nil;
          artifactsVerified =
              successorState != nil &&
              [artifactEntryHash
                  isEqualToData:currentAuthority.snapshot.headHash] &&
              AncPrivateVaultRecoveryWrapVerifyCommittedSuccessor(
                  wrapData, successorState, nowMilliseconds, &wrapHash,
                  &wrapCeremony) &&
              [wrapHash
                  isEqualToData:currentAuthority.snapshot.recoveryWrapHash] &&
              [wrapCeremony isEqualToString:preparationCeremony];
        }
        return artifactsVerified;
      }
    }];
    if (artifactStatus !=
            AncPrivateVaultRotationPreparationStoreStatusOK ||
        !artifactsVerified) {
      AncPrivateVaultRotationPreparationStoreStatus closed =
          [preparationHandle close];
      anc_pv_rotation_preparation_snapshot_zero(&preparation);
      return closed != AncPrivateVaultRotationPreparationStoreStatusOK
                 ? AncPrivateVaultRotationCoordinatorStatusProtectionFailed
                 : artifactsInspected && !artifactsVerified
                       ? retryPath
                             ? AncPrivateVaultRotationCoordinatorStatusRecoveryWrapRejected
                             : AncPrivateVaultRotationCoordinatorStatusControlRejected
                 : artifactStatus !=
                           AncPrivateVaultRotationPreparationStoreStatusOK
                       ? AncRotationCoordinatorStatusForPreparation(
                             artifactStatus)
                       : AncPrivateVaultRotationCoordinatorStatusControlRejected;
    }
    if (AncRotationCoordinatorFault(
            AncPrivateVaultRotationCoordinatorFaultAfterArtifactAuthentication)) {
      AncPrivateVaultRotationPreparationStoreStatus closed =
          [preparationHandle close];
      anc_pv_rotation_preparation_snapshot_zero(&preparation);
      return closed == AncPrivateVaultRotationPreparationStoreStatusOK
                 ? AncPrivateVaultRotationCoordinatorStatusStorageFailed
                 : AncPrivateVaultRotationCoordinatorStatusProtectionFailed;
    }

    if (basePath) {
      AncPrivateVaultVerifiedReplayResult *verified =
          AncPrivateVaultVerifiedRotationReplayResultCreate(
              replayResult, currentAuthority, preparedCustody,
              nowMilliseconds);
      if (verified == nil) {
        AncPrivateVaultRotationPreparationStoreStatus closed =
            [preparationHandle close];
        anc_pv_rotation_preparation_snapshot_zero(&preparation);
        return closed == AncPrivateVaultRotationPreparationStoreStatusOK
                   ? AncPrivateVaultRotationCoordinatorStatusAuthorityRejected
                   : AncPrivateVaultRotationCoordinatorStatusProtectionFailed;
      }
      AncPrivateVaultAuthorityCheckpoint *committed = nil;
      authorityStatus = [self.authorityStore
          commitVerifiedReplayResult:verified
                             vaultId:vaultHex
                        verifiedAtMs:nowMilliseconds
                          checkpoint:&committed
                               error:&authorityError];
      if (authorityStatus != AncPrivateVaultAuthorityStoreStatusOK ||
          committed == nil || authorityError != nil) {
        AncPrivateVaultRotationPreparationStoreStatus closed =
            [preparationHandle close];
        anc_pv_rotation_preparation_snapshot_zero(&preparation);
        return closed == AncPrivateVaultRotationPreparationStoreStatusOK
                   ? AncRotationCoordinatorStatusForAuthority(authorityStatus)
                   : AncPrivateVaultRotationCoordinatorStatusProtectionFailed;
      }
      currentAuthority = committed;
      if (AncRotationCoordinatorFault(
              AncPrivateVaultRotationCoordinatorFaultAfterAuthorityCommit)) {
        AncPrivateVaultRotationPreparationStoreStatus closed =
            [preparationHandle close];
        anc_pv_rotation_preparation_snapshot_zero(&preparation);
        return closed == AncPrivateVaultRotationPreparationStoreStatusOK
                   ? AncPrivateVaultRotationCoordinatorStatusStorageFailed
                   : AncPrivateVaultRotationCoordinatorStatusProtectionFailed;
      }
    }
    if (AncRotationCoordinatorFault(
            AncPrivateVaultRotationCoordinatorFaultBeforeOfficialReread)) {
      AncPrivateVaultRotationPreparationStoreStatus closed =
          [preparationHandle close];
      anc_pv_rotation_preparation_snapshot_zero(&preparation);
      return closed == AncPrivateVaultRotationPreparationStoreStatusOK
                 ? AncPrivateVaultRotationCoordinatorStatusStorageFailed
                 : AncPrivateVaultRotationCoordinatorStatusProtectionFailed;
    }

    AncPrivateVaultAuthorityCheckpoint *officialAuthority = nil;
    authorityError = nil;
    authorityStatus = [self.authorityStore loadVaultId:vaultHex
                                            checkpoint:&officialAuthority
                                                 error:&authorityError];
    AncPrivateVaultCustodySnapshot officialCustody;
    AncPrivateVaultCustodyHandle *officialCustodyHandle = nil;
    AncPrivateVaultCustodyRepositoryStatus officialCustodyStatus =
        [self.custodyRepository readVaultId:vaultHex
                                   snapshot:&officialCustody
                                     handle:&officialCustodyHandle];
    BOOL officialValid =
        authorityStatus == AncPrivateVaultAuthorityStoreStatusOK &&
        authorityError == nil && officialAuthority != nil &&
        officialCustodyStatus == AncPrivateVaultCustodyRepositoryStatusOK &&
        officialCustodyHandle != nil &&
        AncPrivateVaultRotationPreparationOfficialTupleValid(
            &preparation, vaultHex, officialAuthority, &officialCustody) &&
        [artifactEntryHash isEqualToData:officialAuthority.snapshot.headHash];
    __block BOOL keyMatches = NO;
    __block AncPrivateVaultCustodyRepositoryStatus officialBorrow =
        AncPrivateVaultCustodyRepositoryStatusInvalid;
    if (officialValid) {
      preparationStatus =
          [preparationHandle borrow:^BOOL(const uint8_t *pendingKey) {
        officialBorrow = [officialCustodyHandle
            borrow:^BOOL(const AncPrivateVaultCustodySecretInputs *secrets) {
              keyMatches = anc_pv_memcmp(pendingKey, secrets->active_epoch_key,
                                        ANC_PV_KEY_BYTES) == ANC_PV_CRYPTO_OK;
              return keyMatches;
            }];
        return officialBorrow == AncPrivateVaultCustodyRepositoryStatusOK &&
               keyMatches;
      }];
      officialValid =
          preparationStatus ==
              AncPrivateVaultRotationPreparationStoreStatusOK &&
          officialBorrow == AncPrivateVaultCustodyRepositoryStatusOK &&
          keyMatches;
    }
    AncPrivateVaultCustodyRepositoryStatus officialClosed =
        officialCustodyHandle == nil
            ? AncPrivateVaultCustodyRepositoryStatusInvalid
            : [officialCustodyHandle close];
    AncPrivateVaultRotationPreparationStoreStatus preparationClosed =
        [preparationHandle close];
    AncPrivateVaultCustodyRepositoryStatus cleanupStatus =
        AncPrivateVaultCustodyRepositoryStatusOK;
    if (officialValid &&
        officialClosed == AncPrivateVaultCustodyRepositoryStatusOK &&
        preparationClosed ==
            AncPrivateVaultRotationPreparationStoreStatusOK &&
        preparedCustody != nil) {
      NSData *baseSnapshotDigest = [NSData
          dataWithBytes:preparation.base_frame_digest
                 length:ANC_PV_HASH_BYTES];
      cleanupStatus = [self.custodyRepository
          adoptPreparedRotationAuthorityAnchorVaultId:vaultHex
                                    expectedGeneration:
                                        preparation.base_custody_generation
                                expectedSnapshotDigest:baseSnapshotDigest
                            preparedRotationCheckpoint:preparedCustody
                                     nextPublicSnapshot:&officialCustody];
    }
    if (!officialValid ||
        officialClosed != AncPrivateVaultCustodyRepositoryStatusOK ||
        preparationClosed != AncPrivateVaultRotationPreparationStoreStatusOK ||
        cleanupStatus != AncPrivateVaultCustodyRepositoryStatusOK) {
      anc_pv_custody_snapshot_zero(&officialCustody);
      anc_pv_rotation_preparation_snapshot_zero(&preparation);
      return officialClosed != AncPrivateVaultCustodyRepositoryStatusOK ||
                     preparationClosed !=
                         AncPrivateVaultRotationPreparationStoreStatusOK
                 ? AncPrivateVaultRotationCoordinatorStatusProtectionFailed
             : cleanupStatus != AncPrivateVaultCustodyRepositoryStatusOK
                 ? AncRotationCoordinatorStatusForCustody(cleanupStatus)
                 : AncPrivateVaultRotationCoordinatorStatusConflict;
    }
    if (AncRotationCoordinatorFault(
            AncPrivateVaultRotationCoordinatorFaultBeforePreparationConsume)) {
      anc_pv_custody_snapshot_zero(&officialCustody);
      anc_pv_rotation_preparation_snapshot_zero(&preparation);
      return AncPrivateVaultRotationCoordinatorStatusStorageFailed;
    }

    AncPrivateVaultRotationPreparationCheckpoint *consumed = nil;
    preparationStatus = [self.preparationStore
        consumeCommittedVaultId:vaultId
                 authorityStore:self.authorityStore
              custodyRepository:self.custodyRepository
                     checkpoint:&consumed];
    if (preparationStatus !=
            AncPrivateVaultRotationPreparationStoreStatusOK ||
        consumed == nil) {
      anc_pv_custody_snapshot_zero(&officialCustody);
      anc_pv_rotation_preparation_snapshot_zero(&preparation);
      return AncRotationCoordinatorStatusForPreparation(preparationStatus);
    }
    AncPrivateVaultRotationCoordinatorResult *done =
        AncRotationCoordinatorMakeResult(vaultHex, consumed, officialAuthority,
                                         &officialCustody);
    anc_pv_custody_snapshot_zero(&officialCustody);
    anc_pv_rotation_preparation_snapshot_zero(&preparation);
    if (done == nil)
      return AncPrivateVaultRotationCoordinatorStatusProtectionFailed;
    if (result != NULL)
      *result = done;
    return AncPrivateVaultRotationCoordinatorStatusOK;
  } @catch (__unused NSException *exception) {
    return AncPrivateVaultRotationCoordinatorStatusProtectionFailed;
  } @finally {
    [operationLock unlock];
  }
}

- (AncPrivateVaultRotationCoordinatorStatus)
    prepareHostedAppendVaultId:(const uint8_t[16])vaultId
                         request:
                             (AncPrivateVaultHostedAppendRequest **)request {
  if (request != NULL)
    *request = nil;
  if (vaultId == NULL)
    return AncPrivateVaultRotationCoordinatorStatusInvalid;
  NSString *vaultHex = AncRotationCoordinatorHex(
      vaultId, ANC_PV_ROTATION_PREPARATION_ID_BYTES);
  if (vaultHex.length != 32)
    return AncPrivateVaultRotationCoordinatorStatusInvalid;
  NSRecursiveLock *operationLock =
      AncRotationCoordinatorLockForVault(vaultHex);
  [operationLock lock];
  @try {
    NSData *vaultData = [NSData dataWithBytes:vaultId length:16];
    AncPrivateVaultRotationEvidenceStoreCheckpoint *ledger = nil;
    AncPrivateVaultRotationEvidenceStoreStatus evidenceStatus =
        [self.evidenceStore readVaultId:vaultData checkpoint:&ledger];
    if (evidenceStatus != AncPrivateVaultRotationEvidenceStoreStatusOK ||
        ledger == nil ||
        ledger.phase != AncPrivateVaultRotationEvidenceStorePhaseComplete)
      return evidenceStatus == AncPrivateVaultRotationEvidenceStoreStatusOK
                 ? AncPrivateVaultRotationCoordinatorStatusConflict
                 : AncRotationCoordinatorStatusForEvidenceStore(evidenceStatus);
    uint64_t milliseconds = 0;
    uint8_t nonceBytes[16] = {0};
    if (![self.trustedClock readNowMilliseconds:&milliseconds])
      return AncPrivateVaultRotationCoordinatorStatusClockFailed;
    if (anc_pv_random(nonceBytes, sizeof nonceBytes) != ANC_PV_CRYPTO_OK) {
      anc_pv_zeroize(nonceBytes, sizeof nonceBytes);
      return AncPrivateVaultRotationCoordinatorStatusProtectionFailed;
    }
    NSString *issuedAt = AncRotationCoordinatorTimestamp(milliseconds);
    NSString *nonce = AncRotationCoordinatorHex(nonceBytes, sizeof nonceBytes);
    anc_pv_zeroize(nonceBytes, sizeof nonceBytes);
    if (issuedAt == nil || nonce.length != 32)
      return AncPrivateVaultRotationCoordinatorStatusClockFailed;

    __block AncPrivateVaultHostedAppendRequest *prepared = nil;
    AncPrivateVaultRotationPreparationStoreStatus preparationStatus =
        [self.preparationStore
            borrowConsumedHostedAppendVaultId:vaultId
                               authorityStore:self.authorityStore
                            custodyRepository:self.custodyRepository
                                      consumer:^BOOL(
                                          NSString *authenticatedVaultId,
                                          NSString *endpointId,
                                          const uint8_t *signedEntry,
                                          size_t signedEntryLength,
                                          const uint8_t *recoveryWrap,
                                          size_t recoveryWrapLength,
                                          const uint8_t *signingSeed,
                                          NSData *signingPublicKey) {
      NSData *signedData =
          [NSData dataWithBytesNoCopy:(void *)signedEntry
                               length:signedEntryLength
                         freeWhenDone:NO];
      NSData *wrapData =
          [NSData dataWithBytesNoCopy:(void *)recoveryWrap
                               length:recoveryWrapLength
                         freeWhenDone:NO];
      AncPrivateVaultEndpointRequestStatus endpointStatus;
      NSData *body = AncPrivateVaultControlLogAppendRequestEncode(
          signedData, wrapData, &endpointStatus);
      NSString *proof =
          body == nil
              ? nil
              : AncPrivateVaultControlLogAppendProofHeaderCreate(
                    authenticatedVaultId, endpointId, body, issuedAt, nonce,
                    signingSeed, signingPublicKey, &endpointStatus);
      prepared = endpointStatus == AncPrivateVaultEndpointRequestStatusOK
                     ? AncRotationCoordinatorMakeHostedAppendRequest(
                           authenticatedVaultId, endpointId, body, proof)
                     : nil;
      return prepared != nil;
    }];
    if (preparationStatus !=
            AncPrivateVaultRotationPreparationStoreStatusOK ||
        prepared == nil)
      return preparationStatus ==
                     AncPrivateVaultRotationPreparationStoreStatusOK
                 ? AncPrivateVaultRotationCoordinatorStatusProtectionFailed
                 : AncRotationCoordinatorStatusForPreparation(
                       preparationStatus);
    if (request != NULL)
      *request = prepared;
    return AncPrivateVaultRotationCoordinatorStatusOK;
  } @catch (__unused NSException *exception) {
    return AncPrivateVaultRotationCoordinatorStatusProtectionFailed;
  } @finally {
    [operationLock unlock];
  }
}

- (AncPrivateVaultRotationCoordinatorStatus)
    recoverHostedAppendCleanupVaultId:(const uint8_t[16])vaultId
                                result:
                                    (AncPrivateVaultRotationCoordinatorResult **)
                                        result {
  if (result != NULL)
    *result = nil;
  if (vaultId == NULL)
    return AncPrivateVaultRotationCoordinatorStatusInvalid;
  NSString *vaultHex = AncRotationCoordinatorHex(
      vaultId, ANC_PV_ROTATION_PREPARATION_ID_BYTES);
  if (vaultHex.length != 32)
    return AncPrivateVaultRotationCoordinatorStatusInvalid;
  NSRecursiveLock *operationLock =
      AncRotationCoordinatorLockForVault(vaultHex);
  [operationLock lock];
  @try {
    AncPrivateVaultRotationPreparationCheckpoint *cleaned = nil;
    AncPrivateVaultRotationPreparationStoreStatus preparationStatus =
        [self.preparationStore
            recoverPersistedHostedAppendReceiptVaultId:vaultId
                                        authorityStore:self.authorityStore
                                     custodyRepository:self.custodyRepository
                                            checkpoint:&cleaned];
    if (preparationStatus !=
            AncPrivateVaultRotationPreparationStoreStatusOK ||
        cleaned == nil ||
        cleaned.snapshot.phase !=
            ANC_PV_ROTATION_PREPARATION_PHASE_CLEANED)
      return preparationStatus ==
                     AncPrivateVaultRotationPreparationStoreStatusOK
                 ? AncPrivateVaultRotationCoordinatorStatusProtectionFailed
                 : AncRotationCoordinatorStatusForPreparation(
                       preparationStatus);

    AncPrivateVaultAuthorityCheckpoint *authority = nil;
    NSError *authorityError = nil;
    AncPrivateVaultAuthorityStoreStatus authorityStatus =
        [self.authorityStore loadVaultId:vaultHex
                              checkpoint:&authority
                                   error:&authorityError];
    AncPrivateVaultCustodySnapshot custody = {0};
    AncPrivateVaultCustodyHandle *custodyHandle = nil;
    AncPrivateVaultCustodyRepositoryStatus custodyStatus =
        [self.custodyRepository readVaultId:vaultHex
                                   snapshot:&custody
                                     handle:&custodyHandle];
    AncPrivateVaultRotationPreparationSnapshot tuple = cleaned.snapshot;
    BOOL reconstructable =
        tuple.base_epoch < UINT64_MAX && tuple.base_sequence < UINT64_MAX &&
        authority != nil && authority.snapshot.membershipHash.length == 32;
    if (reconstructable) {
      tuple.flags = ANC_PV_ROTATION_PREPARATION_FLAG_EDGE_BOUND |
                    ANC_PV_ROTATION_PREPARATION_FLAG_SPOOL_DURABLE;
      tuple.pending_epoch = tuple.base_epoch + 1;
      tuple.expected_sequence = tuple.base_sequence + 1;
      memcpy(tuple.expected_previous_head, tuple.base_head,
             ANC_PV_HASH_BYTES);
      memcpy(tuple.transcript_digest,
             authority.snapshot.membershipHash.bytes, ANC_PV_HASH_BYTES);
    }
    BOOL valid =
        reconstructable &&
        authorityStatus == AncPrivateVaultAuthorityStoreStatusOK &&
        authorityError == nil && custodyStatus ==
                                      AncPrivateVaultCustodyRepositoryStatusOK &&
        custodyHandle != nil &&
        AncPrivateVaultRotationPreparationOfficialTupleValid(
            &tuple, vaultHex, authority, &custody);
    anc_pv_rotation_preparation_snapshot_zero(&tuple);
    AncPrivateVaultCustodyRepositoryStatus closed =
        custodyHandle == nil ? AncPrivateVaultCustodyRepositoryStatusInvalid
                             : [custodyHandle close];
    AncPrivateVaultRotationCoordinatorResult *done =
        valid && closed == AncPrivateVaultCustodyRepositoryStatusOK
            ? AncRotationCoordinatorMakeResult(vaultHex, cleaned, authority,
                                               &custody)
            : nil;
    anc_pv_custody_snapshot_zero(&custody);
    if (!valid)
      return AncPrivateVaultRotationCoordinatorStatusConflict;
    if (closed != AncPrivateVaultCustodyRepositoryStatusOK || done == nil)
      return AncPrivateVaultRotationCoordinatorStatusProtectionFailed;
    if (result != NULL)
      *result = done;
    return AncPrivateVaultRotationCoordinatorStatusOK;
  } @finally {
    [operationLock unlock];
  }
}

- (AncPrivateVaultRotationCoordinatorStatus)
    finalizeHostedAppendVaultId:(const uint8_t[16])vaultId
                         receipt:(NSData *)receiptBytes
                          result:
                              (AncPrivateVaultRotationCoordinatorResult **)result {
  if (result != NULL)
    *result = nil;
  NSData *canonicalReceipt = [receiptBytes copy];
  AncPrivateVaultRotationAppendReceipt *receipt =
      AncPrivateVaultRotationAppendReceiptDecode(canonicalReceipt);
  if (vaultId == NULL || canonicalReceipt == nil || receipt == nil)
    return AncPrivateVaultRotationCoordinatorStatusInvalid;
  NSString *vaultHex = AncRotationCoordinatorHex(
      vaultId, ANC_PV_ROTATION_PREPARATION_ID_BYTES);
  NSRecursiveLock *operationLock =
      AncRotationCoordinatorLockForVault(vaultHex);
  [operationLock lock];
  @try {
    AncPrivateVaultRotationPreparationCheckpoint *cleaned = nil;
    AncPrivateVaultRotationPreparationStoreStatus preparationStatus =
        [self.preparationStore
                  cleanConsumedVaultId:vaultId
                                receipt:canonicalReceipt
                       authorityStore:self.authorityStore
                    custodyRepository:self.custodyRepository
                           checkpoint:&cleaned];
    if (preparationStatus !=
            AncPrivateVaultRotationPreparationStoreStatusOK ||
        cleaned == nil ||
        cleaned.snapshot.phase !=
            ANC_PV_ROTATION_PREPARATION_PHASE_CLEANED)
      return preparationStatus ==
                     AncPrivateVaultRotationPreparationStoreStatusOK
                 ? AncPrivateVaultRotationCoordinatorStatusProtectionFailed
                 : AncRotationCoordinatorStatusForPreparation(
                       preparationStatus);

    AncPrivateVaultAuthorityCheckpoint *authority = nil;
    NSError *authorityError = nil;
    AncPrivateVaultAuthorityStoreStatus authorityStatus =
        [self.authorityStore loadVaultId:vaultHex
                              checkpoint:&authority
                                   error:&authorityError];
    AncPrivateVaultCustodySnapshot custody = {0};
    AncPrivateVaultCustodyHandle *custodyHandle = nil;
    AncPrivateVaultCustodyRepositoryStatus custodyStatus =
        [self.custodyRepository readVaultId:vaultHex
                                   snapshot:&custody
                                     handle:&custodyHandle];
    BOOL valid = authorityStatus == AncPrivateVaultAuthorityStoreStatusOK &&
                 authorityError == nil && authority != nil &&
                 [authority.vaultId isEqualToString:receipt.vaultId] &&
                 authority.snapshot.sequence == receipt.sequence &&
                 [authority.snapshot.headHash isEqualToData:receipt.headHash] &&
                 [authority.snapshot.recoveryWrapHash
                     isEqualToData:receipt.recoveryWrapHash] &&
                 custodyStatus == AncPrivateVaultCustodyRepositoryStatusOK &&
                 custodyHandle != nil &&
                 custody.custody_generation ==
                     authority.custodyGeneration &&
                 custody.anchored_sequence == receipt.sequence &&
                 AncRotationCoordinatorBytesEqualData(
                     custody.anchored_head, receipt.headHash, 32);
    AncPrivateVaultCustodyRepositoryStatus closed =
        custodyHandle == nil ? AncPrivateVaultCustodyRepositoryStatusInvalid
                             : [custodyHandle close];
    AncPrivateVaultRotationCoordinatorResult *done =
        valid && closed == AncPrivateVaultCustodyRepositoryStatusOK
            ? AncRotationCoordinatorMakeResult(vaultHex, cleaned, authority,
                                               &custody)
            : nil;
    anc_pv_custody_snapshot_zero(&custody);
    if (!valid)
      return AncPrivateVaultRotationCoordinatorStatusConflict;
    if (closed != AncPrivateVaultCustodyRepositoryStatusOK || done == nil)
      return AncPrivateVaultRotationCoordinatorStatusProtectionFailed;
    if (result != NULL)
      *result = done;
    return AncPrivateVaultRotationCoordinatorStatusOK;
  } @finally {
    [operationLock unlock];
  }
}

@end
