#import "PrivateVaultCustodyRepository.h"

NS_ASSUME_NONNULL_BEGIN

@interface AncPrivateVaultPreparedRotationCustodyCheckpoint : NSObject
@property(nonatomic, readonly) NSString *vaultId;
@property(nonatomic, readonly) NSData *targetEndpointId;
@property(nonatomic, readonly) NSData *ceremonyId;
@property(nonatomic, readonly) uint64_t baseCustodyGeneration;
@property(nonatomic, readonly) uint64_t targetCustodyGeneration;
@property(nonatomic, readonly) NSData *baseSnapshotDigest;
@property(nonatomic, readonly) uint64_t activeEpoch;
@property(nonatomic, readonly) uint64_t pendingEpoch;
@property(nonatomic, readonly) uint64_t expectedNextSequence;
@property(nonatomic, readonly) NSData *expectedPreviousHead;
@property(nonatomic, readonly) NSData *successorMembershipDigest;
@property(nonatomic, readonly) uint64_t preparationFenceGeneration;
@property(nonatomic, readonly) NSData *preparationRecordDigest;
@property(nonatomic, readonly) uint64_t fenceGeneration;
@property(nonatomic, readonly) NSData *recordDigest;
- (instancetype)init NS_UNAVAILABLE;
+ (instancetype)new NS_UNAVAILABLE;
@end

@interface AncPrivateVaultCustodyRepository (RotationInternal)

/* Reconciles and returns the exact secret-free sidecar checkpoint. It never
 * creates or restages missing custody. */
- (AncPrivateVaultCustodyRepositoryStatus)
    readPreparedRotationVaultId:(NSString *)vaultId
                     checkpoint:
                         (AncPrivateVaultPreparedRotationCustodyCheckpoint
                              *_Nullable *_Nullable)checkpoint;

/* Stores the next EEK in a separately fenced target-generation record. The
 * official custody record remains generation g until AuthorityStore adopts the
 * authenticated control edge as generation g+1. */
- (AncPrivateVaultCustodyRepositoryStatus)
    stagePreparedRotationVaultId:(NSString *)vaultId
                targetEndpointId:(NSData *)targetEndpointId
                      ceremonyId:(NSData *)ceremonyId
              expectedGeneration:(uint64_t)expectedGeneration
          expectedSnapshotDigest:(NSData *)expectedSnapshotDigest
                    pendingEpoch:(uint64_t)pendingEpoch
            expectedNextSequence:(uint64_t)expectedNextSequence
            expectedPreviousHead:(NSData *)expectedPreviousHead
       successorMembershipDigest:(NSData *)successorMembershipDigest
      preparationFenceGeneration:(uint64_t)preparationFenceGeneration
          preparationRecordDigest:(NSData *)preparationRecordDigest
                  pendingEpochKey:(const uint8_t *)pendingEpochKey
                       checkpoint:
                           (AncPrivateVaultPreparedRotationCustodyCheckpoint
                                *_Nullable *_Nullable)checkpoint;

/* Consumes only the exact separately fenced checkpoint and commits the official
 * generation g+1 record once. Exact retries clean a stale sidecar; no path may
 * turn an already official g+1 record into g+2. */
- (AncPrivateVaultCustodyRepositoryStatus)
    adoptPreparedRotationAuthorityAnchorVaultId:(NSString *)vaultId
                              expectedGeneration:(uint64_t)expectedGeneration
                          expectedSnapshotDigest:(NSData *)expectedSnapshotDigest
                      preparedRotationCheckpoint:
                          (AncPrivateVaultPreparedRotationCustodyCheckpoint *)
                              preparedRotationCheckpoint
                               nextPublicSnapshot:
                                   (const AncPrivateVaultCustodySnapshot *)
                                       nextPublicSnapshot;

@end

typedef NS_ENUM(NSInteger, AncPrivateVaultCustodyRotationFaultPoint) {
  AncPrivateVaultCustodyRotationFaultAfterStageWrite = 1,
  AncPrivateVaultCustodyRotationFaultAfterFenceBegin = 2,
  AncPrivateVaultCustodyRotationFaultAfterLiveWrite = 3,
  AncPrivateVaultCustodyRotationFaultAfterFenceCommit = 4,
  AncPrivateVaultCustodyRotationFaultBeforeFinalReread = 5,
  AncPrivateVaultCustodyRotationFaultAfterMainAdoption = 6,
  AncPrivateVaultCustodyRotationFaultBeforeSidecarDelete = 7,
};

#if ANC_PRIVATE_VAULT_TESTING
typedef BOOL (^AncPrivateVaultCustodyRotationFaultHook)(
    AncPrivateVaultCustodyRotationFaultPoint point);
FOUNDATION_EXPORT void AncPrivateVaultCustodyRotationSetFaultHookForTesting(
    AncPrivateVaultCustodyRotationFaultHook _Nullable hook);
#endif

NS_ASSUME_NONNULL_END
