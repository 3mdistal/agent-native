#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

enum {
  ANC_PV_ROTATION_EVIDENCE_STORE_ID_BYTES = 16,
  ANC_PV_ROTATION_EVIDENCE_STORE_DIGEST_BYTES = 32,
  ANC_PV_ROTATION_EVIDENCE_STORE_PUBLIC_KEY_BYTES = 32,
  ANC_PV_ROTATION_EVIDENCE_STORE_MAX_RECIPIENTS = 64,
  ANC_PV_ROTATION_EVIDENCE_STORE_MAX_LIVE_REVISIONS = 10000,
  ANC_PV_ROTATION_EVIDENCE_STORE_MAX_ARTIFACT_BYTES = 1024,
};

typedef NS_ENUM(NSInteger, AncPrivateVaultRotationEvidenceStoreStatus) {
  AncPrivateVaultRotationEvidenceStoreStatusOK = 0,
  AncPrivateVaultRotationEvidenceStoreStatusNotFound = 1,
  AncPrivateVaultRotationEvidenceStoreStatusInvalid = 2,
  AncPrivateVaultRotationEvidenceStoreStatusConflict = 3,
  AncPrivateVaultRotationEvidenceStoreStatusCorrupt = 4,
  AncPrivateVaultRotationEvidenceStoreStatusStorageFailed = 5,
};

typedef NS_ENUM(NSInteger, AncPrivateVaultRotationEvidenceStorePhase) {
  AncPrivateVaultRotationEvidenceStorePhaseAcknowledgements = 1,
  AncPrivateVaultRotationEvidenceStorePhaseDestructions = 2,
  AncPrivateVaultRotationEvidenceStorePhaseComplete = 3,
};

/* Public identity and exact public ceremony artifacts. The store does not
 * interpret or verify offer or EEK-wrap proofs. */
@interface AncPrivateVaultRotationEvidenceStoreRecipient : NSObject
@property(nonatomic, readonly) NSData *endpointId;
@property(nonatomic, readonly) NSData *signingPublicKey;
@property(nonatomic, readonly) NSData *keyAgreementPublicKey;
@property(nonatomic, readonly) NSData *encodedOffer;
@property(nonatomic, readonly) NSData *encodedEEKWrap;
- (nullable instancetype)initWithEndpointId:(NSData *)endpointId
                           signingPublicKey:(NSData *)signingPublicKey
                      keyAgreementPublicKey:(NSData *)keyAgreementPublicKey
                               encodedOffer:(NSData *)encodedOffer
                             encodedEEKWrap:(NSData *)encodedEEKWrap
    NS_DESIGNATED_INITIALIZER;
- (instancetype)init NS_UNAVAILABLE;
@end

/* Exact public revision coordinate and its before/after revision identities. */
@interface AncPrivateVaultRotationEvidenceStoreLiveRevision : NSObject
@property(nonatomic, readonly) NSData *objectId;
@property(nonatomic, readonly) uint64_t revision;
@property(nonatomic, readonly) NSData *priorRevisionId;
@property(nonatomic, readonly) NSData *rotatedRevisionId;
- (nullable instancetype)initWithObjectId:(NSData *)objectId
                                 revision:(uint64_t)revision
                          priorRevisionId:(NSData *)priorRevisionId
                        rotatedRevisionId:(NSData *)rotatedRevisionId
    NS_DESIGNATED_INITIALIZER;
- (instancetype)init NS_UNAVAILABLE;
@end

/* An immutable compare-and-swap token and complete public snapshot. */
@interface AncPrivateVaultRotationEvidenceStoreCheckpoint : NSObject
@property(nonatomic, readonly) NSData *vaultId;
@property(nonatomic, readonly) NSData *ceremonyId;
@property(nonatomic, readonly) NSData *targetEndpointId;
@property(nonatomic, readonly) uint64_t preparationFenceGeneration;
@property(nonatomic, readonly) NSData *preparationRecordDigest;
@property(nonatomic, readonly) uint64_t generation;
@property(nonatomic, readonly) NSData *contentDigest;
@property(nonatomic, readonly) NSData *encodedCheckpoint;
@property(nonatomic, readonly)
    NSArray<AncPrivateVaultRotationEvidenceStoreRecipient *> *recipients;
@property(nonatomic, readonly)
    NSArray<AncPrivateVaultRotationEvidenceStoreLiveRevision *> *liveRevisions;
@property(nonatomic, readonly) NSDictionary<NSData *, NSData *> *acknowledgements;
@property(nonatomic, readonly) NSDictionary<NSData *, NSData *> *destructions;
@property(nonatomic, readonly) AncPrivateVaultRotationEvidenceStorePhase phase;
@end

/*
 * Durable, secret-free rotation evidence. stateRootURL is an already-approved
 * owner-only 0700 trust anchor. There is at most one active ceremony per vault.
 * Active ledgers are never age-purged; cleanup requires an exact complete
 * checkpoint returned by this store.
 */
@interface AncPrivateVaultRotationEvidenceStore : NSObject
- (instancetype)initWithStateRootURL:(NSURL *)stateRootURL
    NS_DESIGNATED_INITIALIZER;
- (instancetype)init NS_UNAVAILABLE;

- (AncPrivateVaultRotationEvidenceStoreStatus)
    createVaultId:(NSData *)vaultId
       ceremonyId:(NSData *)ceremonyId
  targetEndpointId:(NSData *)targetEndpointId
preparationFenceGeneration:(uint64_t)preparationFenceGeneration
preparationRecordDigest:(NSData *)preparationRecordDigest
 encodedCheckpoint:(NSData *)encodedCheckpoint
         recipients:
             (NSArray<AncPrivateVaultRotationEvidenceStoreRecipient *> *)recipients
      liveRevisions:
          (NSArray<AncPrivateVaultRotationEvidenceStoreLiveRevision *> *)
              liveRevisions
         checkpoint:
             (AncPrivateVaultRotationEvidenceStoreCheckpoint *_Nullable *_Nullable)
                 checkpoint;

- (AncPrivateVaultRotationEvidenceStoreStatus)
    readVaultId:(NSData *)vaultId
      checkpoint:
          (AncPrivateVaultRotationEvidenceStoreCheckpoint *_Nullable *_Nullable)
              checkpoint;

/* Exact retries are byte-idempotent. New bytes for a recorded recipient,
 * recipients outside the frozen roster, stale non-idempotent CAS tokens, and
 * writes that skip the current phase fail with Conflict. */
- (AncPrivateVaultRotationEvidenceStoreStatus)
    storeAcknowledgement:(NSData *)encodedAcknowledgement
              endpointId:(NSData *)endpointId
                 vaultId:(NSData *)vaultId
       expectedCheckpoint:
           (AncPrivateVaultRotationEvidenceStoreCheckpoint *)expectedCheckpoint
               checkpoint:
                   (AncPrivateVaultRotationEvidenceStoreCheckpoint *_Nullable
                        *_Nullable)checkpoint;

- (AncPrivateVaultRotationEvidenceStoreStatus)
    storeDestruction:(NSData *)encodedDestruction
           endpointId:(NSData *)endpointId
              vaultId:(NSData *)vaultId
    expectedCheckpoint:
        (AncPrivateVaultRotationEvidenceStoreCheckpoint *)expectedCheckpoint
            checkpoint:
                (AncPrivateVaultRotationEvidenceStoreCheckpoint *_Nullable
                     *_Nullable)checkpoint;

/* The file is removed only when expectedCheckpoint exactly identifies the
 * live, complete ledger and all frozen bindings still match. */
- (AncPrivateVaultRotationEvidenceStoreStatus)
    deleteTerminalVaultId:(NSData *)vaultId
       expectedCheckpoint:
           (AncPrivateVaultRotationEvidenceStoreCheckpoint *)expectedCheckpoint;
@end

typedef NS_ENUM(NSInteger, AncPrivateVaultRotationEvidenceStoreFaultPoint) {
  AncPrivateVaultRotationEvidenceStoreFaultAfterTemporaryFsync = 1,
  AncPrivateVaultRotationEvidenceStoreFaultBeforeRename = 2,
  AncPrivateVaultRotationEvidenceStoreFaultAfterRename = 3,
  AncPrivateVaultRotationEvidenceStoreFaultBeforeReadback = 4,
  AncPrivateVaultRotationEvidenceStoreFaultBeforeUnlink = 5,
};

#if ANC_PRIVATE_VAULT_TESTING
typedef BOOL (^AncPrivateVaultRotationEvidenceStoreFaultHook)(
    AncPrivateVaultRotationEvidenceStoreFaultPoint point);
FOUNDATION_EXPORT void
AncPrivateVaultRotationEvidenceStoreSetFaultHookForTesting(
    AncPrivateVaultRotationEvidenceStoreFaultHook _Nullable hook);
#endif

NS_ASSUME_NONNULL_END
