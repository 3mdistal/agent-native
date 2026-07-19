#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

typedef NS_ENUM(NSInteger, AncPrivateVaultRotationEvidenceStatus) {
  AncPrivateVaultRotationEvidenceStatusOK = 0,
  AncPrivateVaultRotationEvidenceStatusInvalid = 1,
  AncPrivateVaultRotationEvidenceStatusBinding = 2,
  AncPrivateVaultRotationEvidenceStatusSignature = 3,
  AncPrivateVaultRotationEvidenceStatusCrypto = 4,
};

@interface AncPrivateVaultRotationEvidenceRecipient : NSObject
@property(nonatomic, readonly) NSData *endpointId;
@property(nonatomic, readonly) NSData *signingPublicKey;
@property(nonatomic, readonly) NSData *keyAgreementPublicKey;
@property(nonatomic, readonly) NSData *eekWrapHash;
@property(nonatomic, readonly) NSData *encodedOffer;
- (nullable instancetype)initWithEndpointId:(NSData *)endpointId
                           signingPublicKey:(NSData *)signingPublicKey
                      keyAgreementPublicKey:(NSData *)keyAgreementPublicKey
                                eekWrapHash:(NSData *)eekWrapHash
                               encodedOffer:(NSData *)encodedOffer;
@end

@interface AncPrivateVaultRotationLiveRevision : NSObject
@property(nonatomic, readonly) NSData *objectId;
@property(nonatomic, readonly) uint64_t revision;
@property(nonatomic, readonly) NSData *priorRevisionId;
@property(nonatomic, readonly) NSData *rotatedRevisionId;
- (nullable instancetype)initWithObjectId:(NSData *)objectId
                                 revision:(uint64_t)revision
                          priorRevisionId:(NSData *)priorRevisionId
                        rotatedRevisionId:(NSData *)rotatedRevisionId;
@end

/* Opaque component-verification results. Neither type establishes rotation
 * completion. Custody evidence can only be produced from verified preparation
 * evidence, preventing acknowledgement/destruction checks from being composed
 * against an independently supplied checkpoint or roster. */
@interface AncPrivateVaultRotationPreparationEvidence : NSObject
- (instancetype)init NS_UNAVAILABLE;
@end

@interface AncPrivateVaultRotationCustodyEvidence : NSObject
- (instancetype)init NS_UNAVAILABLE;
@end

@interface AncPrivateVaultRotationAcknowledgementEvidence : NSObject
- (instancetype)init NS_UNAVAILABLE;
@end

@interface AncPrivateVaultRotationDestructionEvidence : NSObject
- (instancetype)init NS_UNAVAILABLE;
@end

FOUNDATION_EXPORT NSData *_Nullable AncPrivateVaultRotationEvidenceBuildCheckpoint(
    NSData *vaultId, uint64_t createdAt, NSData *envelopeId,
    NSData *ceremonyId, uint64_t baseSequence, NSData *baseHeadHash,
    uint64_t baseEpoch, uint64_t targetEpoch, NSData *manifestObjectId,
    NSData *revisionId, uint64_t generation, NSData *ciphertextHash,
    uint64_t liveObjectCount, uint64_t liveRevisionCount,
    NSData *liveRevisionSetHash, NSData *recipientSetHash,
    NSData *controlEntryHash, NSData *signerEndpointId,
    NSData *removedEndpointId, const uint8_t *_Nonnull signingSeed,
    AncPrivateVaultRotationEvidenceStatus *_Nullable status);

FOUNDATION_EXPORT NSData *_Nullable AncPrivateVaultRotationEvidenceBuildOffer(
    NSData *vaultId, uint64_t createdAt, NSData *envelopeId,
    NSData *ceremonyId, NSData *checkpointHash, NSData *eekWrapHash,
    NSData *recipientEndpointId, NSData *issuerEndpointId,
    uint64_t targetEpoch, uint64_t expiresAt,
    const uint8_t *_Nonnull issuerSigningSeed,
    AncPrivateVaultRotationEvidenceStatus *_Nullable status);

FOUNDATION_EXPORT NSData *_Nullable
AncPrivateVaultRotationEvidenceBuildAcknowledgement(
    NSData *vaultId, uint64_t createdAt, NSData *envelopeId,
    NSData *ceremonyId, NSData *checkpointHash, NSData *eekWrapHash,
    NSData *offerHash, NSData *recipientEndpointId, uint64_t targetEpoch,
    const uint8_t *_Nonnull recipientSigningSeed,
    const uint8_t *_Nonnull pendingEpochKey,
    AncPrivateVaultRotationEvidenceStatus *_Nullable status);

FOUNDATION_EXPORT NSData *_Nullable
AncPrivateVaultRotationEvidenceBuildDestruction(
    NSData *vaultId, uint64_t createdAt, NSData *envelopeId,
    NSData *ceremonyId, NSData *checkpointHash, NSData *controlEntryHash,
    NSData *endpointId, uint64_t destroyedEpoch, uint64_t activatedEpoch,
    uint64_t custodyGeneration,
    const uint8_t *_Nonnull endpointSigningSeed,
    AncPrivateVaultRotationEvidenceStatus *_Nullable status);

FOUNDATION_EXPORT NSData *_Nullable AncPrivateVaultRotationEvidenceBuildCompletion(
    NSData *vaultId, uint64_t createdAt, NSData *envelopeId,
    NSData *ceremonyId, NSData *checkpointHash, NSData *controlEntryHash,
    NSData *hostedReceiptHash, NSData *signerEndpointId,
    uint64_t committedSequence, NSData *committedHeadHash,
    NSData *recipientSetHash, const uint8_t *_Nonnull signerSigningSeed,
    AncPrivateVaultRotationEvidenceStatus *_Nullable status);

FOUNDATION_EXPORT NSData *_Nullable
AncPrivateVaultRotationEvidenceHashCheckpoint(NSData *encodedCheckpoint,
                                              NSData *expectedVaultId);
FOUNDATION_EXPORT NSData *_Nullable
AncPrivateVaultRotationEvidenceHashOffer(NSData *encodedOffer,
                                         NSData *expectedVaultId);
FOUNDATION_EXPORT NSData *_Nullable
AncPrivateVaultRotationEvidenceHashHostedReceipt(NSData *encodedReceipt);
FOUNDATION_EXPORT NSData *_Nullable AncPrivateVaultRotationEvidenceHashRecipientSet(
    NSArray<AncPrivateVaultRotationEvidenceRecipient *> *recipients);
FOUNDATION_EXPORT NSData *_Nullable
AncPrivateVaultRotationEvidenceHashLiveRevisionSet(
    NSArray<AncPrivateVaultRotationLiveRevision *> *liveRevisions);

/* Component verification only; success does not establish rotation
 * completion or authorize control commit/publication. */
FOUNDATION_EXPORT AncPrivateVaultRotationPreparationEvidence *_Nullable
AncPrivateVaultVerifyRotationPreparationEvidence(
    NSData *encodedCheckpoint, NSData *expectedVaultId,
    NSData *expectedSignerEndpointId, NSData *signerSigningPublicKey,
    NSArray<AncPrivateVaultRotationEvidenceRecipient *> *expectedRecipients,
    NSArray<AncPrivateVaultRotationLiveRevision *> *liveRevisions,
    uint64_t now, AncPrivateVaultRotationEvidenceStatus *_Nullable status);

/* Component verification only; success proves exact acknowledgement and old
 * epoch destruction coverage for an already verified preparation. It does not
 * establish rotation completion or authorize publication. */
FOUNDATION_EXPORT AncPrivateVaultRotationCustodyEvidence *_Nullable
AncPrivateVaultVerifyRotationCustodyEvidence(
    AncPrivateVaultRotationPreparationEvidence *preparation,
    NSArray<NSData *> *encodedAcknowledgements,
    NSArray<NSData *> *encodedDestructions,
    const uint8_t *_Nonnull pendingEpochKey, uint64_t now,
    AncPrivateVaultRotationEvidenceStatus *_Nullable status);

/* Staged component checks for crash-safe coordinators. Acknowledgements require
 * the pending EEK and are verified before promotion. Destructions are verified
 * independently after the exact control edge has been replayed and the old EEK
 * has been destroyed. Neither result authorizes hosted append on its own. */
FOUNDATION_EXPORT AncPrivateVaultRotationAcknowledgementEvidence *_Nullable
AncPrivateVaultVerifyRotationAcknowledgementEvidence(
    AncPrivateVaultRotationPreparationEvidence *preparation,
    NSArray<NSData *> *encodedAcknowledgements,
    const uint8_t *_Nonnull pendingEpochKey, uint64_t now,
    AncPrivateVaultRotationEvidenceStatus *_Nullable status);

FOUNDATION_EXPORT AncPrivateVaultRotationDestructionEvidence *_Nullable
AncPrivateVaultVerifyRotationDestructionEvidence(
    AncPrivateVaultRotationPreparationEvidence *preparation,
    NSArray<NSData *> *encodedDestructions, uint64_t now,
    AncPrivateVaultRotationEvidenceStatus *_Nullable status);

/* Sole native success predicate for a completed attended rotation. Secret
 * inputs are borrowed for this call only; derived keys, private keys, MAC
 * preimages, and signatures are zeroized before return. Evidence outputs are
 * public, canonical, and bounded to the frozen Core limits. */
FOUNDATION_EXPORT BOOL AncPrivateVaultVerifyCompletedRotationEvidence(
    NSData *encodedCheckpoint, NSArray<NSData *> *encodedAcknowledgements,
    NSArray<NSData *> *encodedDestructions, NSData *encodedCompletion,
    NSData *encodedHostedReceipt, NSString *expectedHostedEntryId,
    NSString *expectedHostedVaultId, NSData *expectedRecoveryWrapHash,
    uint64_t expectedRecoveryWrapByteLength, NSData *expectedVaultId,
    NSData *expectedSignerEndpointId, NSData *signerSigningPublicKey,
    NSArray<AncPrivateVaultRotationEvidenceRecipient *> *expectedRecipients,
    NSArray<AncPrivateVaultRotationLiveRevision *> *liveRevisions,
    const uint8_t *_Nonnull pendingEpochKey, uint64_t now,
    AncPrivateVaultRotationEvidenceStatus *_Nullable status);

NS_ASSUME_NONNULL_END
