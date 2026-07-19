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
    const uint8_t *_Nonnull pendingEpochKey, uint64_t now,
    AncPrivateVaultRotationEvidenceStatus *_Nullable status);

NS_ASSUME_NONNULL_END
