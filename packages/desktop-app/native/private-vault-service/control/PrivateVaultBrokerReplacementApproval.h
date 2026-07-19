#import <Foundation/Foundation.h>

#import "PrivateVaultControlLog.h"
#import "PrivateVaultEnrollmentSasReceipt.h"

NS_ASSUME_NONNULL_BEGIN

typedef NS_ENUM(NSInteger, AncPrivateVaultBrokerReplacementApprovalStatus) {
  AncPrivateVaultBrokerReplacementApprovalStatusOK = 0,
  AncPrivateVaultBrokerReplacementApprovalStatusInvalid = 1,
  AncPrivateVaultBrokerReplacementApprovalStatusConflict = 2,
  AncPrivateVaultBrokerReplacementApprovalStatusExpired = 3,
  AncPrivateVaultBrokerReplacementApprovalStatusInvalidSignature = 4,
  AncPrivateVaultBrokerReplacementApprovalStatusCryptoFailed = 5,
  AncPrivateVaultBrokerReplacementApprovalStatusEncodingFailed = 6,
};

@interface AncPrivateVaultBrokerReplacementApproval : NSObject
@property(nonatomic, readonly) NSData *encodedApproval;
@property(nonatomic, readonly) NSData *freezeId;
@property(nonatomic, readonly) NSData *envelopeId;
@property(nonatomic, readonly) NSData *issuerEndpointId;
@property(nonatomic, readonly) NSData *oldBrokerEndpointId;
@property(nonatomic, readonly) NSData *candidateBrokerEndpointId;
@property(nonatomic, readonly) NSData *candidateSigningPublicKey;
@property(nonatomic, readonly) NSData *candidateKeyAgreementPublicKey;
@property(nonatomic, readonly) NSData *candidateEnrollmentRef;
@property(nonatomic, readonly) NSData *offerHash;
@property(nonatomic, readonly) NSData *challengeHash;
@property(nonatomic, readonly) NSData *sasDecisionHash;
@property(nonatomic, readonly) NSData *drainId;
@property(nonatomic, readonly) uint64_t drainGeneration;
@property(nonatomic, readonly) uint64_t createdAtSeconds;
@property(nonatomic, readonly) uint64_t deadlineAtSeconds;
@property(nonatomic, readonly) uint64_t baseSequence;
@property(nonatomic, readonly) NSData *baseHeadHash;
@property(nonatomic, readonly) NSData *baseMembershipHash;
@property(nonatomic, readonly) uint64_t baseEpoch;
- (instancetype)init NS_UNAVAILABLE;
+ (instancetype)new NS_UNAVAILABLE;
@end

FOUNDATION_EXPORT AncPrivateVaultEnrollmentSasReceipt
    *_Nullable AncPrivateVaultBrokerReplacementSasDecisionVerify(
        NSData *encodedOffer, NSData *encodedChallenge,
        NSData *encodedSasDecision,
        AncPrivateVaultControlLogState *authenticatedState,
        NSData *oldBrokerEndpointId,
        uint64_t authenticatedHeadSignedAtSeconds, uint64_t nowSeconds,
        AncPrivateVaultBrokerReplacementApprovalStatus *_Nullable status);

FOUNDATION_EXPORT AncPrivateVaultBrokerReplacementApproval
    *_Nullable AncPrivateVaultBuildBrokerReplacementApproval(
        AncPrivateVaultControlLogState *authenticatedState,
        NSData *encodedOffer, NSData *encodedChallenge,
        NSData *encodedSasDecision, NSData *oldBrokerEndpointId,
        uint64_t authenticatedHeadSignedAtSeconds, uint64_t nowSeconds,
        uint64_t deadlineAtSeconds,
        const uint8_t *_Nonnull issuerSigningSeed,
        AncPrivateVaultBrokerReplacementApprovalStatus *_Nullable status);

FOUNDATION_EXPORT AncPrivateVaultBrokerReplacementApproval
    *_Nullable AncPrivateVaultVerifyBrokerReplacementApproval(
        NSData *encodedApproval,
        AncPrivateVaultControlLogState *authenticatedState,
        NSData *oldBrokerEndpointId, NSData *candidateBrokerEndpointId,
        NSData *candidateSigningPublicKey,
        NSData *candidateKeyAgreementPublicKey,
        NSData *candidateEnrollmentRef, NSData *offerHash,
        NSData *challengeHash, NSData *sasDecisionHash, NSData *drainId,
        uint64_t drainGeneration, uint64_t deadlineAtSeconds,
        uint64_t expectedCreatedAtSeconds, uint64_t nowSeconds,
        AncPrivateVaultBrokerReplacementApprovalStatus *_Nullable status);

FOUNDATION_EXPORT NSData *_Nullable
AncPrivateVaultBrokerReplacementApprovalFreezeId(NSData *encodedApproval);

NS_ASSUME_NONNULL_END
