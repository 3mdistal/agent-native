#import <Foundation/Foundation.h>

#import "PrivateVaultControlLog.h"

NS_ASSUME_NONNULL_BEGIN

typedef NS_ENUM(NSInteger, AncPrivateVaultBrokerReplacementBuilderStatus) {
  AncPrivateVaultBrokerReplacementBuilderStatusOK = 0,
  AncPrivateVaultBrokerReplacementBuilderStatusInvalidArgument,
  AncPrivateVaultBrokerReplacementBuilderStatusIssuerRejected,
  AncPrivateVaultBrokerReplacementBuilderStatusBrokerRejected,
  AncPrivateVaultBrokerReplacementBuilderStatusDrainRejected,
  AncPrivateVaultBrokerReplacementBuilderStatusCryptoFailed,
  AncPrivateVaultBrokerReplacementBuilderStatusEncodingFailed,
  AncPrivateVaultBrokerReplacementBuilderStatusVerificationFailed,
};

@interface AncPrivateVaultPreparedBrokerReplacement : NSObject
@property(nonatomic, readonly) NSData *signedEntry;
@property(nonatomic, readonly) NSData *recoveryWrap;
@property(nonatomic, readonly) NSData *transcriptDigest;
@property(nonatomic, readonly) NSData *drainAttestationHash;
@property(nonatomic, readonly) AncPrivateVaultControlLogState *nextState;
- (instancetype)init NS_UNAVAILABLE;
+ (instancetype)new NS_UNAVAILABLE;
@end

/* Creates the canonical endpoint-authenticated proof that the old broker's
 * durable queue generation was fully drained. The signing seed must belong to
 * an active attended endpoint in currentState. */
FOUNDATION_EXPORT NSData *_Nullable AncPrivateVaultCreateBrokerDrainAttestation(
    AncPrivateVaultControlLogState *currentState, NSData *oldBrokerEndpointId,
    NSData *candidateBrokerEndpointId, NSData *candidateSigningPublicKey,
    NSData *candidateKeyAgreementPublicKey, NSData *candidateEnrollmentRef,
    NSData *envelopeId, uint64_t createdAtSeconds, uint64_t drainGeneration,
    uint64_t drainedJobCount, NSData *drainDigest,
    uint64_t outstandingJobCount,
    const uint8_t *_Nonnull issuerSigningSeed,
    AncPrivateVaultBrokerReplacementBuilderStatus *_Nullable status);

/* Returns the exact 128-bit ceremony identifier committed by the control log.
 * It is a domain-separated digest of the complete signed drain attestation. */
FOUNDATION_EXPORT NSData *_Nullable
AncPrivateVaultBrokerReplacementCeremonyId(NSData *drainAttestation);

/* Builds and independently replays exactly one broker_replacement edge. The
 * drain proof is verified before any artifact is emitted. The old broker is
 * tombstoned, one healthy unattended broker is admitted, and the EEK/recovery
 * wrap rotate together. */
FOUNDATION_EXPORT AncPrivateVaultPreparedBrokerReplacement *_Nullable
AncPrivateVaultBuildBrokerReplacement(
    AncPrivateVaultControlLogState *currentState, NSData *oldBrokerEndpointId,
    NSData *candidateBrokerEndpointId, NSData *candidateSigningPublicKey,
    NSData *candidateKeyAgreementPublicKey, NSData *candidateEnrollmentRef,
    NSData *drainAttestation, NSData *wrapEnvelopeId, NSData *entryEnvelopeId,
    NSData *wrapNonce, uint64_t trustedNowSeconds,
    const uint8_t *_Nonnull pendingEpochKey,
    const uint8_t *_Nonnull issuerSigningSeed,
    const uint8_t *_Nonnull issuerAgreementSeed,
    AncPrivateVaultBrokerReplacementBuilderStatus *_Nullable status);

NS_ASSUME_NONNULL_END
