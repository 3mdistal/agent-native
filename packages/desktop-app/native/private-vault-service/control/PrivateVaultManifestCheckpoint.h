#import <Foundation/Foundation.h>

#import "PrivateVaultControlLog.h"
#import "PrivateVaultEnrollmentAuthorization.h"

NS_ASSUME_NONNULL_BEGIN

typedef NS_ENUM(NSInteger, AncPrivateVaultManifestCheckpointStatus) {
  AncPrivateVaultManifestCheckpointStatusOK = 0,
  AncPrivateVaultManifestCheckpointStatusInvalid = 1,
  AncPrivateVaultManifestCheckpointStatusUnauthorized = 2,
  AncPrivateVaultManifestCheckpointStatusExpired = 3,
  AncPrivateVaultManifestCheckpointStatusSignature = 4,
  AncPrivateVaultManifestCheckpointStatusBinding = 5,
  AncPrivateVaultManifestCheckpointStatusCrypto = 6,
};

@interface AncPrivateVaultManifestCheckpointBundle : NSObject
@property(nonatomic, readonly) NSData *encodedCheckpoint;
@property(nonatomic, readonly) NSData *encodedAuthorization;
@property(nonatomic, readonly) NSData *checkpointDigest;
- (instancetype)init NS_UNAVAILABLE;
+ (instancetype)new NS_UNAVAILABLE;
@end

/* Builds the Core anc/enrollment-manifest/v1 companion envelopes. The
 * enrollment result must have been minted by the complete native ceremony
 * verifier; its protected registry evidence is used rather than trusting a
 * caller-provided authorizer claim. Seeds are borrowed for this call only. */
FOUNDATION_EXPORT AncPrivateVaultManifestCheckpointBundle *_Nullable
AncPrivateVaultBuildManifestCheckpoint(
    AncPrivateVaultEnrollmentAuthorizationResult *enrollment,
    AncPrivateVaultControlLogState *authenticatedState, NSData *manifestObjectId,
    NSData *revisionId, uint64_t generation, NSData *ciphertextHash,
    NSData *checkpointEnvelopeId, NSData *bindingEnvelopeId,
    uint64_t checkpointCreatedAtSeconds, uint64_t bindingCreatedAtSeconds,
    uint64_t bindingExpiresAtSeconds, const uint8_t *_Nonnull signingSeed,
    AncPrivateVaultManifestCheckpointStatus *_Nullable status);

/* Authenticates an opaque bundle against the locally opened revision metadata
 * and the present authenticated control state. This is deliberately metadata
 * only: callers never hand a seed or document plaintext to this primitive. */
FOUNDATION_EXPORT AncPrivateVaultManifestCheckpointBundle *_Nullable
AncPrivateVaultVerifyManifestCheckpoint(
    NSData *encodedEnrollmentAuthorization, NSData *encodedCheckpoint,
    NSData *encodedBinding, AncPrivateVaultControlLogState *authenticatedState,
    NSData *manifestObjectId, NSData *revisionId, uint64_t generation,
    NSData *ciphertextHash, uint64_t nowSeconds,
    AncPrivateVaultManifestCheckpointStatus *_Nullable status);

NS_ASSUME_NONNULL_END
