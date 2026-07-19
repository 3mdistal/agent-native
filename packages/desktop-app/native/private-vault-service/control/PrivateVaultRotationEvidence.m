#import "PrivateVaultRotationEvidence.h"

#import "PrivateVaultAncCanonical.h"
#import "PrivateVaultCrypto.h"

static const uint64_t kMaxSafe = UINT64_C(9007199254740991);
static const NSUInteger kEvidenceLimit = 1024;
static const NSUInteger kRecipientLimit = 64;
static const uint64_t kClockSkew = 60;
static const uint8_t kCheckpointDomain[] =
    "anc/rotation/v1/rotation-manifest-checkpoint";
static const uint8_t kCheckpointHashDomain[] =
    "anc/rotation/v1/rotation-manifest-checkpoint-hash";
static const uint8_t kOfferDomain[] =
    "anc/rotation/v1/rotation-recipient-offer";
static const uint8_t kOfferHashDomain[] =
    "anc/rotation/v1/rotation-recipient-offer-hash";
static const uint8_t kAcknowledgementDomain[] =
    "anc/rotation/v1/rotation-recipient-acknowledgement";
static const uint8_t kAcknowledgementMacDomain[] =
    "anc/rotation/v1/rotation-recipient-acknowledgement-mac";
static const uint8_t kPossessionKeyDomain[] =
    "anc/rotation/v1/possession-key";
static const uint8_t kDestructionDomain[] =
    "anc/rotation/v1/rotation-epoch-destruction-attestation";
static const uint8_t kCompletionDomain[] =
    "anc/rotation/v1/rotation-control-commit-attestation";
static const uint8_t kHostedReceiptHashDomain[] =
    "anc/rotation/v1/rotation-hosted-receipt-hash";
static const uint8_t kRecipientSetHashDomain[] =
    "anc/rotation/v1/rotation-recipient-set-hash";
static const uint8_t kLiveRevisionSetHashDomain[] =
    "anc/rotation/v1/rotation-live-revision-set-hash";

@interface AncPrivateVaultRotationEvidenceRecipient ()
@property(nonatomic, readwrite) NSData *endpointId;
@property(nonatomic, readwrite) NSData *signingPublicKey;
@property(nonatomic, readwrite) NSData *keyAgreementPublicKey;
@property(nonatomic, readwrite) NSData *eekWrapHash;
@property(nonatomic, readwrite) NSData *encodedOffer;
@end

@implementation AncPrivateVaultRotationEvidenceRecipient
- (instancetype)initWithEndpointId:(NSData *)endpointId
                  signingPublicKey:(NSData *)signingPublicKey
             keyAgreementPublicKey:(NSData *)keyAgreementPublicKey
                       eekWrapHash:(NSData *)eekWrapHash
                      encodedOffer:(NSData *)encodedOffer {
  if (![endpointId isKindOfClass:NSData.class] || endpointId.length != 16 ||
      ![signingPublicKey isKindOfClass:NSData.class] ||
      signingPublicKey.length != 32 ||
      ![keyAgreementPublicKey isKindOfClass:NSData.class] ||
      keyAgreementPublicKey.length != 32 ||
      ![eekWrapHash isKindOfClass:NSData.class] || eekWrapHash.length != 32 ||
      ![encodedOffer isKindOfClass:NSData.class] || encodedOffer.length < 1 ||
      encodedOffer.length > kEvidenceLimit)
    return nil;
  if ((self = [super init])) {
    _endpointId = [endpointId copy];
    _signingPublicKey = [signingPublicKey copy];
    _keyAgreementPublicKey = [keyAgreementPublicKey copy];
    _eekWrapHash = [eekWrapHash copy];
    _encodedOffer = [encodedOffer copy];
  }
  return self;
}
@end

@interface AncPrivateVaultRotationLiveRevision ()
@property(nonatomic, readwrite) NSData *objectId;
@property(nonatomic, readwrite) uint64_t revision;
@property(nonatomic, readwrite) NSData *priorRevisionId;
@property(nonatomic, readwrite) NSData *rotatedRevisionId;
@end

@implementation AncPrivateVaultRotationLiveRevision
- (instancetype)initWithObjectId:(NSData *)objectId
                        revision:(uint64_t)revision
                 priorRevisionId:(NSData *)priorRevisionId
               rotatedRevisionId:(NSData *)rotatedRevisionId {
  if (![objectId isKindOfClass:NSData.class] || objectId.length != 16 ||
      revision < 1 || revision > kMaxSafe ||
      ![priorRevisionId isKindOfClass:NSData.class] ||
      priorRevisionId.length != 32 ||
      ![rotatedRevisionId isKindOfClass:NSData.class] ||
      rotatedRevisionId.length != 32)
    return nil;
  if ((self = [super init])) {
    _objectId = [objectId copy];
    _revision = revision;
    _priorRevisionId = [priorRevisionId copy];
    _rotatedRevisionId = [rotatedRevisionId copy];
  }
  return self;
}
@end

@interface AncPrivateVaultRotationPreparationEvidence ()
@property(nonatomic, readwrite) NSData *encodedCheckpoint;
@property(nonatomic, readwrite) NSData *expectedVaultId;
@property(nonatomic, readwrite) NSData *signerSigningPublicKey;
@property(nonatomic, readwrite) NSArray<AncPrivateVaultRotationEvidenceRecipient *> *recipients;
@property(nonatomic, readwrite) NSDictionary<NSData *, AncPrivateVaultRotationEvidenceRecipient *> *recipientsById;
@property(nonatomic, readwrite) NSDictionary<NSData *, NSDictionary *> *offersById;
@property(nonatomic, readwrite) NSDictionary<NSData *, NSData *> *offerHashesById;
@property(nonatomic, readwrite) NSDictionary *checkpoint;
@property(nonatomic, readwrite) NSData *checkpointHash;
- (instancetype)initPrivate;
@end

@implementation AncPrivateVaultRotationPreparationEvidence
- (instancetype)initPrivate { return [super init]; }
@end

@interface AncPrivateVaultRotationCustodyEvidence ()
@property(nonatomic, readwrite) AncPrivateVaultRotationPreparationEvidence *preparation;
@property(nonatomic, readwrite) uint64_t notBefore;
- (instancetype)initPrivate;
@end

@implementation AncPrivateVaultRotationCustodyEvidence
- (instancetype)initPrivate { return [super init]; }
@end

static void SetStatus(AncPrivateVaultRotationEvidenceStatus *status,
                      AncPrivateVaultRotationEvidenceStatus value) {
  if (status != NULL)
    *status = value;
}

static BOOL Exact(NSData *value, NSUInteger length) {
  return [value isKindOfClass:NSData.class] && value.length == length;
}

static BOOL Same(NSData *left, NSData *right) {
  return Exact(left, right.length) && right.length > 0 &&
         anc_pv_memcmp(left.bytes, right.bytes, right.length) ==
             ANC_PV_CRYPTO_OK;
}

static BOOL Safe(uint64_t value) { return value <= kMaxSafe; }
static BOOL Positive(uint64_t value) { return value > 0 && Safe(value); }

static AncPrivateVaultCanonicalValue *Bytes(NSData *value) {
  return [AncPrivateVaultCanonicalValue bytes:value];
}

static AncPrivateVaultCanonicalValue *Text(NSString *value) {
  return [AncPrivateVaultCanonicalValue text:value];
}

static AncPrivateVaultCanonicalValue *Integer(uint64_t value) {
  return Safe(value)
             ? [AncPrivateVaultCanonicalValue integer:(int64_t)value]
             : nil;
}

static NSData *Encode(NSDictionary<NSNumber *, AncPrivateVaultCanonicalValue *> *map) {
  if (map == nil)
    return nil;
  AncPrivateVaultCanonicalStatus status;
  NSData *encoded = AncPrivateVaultCanonicalEncode(
      [AncPrivateVaultCanonicalValue map:map], &status);
  return status == AncPrivateVaultCanonicalStatusOK ? encoded : nil;
}

static NSDictionary<NSNumber *, AncPrivateVaultCanonicalValue *> *
Decode(NSData *encoded, NSUInteger maximum) {
  AncPrivateVaultCanonicalStatus status;
  AncPrivateVaultCanonicalValue *root =
      AncPrivateVaultCanonicalDecode(encoded, maximum, &status);
  return status == AncPrivateVaultCanonicalStatusOK &&
                 root.type == AncPrivateVaultCanonicalTypeMap
             ? root.mapValue
             : nil;
}

static AncPrivateVaultCanonicalValue *
Field(NSDictionary<NSNumber *, AncPrivateVaultCanonicalValue *> *map,
      NSNumber *key, AncPrivateVaultCanonicalType type) {
  AncPrivateVaultCanonicalValue *value = map[key];
  return value.type == type ? value : nil;
}

static BOOL Keys(NSDictionary<NSNumber *, id> *map,
                 NSArray<NSNumber *> *expected) {
  return map.count == expected.count &&
         [[NSSet setWithArray:map.allKeys]
             isEqualToSet:[NSSet setWithArray:expected]];
}

static NSData *DomainHash(const uint8_t *domain, size_t domainLength,
                          NSData *encoded) {
  if (![encoded isKindOfClass:NSData.class])
    return nil;
  uint8_t output[32] = {0};
  BOOL okay = anc_pv_blake2b_256_two_part(
                  output, domain, domainLength, encoded.bytes, encoded.length) ==
      ANC_PV_CRYPTO_OK;
  NSData *result = okay ? [NSData dataWithBytes:output length:32] : nil;
  anc_pv_zeroize(output, sizeof output);
  return result;
}

static NSData *SignMap(
    NSDictionary<NSNumber *, AncPrivateVaultCanonicalValue *> *unsignedMap,
    NSNumber *signatureField, const uint8_t *domain, size_t domainLength,
    const uint8_t seed[32]) {
  NSData *unsignedBytes = Encode(unsignedMap);
  if (unsignedBytes == nil || seed == NULL)
    return nil;
  NSMutableData *message =
      [NSMutableData dataWithBytes:domain length:domainLength];
  [message appendData:unsignedBytes];
  uint8_t publicKey[32] = {0};
  uint8_t privateKey[64] = {0};
  uint8_t signature[64] = {0};
  BOOL okay = anc_pv_ed25519_seed_keypair(publicKey, privateKey, seed) ==
                  ANC_PV_CRYPTO_OK &&
              anc_pv_ed25519_sign(signature, message.bytes, message.length,
                                  privateKey) == ANC_PV_CRYPTO_OK;
  NSMutableDictionary *signedMap = [unsignedMap mutableCopy];
  if (okay)
    signedMap[signatureField] = Bytes([NSData dataWithBytes:signature length:64]);
  NSData *encoded = okay ? Encode(signedMap) : nil;
  anc_pv_zeroize(message.mutableBytes, message.length);
  anc_pv_zeroize(publicKey, sizeof publicKey);
  anc_pv_zeroize(privateKey, sizeof privateKey);
  anc_pv_zeroize(signature, sizeof signature);
  return encoded.length > 0 && encoded.length <= kEvidenceLimit ? encoded : nil;
}

static BOOL VerifyMapSignature(
    NSDictionary<NSNumber *, AncPrivateVaultCanonicalValue *> *map,
    NSNumber *signatureField, const uint8_t *domain, size_t domainLength,
    NSData *publicKey) {
  NSData *signature = Field(map, signatureField,
                            AncPrivateVaultCanonicalTypeBytes).bytesValue;
  if (!Exact(signature, 64) || !Exact(publicKey, 32))
    return NO;
  NSMutableDictionary *unsignedMap = [map mutableCopy];
  [unsignedMap removeObjectForKey:signatureField];
  NSData *unsignedBytes = Encode(unsignedMap);
  NSMutableData *message = unsignedBytes
                               ? [NSMutableData dataWithBytes:domain
                                                      length:domainLength]
                               : nil;
  [message appendData:unsignedBytes];
  BOOL okay = message != nil &&
      anc_pv_ed25519_verify(signature.bytes, message.bytes, message.length,
                            publicKey.bytes) == ANC_PV_CRYPTO_OK;
  anc_pv_zeroize(message.mutableBytes, message.length);
  return okay;
}

static NSMutableDictionary<NSNumber *, AncPrivateVaultCanonicalValue *> *
Common(NSData *vaultId, NSString *type, uint64_t createdAt,
       NSData *envelopeId) {
  if (!Exact(vaultId, 16) || !Positive(createdAt) || !Exact(envelopeId, 16))
    return nil;
  return [@{
    @1 : Text(@"anc/rotation/v1"),
    @2 : Bytes(vaultId),
    @3 : Text(type),
    @4 : Integer(createdAt),
    @5 : Bytes(envelopeId),
  } mutableCopy];
}

static BOOL ValidCommon(
    NSDictionary<NSNumber *, AncPrivateVaultCanonicalValue *> *map,
    NSString *type, NSData *expectedVaultId) {
  int64_t created = Field(map, @4, AncPrivateVaultCanonicalTypeInteger).integerValue;
  return [Field(map, @1, AncPrivateVaultCanonicalTypeText).textValue
             isEqualToString:@"anc/rotation/v1"] &&
         Same(Field(map, @2, AncPrivateVaultCanonicalTypeBytes).bytesValue,
              expectedVaultId) &&
         [Field(map, @3, AncPrivateVaultCanonicalTypeText).textValue
             isEqualToString:type] &&
         created > 0 && (uint64_t)created <= kMaxSafe &&
         Exact(Field(map, @5, AncPrivateVaultCanonicalTypeBytes).bytesValue,
               16);
}

static uint64_t Unsigned(NSDictionary *map, NSNumber *key, BOOL positive) {
  AncPrivateVaultCanonicalValue *value =
      Field(map, key, AncPrivateVaultCanonicalTypeInteger);
  if (value == nil || value.integerValue < (positive ? 1 : 0) ||
      (uint64_t)value.integerValue > kMaxSafe)
    return UINT64_MAX;
  return (uint64_t)value.integerValue;
}

NSData *AncPrivateVaultRotationEvidenceBuildCheckpoint(
    NSData *vaultId, uint64_t createdAt, NSData *envelopeId,
    NSData *ceremonyId, uint64_t baseSequence, NSData *baseHeadHash,
    uint64_t baseEpoch, uint64_t targetEpoch, NSData *manifestObjectId,
    NSData *revisionId, uint64_t generation, NSData *ciphertextHash,
    uint64_t liveObjectCount, uint64_t liveRevisionCount,
    NSData *liveRevisionSetHash, NSData *recipientSetHash,
    NSData *controlEntryHash, NSData *signerEndpointId,
    NSData *removedEndpointId, const uint8_t signingSeed[32],
    AncPrivateVaultRotationEvidenceStatus *status) {
  SetStatus(status, AncPrivateVaultRotationEvidenceStatusInvalid);
  NSMutableDictionary *map = Common(vaultId, @"rotation-manifest-checkpoint",
                                    createdAt, envelopeId);
  if (map == nil || !Exact(ceremonyId, 16) || !Safe(baseSequence) ||
      !Exact(baseHeadHash, 32) || !Positive(baseEpoch) ||
      !Positive(targetEpoch) || !Exact(manifestObjectId, 16) ||
      !Exact(revisionId, 32) || !Positive(generation) ||
      !Exact(ciphertextHash, 32) || !Safe(liveObjectCount) ||
      liveObjectCount > 10000 || !Safe(liveRevisionCount) ||
      liveRevisionCount > 10000 || !Exact(liveRevisionSetHash, 32) ||
      !Exact(recipientSetHash, 32) || !Exact(controlEntryHash, 32) ||
      !Exact(signerEndpointId, 16) || !Exact(removedEndpointId, 16) ||
      signingSeed == NULL)
    return nil;
  [map addEntriesFromDictionary:@{
    @10 : Bytes(ceremonyId), @11 : Integer(baseSequence),
    @12 : Bytes(baseHeadHash), @13 : Integer(targetEpoch),
    @14 : Bytes(manifestObjectId), @15 : Bytes(revisionId),
    @16 : Integer(generation), @17 : Bytes(ciphertextHash),
    @18 : Integer(liveObjectCount), @19 : Bytes(liveRevisionSetHash),
    @20 : Bytes(signerEndpointId), @21 : Bytes(removedEndpointId),
    @23 : Integer(baseEpoch), @24 : Integer(liveRevisionCount),
    @25 : Bytes(recipientSetHash), @26 : Bytes(controlEntryHash),
  }];
  NSData *encoded = SignMap(map, @22, kCheckpointDomain,
                            sizeof kCheckpointDomain, signingSeed);
  SetStatus(status, encoded ? AncPrivateVaultRotationEvidenceStatusOK
                            : AncPrivateVaultRotationEvidenceStatusCrypto);
  return encoded;
}

NSData *AncPrivateVaultRotationEvidenceBuildOffer(
    NSData *vaultId, uint64_t createdAt, NSData *envelopeId,
    NSData *ceremonyId, NSData *checkpointHash, NSData *eekWrapHash,
    NSData *recipientEndpointId, NSData *issuerEndpointId,
    uint64_t targetEpoch, uint64_t expiresAt,
    const uint8_t issuerSigningSeed[32],
    AncPrivateVaultRotationEvidenceStatus *status) {
  SetStatus(status, AncPrivateVaultRotationEvidenceStatusInvalid);
  NSMutableDictionary *map = Common(vaultId, @"rotation-recipient-offer",
                                    createdAt, envelopeId);
  if (map == nil || !Exact(ceremonyId, 16) || !Exact(checkpointHash, 32) ||
      !Exact(eekWrapHash, 32) || !Exact(recipientEndpointId, 16) ||
      !Exact(issuerEndpointId, 16) || !Positive(targetEpoch) ||
      !Positive(expiresAt) || expiresAt < createdAt ||
      issuerSigningSeed == NULL)
    return nil;
  [map addEntriesFromDictionary:@{
    @30 : Bytes(ceremonyId), @31 : Bytes(checkpointHash),
    @32 : Bytes(eekWrapHash), @33 : Bytes(recipientEndpointId),
    @34 : Bytes(issuerEndpointId), @35 : Integer(targetEpoch),
    @36 : Integer(expiresAt),
  }];
  NSData *encoded =
      SignMap(map, @37, kOfferDomain, sizeof kOfferDomain, issuerSigningSeed);
  SetStatus(status, encoded ? AncPrivateVaultRotationEvidenceStatusOK
                            : AncPrivateVaultRotationEvidenceStatusCrypto);
  return encoded;
}

static NSMutableData *PossessionMac(
    NSDictionary<NSNumber *, AncPrivateVaultCanonicalValue *> *unsignedMap,
    const uint8_t pendingEpochKey[32]) {
  NSData *encoded = Encode(unsignedMap);
  if (encoded == nil || pendingEpochKey == NULL)
    return nil;
  NSMutableData *message =
      [NSMutableData dataWithBytes:kAcknowledgementMacDomain
                            length:sizeof kAcknowledgementMacDomain];
  [message appendData:encoded];
  uint8_t epoch[32] = {0};
  uint8_t key[32] = {0};
  uint8_t output[32] = {0};
  memcpy(epoch, pendingEpochKey, sizeof epoch);
  BOOL okay = anc_pv_blake2b_256_keyed(
                  key, kPossessionKeyDomain, sizeof kPossessionKeyDomain,
                  epoch) == ANC_PV_CRYPTO_OK &&
              anc_pv_blake2b_256_keyed(output, message.bytes, message.length,
                                       key) == ANC_PV_CRYPTO_OK;
  NSMutableData *result =
      okay ? [NSMutableData dataWithBytes:output length:32] : nil;
  anc_pv_zeroize(message.mutableBytes, message.length);
  anc_pv_zeroize(epoch, sizeof epoch);
  anc_pv_zeroize(key, sizeof key);
  anc_pv_zeroize(output, sizeof output);
  return result;
}

NSData *AncPrivateVaultRotationEvidenceBuildAcknowledgement(
    NSData *vaultId, uint64_t createdAt, NSData *envelopeId,
    NSData *ceremonyId, NSData *checkpointHash, NSData *eekWrapHash,
    NSData *offerHash, NSData *recipientEndpointId, uint64_t targetEpoch,
    const uint8_t recipientSigningSeed[32],
    const uint8_t pendingEpochKey[32],
    AncPrivateVaultRotationEvidenceStatus *status) {
  SetStatus(status, AncPrivateVaultRotationEvidenceStatusInvalid);
  NSMutableDictionary *map = Common(
      vaultId, @"rotation-recipient-acknowledgement", createdAt, envelopeId);
  if (map == nil || !Exact(ceremonyId, 16) || !Exact(checkpointHash, 32) ||
      !Exact(eekWrapHash, 32) || !Exact(offerHash, 32) ||
      !Exact(recipientEndpointId, 16) || !Positive(targetEpoch) ||
      recipientSigningSeed == NULL || pendingEpochKey == NULL)
    return nil;
  [map addEntriesFromDictionary:@{
    @40 : Bytes(ceremonyId), @41 : Bytes(checkpointHash),
    @42 : Bytes(eekWrapHash), @43 : Bytes(recipientEndpointId),
    @44 : Integer(targetEpoch), @47 : Bytes(offerHash),
  }];
  NSMutableData *mac = PossessionMac(map, pendingEpochKey);
  if (mac == nil) {
    SetStatus(status, AncPrivateVaultRotationEvidenceStatusCrypto);
    return nil;
  }
  map[@45] = Bytes(mac);
  NSData *encoded = SignMap(map, @46, kAcknowledgementDomain,
                            sizeof kAcknowledgementDomain,
                            recipientSigningSeed);
  anc_pv_zeroize(mac.mutableBytes, mac.length);
  SetStatus(status, encoded ? AncPrivateVaultRotationEvidenceStatusOK
                            : AncPrivateVaultRotationEvidenceStatusCrypto);
  return encoded;
}

NSData *AncPrivateVaultRotationEvidenceBuildDestruction(
    NSData *vaultId, uint64_t createdAt, NSData *envelopeId,
    NSData *ceremonyId, NSData *checkpointHash, NSData *controlEntryHash,
    NSData *endpointId, uint64_t destroyedEpoch, uint64_t activatedEpoch,
    uint64_t custodyGeneration, const uint8_t endpointSigningSeed[32],
    AncPrivateVaultRotationEvidenceStatus *status) {
  SetStatus(status, AncPrivateVaultRotationEvidenceStatusInvalid);
  NSMutableDictionary *map = Common(
      vaultId, @"rotation-epoch-destruction-attestation", createdAt,
      envelopeId);
  if (map == nil || !Exact(ceremonyId, 16) || !Exact(checkpointHash, 32) ||
      !Exact(controlEntryHash, 32) || !Exact(endpointId, 16) ||
      !Positive(destroyedEpoch) || !Positive(activatedEpoch) ||
      !Positive(custodyGeneration) || endpointSigningSeed == NULL)
    return nil;
  [map addEntriesFromDictionary:@{
    @50 : Bytes(ceremonyId), @51 : Bytes(checkpointHash),
    @52 : Bytes(controlEntryHash), @53 : Bytes(endpointId),
    @54 : Integer(destroyedEpoch), @55 : Integer(activatedEpoch),
    @56 : Integer(custodyGeneration),
  }];
  NSData *encoded = SignMap(map, @57, kDestructionDomain,
                            sizeof kDestructionDomain, endpointSigningSeed);
  SetStatus(status, encoded ? AncPrivateVaultRotationEvidenceStatusOK
                            : AncPrivateVaultRotationEvidenceStatusCrypto);
  return encoded;
}

NSData *AncPrivateVaultRotationEvidenceBuildCompletion(
    NSData *vaultId, uint64_t createdAt, NSData *envelopeId,
    NSData *ceremonyId, NSData *checkpointHash, NSData *controlEntryHash,
    NSData *hostedReceiptHash, NSData *signerEndpointId,
    uint64_t committedSequence, NSData *committedHeadHash,
    NSData *recipientSetHash, const uint8_t signerSigningSeed[32],
    AncPrivateVaultRotationEvidenceStatus *status) {
  SetStatus(status, AncPrivateVaultRotationEvidenceStatusInvalid);
  NSMutableDictionary *map = Common(
      vaultId, @"rotation-control-commit-attestation", createdAt, envelopeId);
  if (map == nil || !Exact(ceremonyId, 16) || !Exact(checkpointHash, 32) ||
      !Exact(controlEntryHash, 32) || !Exact(hostedReceiptHash, 32) ||
      !Exact(signerEndpointId, 16) || !Positive(committedSequence) ||
      !Exact(committedHeadHash, 32) || !Exact(recipientSetHash, 32) ||
      signerSigningSeed == NULL)
    return nil;
  [map addEntriesFromDictionary:@{
    @60 : Bytes(ceremonyId), @61 : Bytes(checkpointHash),
    @62 : Bytes(controlEntryHash), @63 : Bytes(hostedReceiptHash),
    @64 : Bytes(signerEndpointId), @65 : Integer(committedSequence),
    @66 : Bytes(committedHeadHash), @67 : Bytes(recipientSetHash),
  }];
  NSData *encoded = SignMap(map, @68, kCompletionDomain,
                            sizeof kCompletionDomain, signerSigningSeed);
  SetStatus(status, encoded ? AncPrivateVaultRotationEvidenceStatusOK
                            : AncPrivateVaultRotationEvidenceStatusCrypto);
  return encoded;
}

static NSArray<NSNumber *> *CheckpointKeys(void) {
  return @[
    @1, @2, @3, @4, @5, @10, @11, @12, @13, @14, @15, @16, @17, @18,
    @19, @20, @21, @22, @23, @24, @25, @26
  ];
}
static NSArray<NSNumber *> *OfferKeys(void) {
  return @[ @1, @2, @3, @4, @5, @30, @31, @32, @33, @34, @35, @36, @37 ];
}
static NSArray<NSNumber *> *AcknowledgementKeys(void) {
  return @[ @1, @2, @3, @4, @5, @40, @41, @42, @43, @44, @45, @46, @47 ];
}
static NSArray<NSNumber *> *DestructionKeys(void) {
  return @[ @1, @2, @3, @4, @5, @50, @51, @52, @53, @54, @55, @56, @57 ];
}
static NSArray<NSNumber *> *CompletionKeys(void) {
  return @[ @1, @2, @3, @4, @5, @60, @61, @62, @63, @64, @65, @66, @67, @68 ];
}
static NSArray<NSNumber *> *ReceiptKeys(void) {
  return @[ @1, @2, @3, @4, @5, @6, @7, @8, @9 ];
}

static NSDictionary *Checkpoint(NSData *encoded, NSData *vaultId) {
  NSDictionary *map = Decode(encoded, kEvidenceLimit);
  if (!Keys(map, CheckpointKeys()) ||
      !ValidCommon(map, @"rotation-manifest-checkpoint", vaultId) ||
      !Exact(Field(map, @10, AncPrivateVaultCanonicalTypeBytes).bytesValue,
             16) ||
      Unsigned(map, @11, NO) == UINT64_MAX ||
      !Exact(Field(map, @12, AncPrivateVaultCanonicalTypeBytes).bytesValue,
             32) ||
      Unsigned(map, @13, YES) == UINT64_MAX ||
      !Exact(Field(map, @14, AncPrivateVaultCanonicalTypeBytes).bytesValue,
             16) ||
      !Exact(Field(map, @15, AncPrivateVaultCanonicalTypeBytes).bytesValue,
             32) ||
      Unsigned(map, @16, YES) == UINT64_MAX ||
      !Exact(Field(map, @17, AncPrivateVaultCanonicalTypeBytes).bytesValue,
             32) ||
      Unsigned(map, @18, NO) > 10000 ||
      !Exact(Field(map, @19, AncPrivateVaultCanonicalTypeBytes).bytesValue,
             32) ||
      !Exact(Field(map, @20, AncPrivateVaultCanonicalTypeBytes).bytesValue,
             16) ||
      !Exact(Field(map, @21, AncPrivateVaultCanonicalTypeBytes).bytesValue,
             16) ||
      !Exact(Field(map, @22, AncPrivateVaultCanonicalTypeBytes).bytesValue,
             64) ||
      Unsigned(map, @23, YES) == UINT64_MAX ||
      Unsigned(map, @24, NO) > 10000 ||
      !Exact(Field(map, @25, AncPrivateVaultCanonicalTypeBytes).bytesValue,
             32) ||
      !Exact(Field(map, @26, AncPrivateVaultCanonicalTypeBytes).bytesValue,
             32))
    return nil;
  return map;
}

static NSDictionary *Offer(NSData *encoded, NSData *vaultId) {
  NSDictionary *map = Decode(encoded, kEvidenceLimit);
  uint64_t created = Unsigned(map, @4, YES);
  uint64_t expires = Unsigned(map, @36, YES);
  if (!Keys(map, OfferKeys()) ||
      !ValidCommon(map, @"rotation-recipient-offer", vaultId) ||
      !Exact(Field(map, @30, AncPrivateVaultCanonicalTypeBytes).bytesValue,
             16) ||
      !Exact(Field(map, @31, AncPrivateVaultCanonicalTypeBytes).bytesValue,
             32) ||
      !Exact(Field(map, @32, AncPrivateVaultCanonicalTypeBytes).bytesValue,
             32) ||
      !Exact(Field(map, @33, AncPrivateVaultCanonicalTypeBytes).bytesValue,
             16) ||
      !Exact(Field(map, @34, AncPrivateVaultCanonicalTypeBytes).bytesValue,
             16) ||
      Unsigned(map, @35, YES) == UINT64_MAX || expires == UINT64_MAX ||
      created == UINT64_MAX || expires < created ||
      !Exact(Field(map, @37, AncPrivateVaultCanonicalTypeBytes).bytesValue,
             64))
    return nil;
  return map;
}

static NSDictionary *Acknowledgement(NSData *encoded, NSData *vaultId) {
  NSDictionary *map = Decode(encoded, kEvidenceLimit);
  if (!Keys(map, AcknowledgementKeys()) ||
      !ValidCommon(map, @"rotation-recipient-acknowledgement", vaultId) ||
      !Exact(Field(map, @40, AncPrivateVaultCanonicalTypeBytes).bytesValue,
             16) ||
      !Exact(Field(map, @41, AncPrivateVaultCanonicalTypeBytes).bytesValue,
             32) ||
      !Exact(Field(map, @42, AncPrivateVaultCanonicalTypeBytes).bytesValue,
             32) ||
      !Exact(Field(map, @43, AncPrivateVaultCanonicalTypeBytes).bytesValue,
             16) ||
      Unsigned(map, @44, YES) == UINT64_MAX ||
      !Exact(Field(map, @45, AncPrivateVaultCanonicalTypeBytes).bytesValue,
             32) ||
      !Exact(Field(map, @46, AncPrivateVaultCanonicalTypeBytes).bytesValue,
             64) ||
      !Exact(Field(map, @47, AncPrivateVaultCanonicalTypeBytes).bytesValue,
             32))
    return nil;
  return map;
}

static NSDictionary *Destruction(NSData *encoded, NSData *vaultId) {
  NSDictionary *map = Decode(encoded, kEvidenceLimit);
  if (!Keys(map, DestructionKeys()) ||
      !ValidCommon(map, @"rotation-epoch-destruction-attestation", vaultId) ||
      !Exact(Field(map, @50, AncPrivateVaultCanonicalTypeBytes).bytesValue,
             16) ||
      !Exact(Field(map, @51, AncPrivateVaultCanonicalTypeBytes).bytesValue,
             32) ||
      !Exact(Field(map, @52, AncPrivateVaultCanonicalTypeBytes).bytesValue,
             32) ||
      !Exact(Field(map, @53, AncPrivateVaultCanonicalTypeBytes).bytesValue,
             16) ||
      Unsigned(map, @54, YES) == UINT64_MAX ||
      Unsigned(map, @55, YES) == UINT64_MAX ||
      Unsigned(map, @56, YES) == UINT64_MAX ||
      !Exact(Field(map, @57, AncPrivateVaultCanonicalTypeBytes).bytesValue,
             64))
    return nil;
  return map;
}

static NSDictionary *Completion(NSData *encoded, NSData *vaultId) {
  NSDictionary *map = Decode(encoded, kEvidenceLimit);
  if (!Keys(map, CompletionKeys()) ||
      !ValidCommon(map, @"rotation-control-commit-attestation", vaultId) ||
      !Exact(Field(map, @60, AncPrivateVaultCanonicalTypeBytes).bytesValue,
             16) ||
      !Exact(Field(map, @61, AncPrivateVaultCanonicalTypeBytes).bytesValue,
             32) ||
      !Exact(Field(map, @62, AncPrivateVaultCanonicalTypeBytes).bytesValue,
             32) ||
      !Exact(Field(map, @63, AncPrivateVaultCanonicalTypeBytes).bytesValue,
             32) ||
      !Exact(Field(map, @64, AncPrivateVaultCanonicalTypeBytes).bytesValue,
             16) ||
      Unsigned(map, @65, YES) == UINT64_MAX ||
      !Exact(Field(map, @66, AncPrivateVaultCanonicalTypeBytes).bytesValue,
             32) ||
      !Exact(Field(map, @67, AncPrivateVaultCanonicalTypeBytes).bytesValue,
             32) ||
      !Exact(Field(map, @68, AncPrivateVaultCanonicalTypeBytes).bytesValue,
             64))
    return nil;
  return map;
}

static BOOL OpaqueId(NSString *value) {
  if (![value isKindOfClass:NSString.class] || value.length < 8 ||
      value.length > 160)
    return NO;
  NSCharacterSet *allowed = [NSCharacterSet
      characterSetWithCharactersInString:
          @"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._:-"];
  NSCharacterSet *first = [NSCharacterSet
      characterSetWithCharactersInString:
          @"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"];
  return [first characterIsMember:[value characterAtIndex:0]] &&
         [value rangeOfCharacterFromSet:allowed.invertedSet].location ==
             NSNotFound;
}

static NSDictionary *Receipt(NSData *encoded) {
  NSDictionary *map = Decode(encoded, kEvidenceLimit);
  NSString *vault = Field(map, @4, AncPrivateVaultCanonicalTypeText).textValue;
  NSString *entry = Field(map, @5, AncPrivateVaultCanonicalTypeText).textValue;
  uint64_t sequence = Unsigned(map, @6, NO);
  uint64_t length = Unsigned(map, @9, YES);
  if (!Keys(map, ReceiptKeys()) ||
      ![Field(map, @1, AncPrivateVaultCanonicalTypeText).textValue
          isEqualToString:@"anc/v1"] ||
      Unsigned(map, @2, NO) != 1 ||
      ![Field(map, @3, AncPrivateVaultCanonicalTypeText).textValue
          isEqualToString:@"control-log-rotation-append-receipt"] ||
      !OpaqueId(vault) || !OpaqueId(entry) || sequence == UINT64_MAX ||
      !Exact(Field(map, @7, AncPrivateVaultCanonicalTypeBytes).bytesValue,
             32) ||
      !Exact(Field(map, @8, AncPrivateVaultCanonicalTypeBytes).bytesValue,
             32) ||
      length == UINT64_MAX || length > 1024 * 1024)
    return nil;
  return map;
}

NSData *AncPrivateVaultRotationEvidenceHashCheckpoint(NSData *encodedCheckpoint,
                                                      NSData *expectedVaultId) {
  return Checkpoint(encodedCheckpoint, expectedVaultId)
             ? DomainHash(kCheckpointHashDomain, sizeof kCheckpointHashDomain,
                          encodedCheckpoint)
             : nil;
}

NSData *AncPrivateVaultRotationEvidenceHashOffer(NSData *encodedOffer,
                                                 NSData *expectedVaultId) {
  return Offer(encodedOffer, expectedVaultId)
             ? DomainHash(kOfferHashDomain, sizeof kOfferHashDomain,
                          encodedOffer)
             : nil;
}

NSData *AncPrivateVaultRotationEvidenceHashHostedReceipt(NSData *encodedReceipt) {
  return Receipt(encodedReceipt)
             ? DomainHash(kHostedReceiptHashDomain,
                          sizeof kHostedReceiptHashDomain, encodedReceipt)
             : nil;
}

static NSComparisonResult CompareData(NSData *left, NSData *right) {
  const uint8_t *a = left.bytes;
  const uint8_t *b = right.bytes;
  NSUInteger length = MIN(left.length, right.length);
  for (NSUInteger index = 0; index < length; index += 1) {
    if (a[index] < b[index])
      return NSOrderedAscending;
    if (a[index] > b[index])
      return NSOrderedDescending;
  }
  if (left.length < right.length)
    return NSOrderedAscending;
  if (left.length > right.length)
    return NSOrderedDescending;
  return NSOrderedSame;
}

NSData *AncPrivateVaultRotationEvidenceHashRecipientSet(
    NSArray<AncPrivateVaultRotationEvidenceRecipient *> *recipients) {
  if (![recipients isKindOfClass:NSArray.class] || recipients.count < 1 ||
      recipients.count > kRecipientLimit)
    return nil;
  for (id recipient in recipients)
    if (![recipient
            isKindOfClass:AncPrivateVaultRotationEvidenceRecipient.class] ||
        !Exact([recipient endpointId], 16) ||
        !Exact([recipient signingPublicKey], 32) ||
        !Exact([recipient keyAgreementPublicKey], 32) ||
        !Exact([recipient eekWrapHash], 32))
      return nil;
  NSArray *sorted = [recipients
      sortedArrayUsingComparator:^NSComparisonResult(
          AncPrivateVaultRotationEvidenceRecipient *left,
          AncPrivateVaultRotationEvidenceRecipient *right) {
        return CompareData(left.endpointId, right.endpointId);
      }];
  NSMutableArray *values = [NSMutableArray arrayWithCapacity:sorted.count];
  NSData *prior = nil;
  for (AncPrivateVaultRotationEvidenceRecipient *recipient in sorted) {
    if (prior != nil && Same(prior, recipient.endpointId))
      return nil;
    [values addObject:[AncPrivateVaultCanonicalValue array:@[
      Bytes(recipient.endpointId), Bytes(recipient.signingPublicKey),
      Bytes(recipient.keyAgreementPublicKey), Bytes(recipient.eekWrapHash)
    ]]];
    prior = recipient.endpointId;
  }
  AncPrivateVaultCanonicalStatus status;
  NSData *encoded = AncPrivateVaultCanonicalEncode(
      [AncPrivateVaultCanonicalValue array:values], &status);
  return status == AncPrivateVaultCanonicalStatusOK
             ? DomainHash(kRecipientSetHashDomain,
                          sizeof kRecipientSetHashDomain, encoded)
             : nil;
}

NSData *AncPrivateVaultRotationEvidenceHashLiveRevisionSet(
    NSArray<AncPrivateVaultRotationLiveRevision *> *liveRevisions) {
  if (![liveRevisions isKindOfClass:NSArray.class] ||
      liveRevisions.count > 10000)
    return nil;
  for (id value in liveRevisions)
    if (![value isKindOfClass:AncPrivateVaultRotationLiveRevision.class] ||
        !Exact([value objectId], 16) || !Positive([value revision]) ||
        !Exact([value priorRevisionId], 32) ||
        !Exact([value rotatedRevisionId], 32))
      return nil;
  NSArray *sorted = [liveRevisions
      sortedArrayUsingComparator:^NSComparisonResult(
          AncPrivateVaultRotationLiveRevision *left,
          AncPrivateVaultRotationLiveRevision *right) {
        NSComparisonResult objects = CompareData(left.objectId, right.objectId);
        if (objects != NSOrderedSame)
          return objects;
        if (left.revision < right.revision)
          return NSOrderedAscending;
        if (left.revision > right.revision)
          return NSOrderedDescending;
        return NSOrderedSame;
      }];
  NSMutableArray *values = [NSMutableArray arrayWithCapacity:sorted.count];
  AncPrivateVaultRotationLiveRevision *prior = nil;
  for (AncPrivateVaultRotationLiveRevision *revision in sorted) {
    if (prior != nil && Same(prior.objectId, revision.objectId) &&
        prior.revision == revision.revision)
      return nil;
    [values addObject:[AncPrivateVaultCanonicalValue array:@[
      Bytes(revision.objectId), Integer(revision.revision),
      Bytes(revision.priorRevisionId), Bytes(revision.rotatedRevisionId)
    ]]];
    prior = revision;
  }
  AncPrivateVaultCanonicalStatus status;
  NSData *encoded = AncPrivateVaultCanonicalEncode(
      [AncPrivateVaultCanonicalValue array:values], &status);
  return status == AncPrivateVaultCanonicalStatusOK
             ? DomainHash(kLiveRevisionSetHashDomain,
                          sizeof kLiveRevisionSetHashDomain, encoded)
             : nil;
}

static BOOL Reject(AncPrivateVaultRotationEvidenceStatus *status,
                   AncPrivateVaultRotationEvidenceStatus value) {
  SetStatus(status, value);
  return NO;
}

static id RejectObject(AncPrivateVaultRotationEvidenceStatus *status,
                       AncPrivateVaultRotationEvidenceStatus value) {
  SetStatus(status, value);
  return nil;
}

AncPrivateVaultRotationPreparationEvidence *
AncPrivateVaultVerifyRotationPreparationEvidence(
    NSData *encodedCheckpoint, NSData *expectedVaultId,
    NSData *expectedSignerEndpointId, NSData *signerSigningPublicKey,
    NSArray<AncPrivateVaultRotationEvidenceRecipient *> *expectedRecipients,
    NSArray<AncPrivateVaultRotationLiveRevision *> *liveRevisions,
    uint64_t now, AncPrivateVaultRotationEvidenceStatus *status) {
  SetStatus(status, AncPrivateVaultRotationEvidenceStatusInvalid);
  if (!Exact(expectedVaultId, 16) || !Exact(expectedSignerEndpointId, 16) ||
      !Exact(signerSigningPublicKey, 32) || !Positive(now) ||
      ![expectedRecipients isKindOfClass:NSArray.class] ||
      expectedRecipients.count < 1 ||
      expectedRecipients.count > kRecipientLimit ||
      ![liveRevisions isKindOfClass:NSArray.class] ||
      liveRevisions.count > 10000)
    return nil;

  NSDictionary *checkpoint = Checkpoint(encodedCheckpoint, expectedVaultId);
  if (checkpoint == nil)
    return nil;
  uint64_t baseEpoch = Unsigned(checkpoint, @23, YES);
  uint64_t targetEpoch = Unsigned(checkpoint, @13, YES);
  uint64_t liveObjectCount = Unsigned(checkpoint, @18, NO);
  uint64_t liveRevisionCount = Unsigned(checkpoint, @24, NO);
  NSData *ceremonyId =
      Field(checkpoint, @10, AncPrivateVaultCanonicalTypeBytes).bytesValue;
  NSData *removedEndpointId =
      Field(checkpoint, @21, AncPrivateVaultCanonicalTypeBytes).bytesValue;
  NSData *checkpointSigner =
      Field(checkpoint, @20, AncPrivateVaultCanonicalTypeBytes).bytesValue;
  NSData *checkpointRecipientSetHash =
      Field(checkpoint, @25, AncPrivateVaultCanonicalTypeBytes).bytesValue;
  if (baseEpoch == kMaxSafe || targetEpoch != baseEpoch + 1 ||
      !Same(checkpointSigner, expectedSignerEndpointId) ||
      Same(checkpointSigner, removedEndpointId) ||
      liveObjectCount > liveRevisionCount)
    return RejectObject(status, AncPrivateVaultRotationEvidenceStatusBinding);
  if (!VerifyMapSignature(checkpoint, @22, kCheckpointDomain,
                          sizeof kCheckpointDomain, signerSigningPublicKey))
    return RejectObject(status, AncPrivateVaultRotationEvidenceStatusSignature);

  if (liveRevisions.count != liveRevisionCount)
    return RejectObject(status, AncPrivateVaultRotationEvidenceStatusBinding);
  NSMutableSet<NSData *> *liveObjects = [NSMutableSet set];
  for (id revision in liveRevisions) {
    if (![revision isKindOfClass:AncPrivateVaultRotationLiveRevision.class])
      return nil;
    [liveObjects addObject:[revision objectId]];
  }
  NSData *liveRevisionSetHash =
      AncPrivateVaultRotationEvidenceHashLiveRevisionSet(liveRevisions);
  if (liveObjects.count != liveObjectCount ||
      !Same(liveRevisionSetHash,
            Field(checkpoint, @19,
                  AncPrivateVaultCanonicalTypeBytes).bytesValue))
    return RejectObject(status, AncPrivateVaultRotationEvidenceStatusBinding);

  NSData *checkpointHash = AncPrivateVaultRotationEvidenceHashCheckpoint(
      encodedCheckpoint, expectedVaultId);
  NSData *recipientSetHash =
      AncPrivateVaultRotationEvidenceHashRecipientSet(expectedRecipients);
  if (!Same(recipientSetHash, checkpointRecipientSetHash))
    return RejectObject(status, AncPrivateVaultRotationEvidenceStatusBinding);

  NSMutableDictionary<NSData *, AncPrivateVaultRotationEvidenceRecipient *>
      *recipients = [NSMutableDictionary dictionary];
  BOOL signerPresent = NO;
  for (id value in expectedRecipients) {
    if (![value
            isKindOfClass:AncPrivateVaultRotationEvidenceRecipient.class])
      return nil;
    AncPrivateVaultRotationEvidenceRecipient *recipient = value;
    if (recipients[recipient.endpointId] != nil ||
        Same(recipient.endpointId, removedEndpointId))
      return RejectObject(status, AncPrivateVaultRotationEvidenceStatusBinding);
    recipients[recipient.endpointId] = recipient;
    if (Same(recipient.endpointId, checkpointSigner) &&
        Same(recipient.signingPublicKey, signerSigningPublicKey))
      signerPresent = YES;
  }
  if (!signerPresent)
    return RejectObject(status, AncPrivateVaultRotationEvidenceStatusBinding);

  NSMutableDictionary<NSData *, NSDictionary *> *offers =
      [NSMutableDictionary dictionary];
  NSMutableDictionary<NSData *, NSData *> *offerHashes =
      [NSMutableDictionary dictionary];
  for (AncPrivateVaultRotationEvidenceRecipient *recipient in
       expectedRecipients) {
    NSDictionary *offer = Offer(recipient.encodedOffer, expectedVaultId);
    uint64_t offerCreated = Unsigned(offer, @4, YES);
    uint64_t offerExpires = Unsigned(offer, @36, YES);
    if (offer == nil || now + kClockSkew < offerCreated ||
        now > offerExpires + kClockSkew ||
        !Same(Field(offer, @34, AncPrivateVaultCanonicalTypeBytes).bytesValue,
              checkpointSigner) ||
        !Same(Field(offer, @33, AncPrivateVaultCanonicalTypeBytes).bytesValue,
              recipient.endpointId) ||
        !Same(Field(offer, @30, AncPrivateVaultCanonicalTypeBytes).bytesValue,
              ceremonyId) ||
        !Same(Field(offer, @31, AncPrivateVaultCanonicalTypeBytes).bytesValue,
              checkpointHash) ||
        !Same(Field(offer, @32, AncPrivateVaultCanonicalTypeBytes).bytesValue,
              recipient.eekWrapHash) ||
        Unsigned(offer, @35, YES) != targetEpoch)
      return RejectObject(status, AncPrivateVaultRotationEvidenceStatusBinding);
    if (!VerifyMapSignature(offer, @37, kOfferDomain, sizeof kOfferDomain,
                            signerSigningPublicKey))
      return RejectObject(status,
                          AncPrivateVaultRotationEvidenceStatusSignature);
    NSData *offerHash = AncPrivateVaultRotationEvidenceHashOffer(
        recipient.encodedOffer, expectedVaultId);
    if (!Exact(offerHash, 32))
      return RejectObject(status, AncPrivateVaultRotationEvidenceStatusCrypto);
    offers[recipient.endpointId] = offer;
    offerHashes[recipient.endpointId] = offerHash;
  }

  AncPrivateVaultRotationPreparationEvidence *result =
      [[AncPrivateVaultRotationPreparationEvidence alloc] initPrivate];
  result.encodedCheckpoint = [encodedCheckpoint copy];
  result.expectedVaultId = [expectedVaultId copy];
  result.signerSigningPublicKey = [signerSigningPublicKey copy];
  result.recipients = [expectedRecipients copy];
  result.recipientsById = [recipients copy];
  result.offersById = [offers copy];
  result.offerHashesById = [offerHashes copy];
  result.checkpoint = checkpoint;
  result.checkpointHash = checkpointHash;
  SetStatus(status, AncPrivateVaultRotationEvidenceStatusOK);
  return result;
}

AncPrivateVaultRotationCustodyEvidence *
AncPrivateVaultVerifyRotationCustodyEvidence(
    AncPrivateVaultRotationPreparationEvidence *preparation,
    NSArray<NSData *> *encodedAcknowledgements,
    NSArray<NSData *> *encodedDestructions,
    const uint8_t pendingEpochKey[32], uint64_t now,
    AncPrivateVaultRotationEvidenceStatus *status) {
  SetStatus(status, AncPrivateVaultRotationEvidenceStatusInvalid);
  if (![preparation
          isKindOfClass:AncPrivateVaultRotationPreparationEvidence.class] ||
      preparation.recipients.count < 1 ||
      preparation.recipients.count > kRecipientLimit ||
      preparation.recipientsById.count != preparation.recipients.count ||
      preparation.offersById.count != preparation.recipients.count ||
      preparation.offerHashesById.count != preparation.recipients.count ||
      ![preparation.checkpoint isKindOfClass:NSDictionary.class] ||
      !Exact(preparation.expectedVaultId, 16) ||
      !Exact(preparation.signerSigningPublicKey, 32) ||
      !Exact(preparation.checkpointHash, 32) ||
      ![encodedAcknowledgements isKindOfClass:NSArray.class] ||
      ![encodedDestructions isKindOfClass:NSArray.class] ||
      encodedAcknowledgements.count != preparation.recipients.count ||
      encodedDestructions.count != preparation.recipients.count ||
      pendingEpochKey == NULL || !Positive(now))
    return nil;
  NSDictionary *checkpoint = preparation.checkpoint;
  NSData *ceremonyId =
      Field(checkpoint, @10, AncPrivateVaultCanonicalTypeBytes).bytesValue;
  NSData *controlEntryHash =
      Field(checkpoint, @26, AncPrivateVaultCanonicalTypeBytes).bytesValue;
  uint64_t baseEpoch = Unsigned(checkpoint, @23, YES);
  uint64_t targetEpoch = Unsigned(checkpoint, @13, YES);
  uint64_t notBefore = 0;
  NSMutableSet<NSData *> *seenAcknowledgements = [NSMutableSet set];
  for (NSData *encoded in encodedAcknowledgements) {
    NSDictionary *ack = Acknowledgement(encoded, preparation.expectedVaultId);
    NSData *endpointId =
        Field(ack, @43, AncPrivateVaultCanonicalTypeBytes).bytesValue;
    AncPrivateVaultRotationEvidenceRecipient *recipient =
        preparation.recipientsById[endpointId];
    NSDictionary *offer = preparation.offersById[endpointId];
    uint64_t created = Unsigned(ack, @4, YES);
    uint64_t offerCreated = Unsigned(offer, @4, YES);
    uint64_t offerExpires = Unsigned(offer, @36, YES);
    if (ack == nil || recipient == nil ||
        [seenAcknowledgements containsObject:endpointId] ||
        !Same(Field(ack, @40, AncPrivateVaultCanonicalTypeBytes).bytesValue,
              ceremonyId) ||
        !Same(Field(ack, @41, AncPrivateVaultCanonicalTypeBytes).bytesValue,
              preparation.checkpointHash) ||
        !Same(Field(ack, @42, AncPrivateVaultCanonicalTypeBytes).bytesValue,
              recipient.eekWrapHash) ||
        !Same(Field(ack, @47, AncPrivateVaultCanonicalTypeBytes).bytesValue,
              preparation.offerHashesById[endpointId]) ||
        Unsigned(ack, @44, YES) != targetEpoch ||
        created + kClockSkew < offerCreated ||
        created > offerExpires + kClockSkew || created > now + kClockSkew)
      return RejectObject(status, AncPrivateVaultRotationEvidenceStatusBinding);
    NSMutableDictionary *unsignedAck = [ack mutableCopy];
    NSData *mac =
        Field(ack, @45, AncPrivateVaultCanonicalTypeBytes).bytesValue;
    [unsignedAck removeObjectForKey:@45];
    [unsignedAck removeObjectForKey:@46];
    NSMutableData *expectedMac = PossessionMac(unsignedAck, pendingEpochKey);
    BOOL macMatches = Same(mac, expectedMac);
    anc_pv_zeroize(expectedMac.mutableBytes, expectedMac.length);
    if (!macMatches)
      return RejectObject(status, AncPrivateVaultRotationEvidenceStatusCrypto);
    if (!VerifyMapSignature(ack, @46, kAcknowledgementDomain,
                            sizeof kAcknowledgementDomain,
                            recipient.signingPublicKey))
      return RejectObject(status,
                          AncPrivateVaultRotationEvidenceStatusSignature);
    [seenAcknowledgements addObject:endpointId];
    notBefore = MAX(notBefore, created);
  }
  if (seenAcknowledgements.count != preparation.recipients.count)
    return RejectObject(status, AncPrivateVaultRotationEvidenceStatusBinding);

  NSMutableSet<NSData *> *seenDestructions = [NSMutableSet set];
  for (NSData *encoded in encodedDestructions) {
    NSDictionary *destruction =
        Destruction(encoded, preparation.expectedVaultId);
    NSData *endpointId =
        Field(destruction, @53, AncPrivateVaultCanonicalTypeBytes).bytesValue;
    AncPrivateVaultRotationEvidenceRecipient *recipient =
        preparation.recipientsById[endpointId];
    uint64_t created = Unsigned(destruction, @4, YES);
    if (destruction == nil || recipient == nil ||
        [seenDestructions containsObject:endpointId] ||
        !Same(Field(destruction, @50,
                    AncPrivateVaultCanonicalTypeBytes).bytesValue,
              ceremonyId) ||
        !Same(Field(destruction, @51,
                    AncPrivateVaultCanonicalTypeBytes).bytesValue,
              preparation.checkpointHash) ||
        !Same(Field(destruction, @52,
                    AncPrivateVaultCanonicalTypeBytes).bytesValue,
              controlEntryHash) ||
        Unsigned(destruction, @54, YES) != baseEpoch ||
        Unsigned(destruction, @55, YES) != targetEpoch ||
        created > now + kClockSkew)
      return RejectObject(status, AncPrivateVaultRotationEvidenceStatusBinding);
    if (!VerifyMapSignature(destruction, @57, kDestructionDomain,
                            sizeof kDestructionDomain,
                            recipient.signingPublicKey))
      return RejectObject(status,
                          AncPrivateVaultRotationEvidenceStatusSignature);
    [seenDestructions addObject:endpointId];
    notBefore = MAX(notBefore, created);
  }
  if (seenDestructions.count != preparation.recipients.count)
    return RejectObject(status, AncPrivateVaultRotationEvidenceStatusBinding);

  AncPrivateVaultRotationCustodyEvidence *result =
      [[AncPrivateVaultRotationCustodyEvidence alloc] initPrivate];
  result.preparation = preparation;
  result.notBefore = notBefore;
  SetStatus(status, AncPrivateVaultRotationEvidenceStatusOK);
  return result;
}

BOOL AncPrivateVaultVerifyCompletedRotationEvidence(
    NSData *encodedCheckpoint, NSArray<NSData *> *encodedAcknowledgements,
    NSArray<NSData *> *encodedDestructions, NSData *encodedCompletion,
    NSData *encodedHostedReceipt, NSString *expectedHostedEntryId,
    NSString *expectedHostedVaultId, NSData *expectedRecoveryWrapHash,
    uint64_t expectedRecoveryWrapByteLength, NSData *expectedVaultId,
    NSData *expectedSignerEndpointId, NSData *signerSigningPublicKey,
    NSArray<AncPrivateVaultRotationEvidenceRecipient *> *expectedRecipients,
    NSArray<AncPrivateVaultRotationLiveRevision *> *liveRevisions,
    const uint8_t pendingEpochKey[32], uint64_t now,
    AncPrivateVaultRotationEvidenceStatus *status) {
  SetStatus(status, AncPrivateVaultRotationEvidenceStatusInvalid);
  if (!Exact(expectedVaultId, 16) || !Exact(expectedSignerEndpointId, 16) ||
      !Exact(signerSigningPublicKey, 32) ||
      !Exact(expectedRecoveryWrapHash, 32) ||
      !Positive(expectedRecoveryWrapByteLength) ||
      expectedRecoveryWrapByteLength > 1024 * 1024 || !Positive(now) ||
      pendingEpochKey == NULL ||
      !OpaqueId(expectedHostedEntryId) || !OpaqueId(expectedHostedVaultId))
    return NO;
  AncPrivateVaultRotationPreparationEvidence *preparation =
      AncPrivateVaultVerifyRotationPreparationEvidence(
          encodedCheckpoint, expectedVaultId, expectedSignerEndpointId,
          signerSigningPublicKey, expectedRecipients, liveRevisions, now,
          status);
  if (preparation == nil)
    return NO;
  AncPrivateVaultRotationCustodyEvidence *custody =
      AncPrivateVaultVerifyRotationCustodyEvidence(
          preparation, encodedAcknowledgements, encodedDestructions,
          pendingEpochKey, now, status);
  if (custody == nil)
    return NO;
  NSDictionary *checkpoint = preparation.checkpoint;
  uint64_t baseSequence = Unsigned(checkpoint, @11, NO);
  NSData *ceremonyId = Field(checkpoint, @10,
                             AncPrivateVaultCanonicalTypeBytes).bytesValue;
  NSData *checkpointRecipientSetHash = Field(
      checkpoint, @25, AncPrivateVaultCanonicalTypeBytes).bytesValue;
  NSData *controlEntryHash = Field(
      checkpoint, @26, AncPrivateVaultCanonicalTypeBytes).bytesValue;
  NSDictionary *receipt = Receipt(encodedHostedReceipt);
  NSData *receiptHash =
      AncPrivateVaultRotationEvidenceHashHostedReceipt(encodedHostedReceipt);
  NSDictionary *completion = Completion(encodedCompletion, expectedVaultId);
  if (receipt == nil || completion == nil || !Exact(receiptHash, 32))
    return NO;
  if (!Same(Field(completion, @64,
                  AncPrivateVaultCanonicalTypeBytes).bytesValue,
            expectedSignerEndpointId) ||
      !Same(Field(completion, @63,
                  AncPrivateVaultCanonicalTypeBytes).bytesValue,
            receiptHash))
    return Reject(status, AncPrivateVaultRotationEvidenceStatusBinding);
  if (!VerifyMapSignature(completion, @68, kCompletionDomain,
                          sizeof kCompletionDomain, signerSigningPublicKey))
    return Reject(status, AncPrivateVaultRotationEvidenceStatusSignature);

  uint64_t completionCreated = Unsigned(completion, @4, YES);
  uint64_t receiptSequence = Unsigned(receipt, @6, NO);
  if (baseSequence == kMaxSafe ||
      !Same(Field(completion, @60,
                  AncPrivateVaultCanonicalTypeBytes).bytesValue,
            ceremonyId) ||
      !Same(Field(completion, @61,
                  AncPrivateVaultCanonicalTypeBytes).bytesValue,
            preparation.checkpointHash) ||
      !Same(Field(completion, @62,
                  AncPrivateVaultCanonicalTypeBytes).bytesValue,
            controlEntryHash) ||
      !Same(Field(completion, @66,
                  AncPrivateVaultCanonicalTypeBytes).bytesValue,
            controlEntryHash) ||
      !Same(Field(completion, @67,
                  AncPrivateVaultCanonicalTypeBytes).bytesValue,
            checkpointRecipientSetHash) ||
      ![Field(receipt, @4, AncPrivateVaultCanonicalTypeText).textValue
          isEqualToString:expectedHostedVaultId] ||
      ![Field(receipt, @5, AncPrivateVaultCanonicalTypeText).textValue
          isEqualToString:expectedHostedEntryId] ||
      receiptSequence != baseSequence + 1 ||
      !Same(Field(receipt, @7,
                  AncPrivateVaultCanonicalTypeBytes).bytesValue,
            controlEntryHash) ||
      !Same(Field(receipt, @8,
                  AncPrivateVaultCanonicalTypeBytes).bytesValue,
            expectedRecoveryWrapHash) ||
      Unsigned(receipt, @9, YES) != expectedRecoveryWrapByteLength ||
      Unsigned(completion, @65, YES) != baseSequence + 1 ||
      completionCreated + kClockSkew < custody.notBefore ||
      completionCreated > now + kClockSkew)
    return Reject(status, AncPrivateVaultRotationEvidenceStatusBinding);

  SetStatus(status, AncPrivateVaultRotationEvidenceStatusOK);
  return YES;
}
