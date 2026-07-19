#import "PrivateVaultBrokerReplacementApproval.h"

#import "PrivateVaultAncCanonical.h"
#import "PrivateVaultCrypto.h"
#import "PrivateVaultEnrollmentChallenge.h"

#import <Security/Security.h>
#import <objc/runtime.h>

static const uint8_t kApprovalDomain[] =
    "anc/v1/broker-replacement-approval";
static const uint8_t kFreezeDomain[] = "anc/v1/broker-replacement-freeze";
static const uint64_t kMaxSafeInteger = UINT64_C(9007199254740991);
static const uint64_t kDefaultDeadlineSeconds = 3600;
static const uint64_t kMaximumDeadlineSeconds = 86400;

@interface AncPrivateVaultBrokerReplacementApproval ()
@property(nonatomic, readwrite) NSData *encodedApproval;
@property(nonatomic, readwrite) NSData *freezeId;
@property(nonatomic, readwrite) NSData *envelopeId;
@property(nonatomic, readwrite) NSData *issuerEndpointId;
@property(nonatomic, readwrite) NSData *oldBrokerEndpointId;
@property(nonatomic, readwrite) NSData *candidateBrokerEndpointId;
@property(nonatomic, readwrite) NSData *candidateSigningPublicKey;
@property(nonatomic, readwrite) NSData *candidateKeyAgreementPublicKey;
@property(nonatomic, readwrite) NSData *candidateEnrollmentRef;
@property(nonatomic, readwrite) NSData *offerHash;
@property(nonatomic, readwrite) NSData *challengeHash;
@property(nonatomic, readwrite) NSData *sasDecisionHash;
@property(nonatomic, readwrite) NSData *drainId;
@property(nonatomic, readwrite) uint64_t drainGeneration;
@property(nonatomic, readwrite) uint64_t createdAtSeconds;
@property(nonatomic, readwrite) uint64_t deadlineAtSeconds;
@property(nonatomic, readwrite) uint64_t baseSequence;
@property(nonatomic, readwrite) NSData *baseHeadHash;
@property(nonatomic, readwrite) NSData *baseMembershipHash;
@property(nonatomic, readwrite) uint64_t baseEpoch;
@end
@implementation AncPrivateVaultBrokerReplacementApproval
@end

static void SetStatus(AncPrivateVaultBrokerReplacementApprovalStatus *status,
                      AncPrivateVaultBrokerReplacementApprovalStatus value) {
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

static NSData *HexBytes(NSString *hex) {
  if (![hex isKindOfClass:NSString.class] || hex.length != 32)
    return nil;
  NSMutableData *result = [NSMutableData dataWithLength:16];
  uint8_t *bytes = result.mutableBytes;
  for (NSUInteger index = 0; index < 16; index += 1) {
    unichar high = [hex characterAtIndex:index * 2];
    unichar low = [hex characterAtIndex:index * 2 + 1];
    int a = high >= '0' && high <= '9'   ? high - '0'
            : high >= 'a' && high <= 'f' ? high - 'a' + 10
                                         : -1;
    int b = low >= '0' && low <= '9'   ? low - '0'
            : low >= 'a' && low <= 'f' ? low - 'a' + 10
                                       : -1;
    if (a < 0 || b < 0)
      return nil;
    bytes[index] = (uint8_t)((a << 4) | b);
  }
  return result;
}

static NSString *Hex(NSData *data) {
  if (!Exact(data, 16))
    return nil;
  NSMutableString *result = [NSMutableString stringWithCapacity:32];
  const uint8_t *bytes = data.bytes;
  for (NSUInteger index = 0; index < 16; index += 1)
    [result appendFormat:@"%02x", bytes[index]];
  return result;
}

static AncPrivateVaultCanonicalValue *
Field(NSDictionary<NSNumber *, AncPrivateVaultCanonicalValue *> *map,
      NSNumber *key, AncPrivateVaultCanonicalType type) {
  AncPrivateVaultCanonicalValue *value = map[key];
  return value.type == type ? value : nil;
}

static BOOL ExactKeys(NSDictionary<NSNumber *, id> *map,
                      NSArray<NSNumber *> *keys) {
  return map.count == keys.count && [[NSSet setWithArray:map.allKeys]
                                        isEqualToSet:[NSSet setWithArray:keys]];
}

static NSData *DomainHash(const uint8_t *domain, size_t domainLength,
                          NSData *payload) {
  if (payload == nil)
    return nil;
  uint8_t hash[32] = {0};
  BOOL okay = anc_pv_blake2b_256_two_part(
                  hash, domain, domainLength, payload.bytes, payload.length) ==
      ANC_PV_CRYPTO_OK;
  NSData *result = okay ? [NSData dataWithBytes:hash length:32] : nil;
  anc_pv_zeroize(hash, sizeof hash);
  return result;
}

NSData *AncPrivateVaultBrokerReplacementApprovalFreezeId(
    NSData *encodedApproval) {
  AncPrivateVaultCanonicalStatus canonicalStatus;
  AncPrivateVaultCanonicalValue *root =
      AncPrivateVaultCanonicalDecode(encodedApproval, 1024, &canonicalStatus);
  NSDictionary<NSNumber *, AncPrivateVaultCanonicalValue *> *map =
      root.type == AncPrivateVaultCanonicalTypeMap ? root.mapValue : nil;
  NSArray<NSNumber *> *keys = @[
    @1, @2, @3, @4, @5, @620, @621, @622, @623, @624, @625, @626, @627,
    @628, @629, @630, @631, @632, @633, @634, @635, @636
  ];
  AncPrivateVaultCanonicalValue *created =
      Field(map, @4, AncPrivateVaultCanonicalTypeInteger);
  AncPrivateVaultCanonicalValue *sequence =
      Field(map, @629, AncPrivateVaultCanonicalTypeInteger);
  AncPrivateVaultCanonicalValue *epoch =
      Field(map, @632, AncPrivateVaultCanonicalTypeInteger);
  AncPrivateVaultCanonicalValue *generation =
      Field(map, @634, AncPrivateVaultCanonicalTypeInteger);
  AncPrivateVaultCanonicalValue *deadline =
      Field(map, @635, AncPrivateVaultCanonicalTypeInteger);
  NSData *envelopeId =
      Field(map, @5, AncPrivateVaultCanonicalTypeBytes).bytesValue;
  NSData *issuerId =
      Field(map, @620, AncPrivateVaultCanonicalTypeBytes).bytesValue;
  NSData *oldBrokerId =
      Field(map, @621, AncPrivateVaultCanonicalTypeBytes).bytesValue;
  NSData *candidateId =
      Field(map, @622, AncPrivateVaultCanonicalTypeBytes).bytesValue;
  NSData *candidateEnrollmentRef =
      Field(map, @625, AncPrivateVaultCanonicalTypeBytes).bytesValue;
  BOOL structurallyValid =
      ExactKeys(map, keys) &&
      [Field(map, @1, AncPrivateVaultCanonicalTypeText).textValue
          isEqualToString:@"anc/v1"] &&
      Exact(Field(map, @2, AncPrivateVaultCanonicalTypeBytes).bytesValue, 16) &&
      [Field(map, @3, AncPrivateVaultCanonicalTypeText).textValue
          isEqualToString:@"broker_replacement_approval"] &&
      created.integerValue > 0 &&
      (uint64_t)created.integerValue <= kMaxSafeInteger &&
      Exact(envelopeId, 16) && Exact(issuerId, 16) && Exact(oldBrokerId, 16) &&
      Exact(candidateId, 16) &&
      Exact(Field(map, @623, AncPrivateVaultCanonicalTypeBytes).bytesValue,
            32) &&
      Exact(Field(map, @624, AncPrivateVaultCanonicalTypeBytes).bytesValue,
            32) &&
      Same(candidateEnrollmentRef, envelopeId) &&
      Exact(Field(map, @626, AncPrivateVaultCanonicalTypeBytes).bytesValue,
            32) &&
      Exact(Field(map, @627, AncPrivateVaultCanonicalTypeBytes).bytesValue,
            32) &&
      Exact(Field(map, @628, AncPrivateVaultCanonicalTypeBytes).bytesValue,
            32) &&
      sequence.integerValue > 0 &&
      (uint64_t)sequence.integerValue <= kMaxSafeInteger &&
      Exact(Field(map, @630, AncPrivateVaultCanonicalTypeBytes).bytesValue,
            32) &&
      Exact(Field(map, @631, AncPrivateVaultCanonicalTypeBytes).bytesValue,
            32) &&
      epoch.integerValue > 0 &&
      (uint64_t)epoch.integerValue <= kMaxSafeInteger &&
      Exact(Field(map, @633, AncPrivateVaultCanonicalTypeBytes).bytesValue,
            16) &&
      generation.integerValue > 0 &&
      (uint64_t)generation.integerValue <= kMaxSafeInteger &&
      deadline.integerValue > 0 &&
      (uint64_t)deadline.integerValue <= kMaxSafeInteger &&
      deadline.integerValue > created.integerValue &&
      (uint64_t)(deadline.integerValue - created.integerValue) <=
          kMaximumDeadlineSeconds &&
      Exact(Field(map, @636, AncPrivateVaultCanonicalTypeBytes).bytesValue,
            64) &&
      !Same(oldBrokerId, issuerId) && !Same(candidateId, oldBrokerId) &&
      !Same(candidateId, issuerId);
  NSData *hash = structurallyValid
                     ? DomainHash(kFreezeDomain, sizeof kFreezeDomain,
                                  encodedApproval)
                     : nil;
  return hash.length == 32 ? [hash subdataWithRange:NSMakeRange(0, 16)] : nil;
}

static AncPrivateVaultControlLogMember *
Member(AncPrivateVaultControlLogState *state, NSData *endpointId) {
  NSString *hex = Hex(endpointId);
  if (hex == nil)
    return nil;
  for (AncPrivateVaultControlLogMember *member in state.activeMembers)
    if ([member.endpointId isEqualToString:hex])
      return member;
  return nil;
}

static AncPrivateVaultControlLogMember *
Issuer(AncPrivateVaultControlLogState *state, const uint8_t *signingSeed) {
  if (state == nil || signingSeed == NULL)
    return nil;
  uint8_t publicKey[32] = {0};
  uint8_t privateKey[64] = {0};
  BOOL derived = anc_pv_ed25519_seed_keypair(publicKey, privateKey,
                                              signingSeed) == ANC_PV_CRYPTO_OK;
  AncPrivateVaultControlLogMember *issuer = nil;
  NSUInteger matches = 0;
  if (derived) {
    for (AncPrivateVaultControlLogMember *member in state.activeMembers) {
      if ([member.role isEqualToString:@"endpoint"] && !member.unattended &&
          Exact(member.signingPublicKey, 32) &&
          anc_pv_memcmp(member.signingPublicKey.bytes, publicKey, 32) ==
              ANC_PV_CRYPTO_OK) {
        issuer = member;
        matches += 1;
      }
    }
  }
  anc_pv_zeroize(publicKey, sizeof publicKey);
  anc_pv_zeroize(privateKey, sizeof privateKey);
  return matches == 1 ? issuer : nil;
}

AncPrivateVaultEnrollmentSasReceipt *
AncPrivateVaultBrokerReplacementSasDecisionVerify(
    NSData *encodedOffer, NSData *encodedChallenge, NSData *encodedSasDecision,
    AncPrivateVaultControlLogState *state, NSData *oldBrokerEndpointId,
    uint64_t authenticatedHeadSignedAtSeconds, uint64_t nowSeconds,
    AncPrivateVaultBrokerReplacementApprovalStatus *status) {
  SetStatus(status, AncPrivateVaultBrokerReplacementApprovalStatusInvalid);
  AncPrivateVaultEnrollmentChallengeStatus challengeStatus;
  AncPrivateVaultEnrollmentChallengeResult *challenge =
      AncPrivateVaultBrokerReplacementChallengeVerify(
          encodedOffer, encodedChallenge, state, oldBrokerEndpointId,
          authenticatedHeadSignedAtSeconds, nowSeconds, &challengeStatus);
  if (challenge == nil) {
    SetStatus(status,
              challengeStatus == AncPrivateVaultEnrollmentChallengeStatusExpired
                  ? AncPrivateVaultBrokerReplacementApprovalStatusExpired
                  : AncPrivateVaultBrokerReplacementApprovalStatusConflict);
    return nil;
  }
  AncPrivateVaultEnrollmentSasReceiptStatus receiptStatus;
  AncPrivateVaultEnrollmentSasReceipt *receipt =
      AncPrivateVaultEnrollmentSasReceiptVerify(encodedSasDecision, challenge,
                                                &receiptStatus);
  if (receipt == nil ||
      receipt.decision != AncPrivateVaultEnrollmentSasDecisionConfirmed) {
    SetStatus(status,
              receiptStatus ==
                      AncPrivateVaultEnrollmentSasReceiptStatusInvalidSignature
                  ? AncPrivateVaultBrokerReplacementApprovalStatusInvalidSignature
                  : AncPrivateVaultBrokerReplacementApprovalStatusConflict);
    return nil;
  }
  SetStatus(status, AncPrivateVaultBrokerReplacementApprovalStatusOK);
  return receipt;
}

static NSDictionary<NSNumber *, AncPrivateVaultCanonicalValue *> *
UnsignedMap(NSData *vaultId, uint64_t createdAt, NSData *envelopeId,
            NSData *issuerEndpointId, NSData *oldBrokerEndpointId,
            NSData *candidateEndpointId, NSData *candidateSigningPublicKey,
            NSData *candidateAgreementPublicKey,
            NSData *candidateEnrollmentRef, NSData *offerHash,
            NSData *challengeHash, NSData *sasDecisionHash,
            uint64_t baseSequence, NSData *baseHead, NSData *baseMembership,
            uint64_t baseEpoch, NSData *drainId, uint64_t drainGeneration,
            uint64_t deadlineAt) {
  return @{
    @1 : [AncPrivateVaultCanonicalValue text:@"anc/v1"],
    @2 : [AncPrivateVaultCanonicalValue bytes:vaultId],
    @3 : [AncPrivateVaultCanonicalValue
        text:@"broker_replacement_approval"],
    @4 : [AncPrivateVaultCanonicalValue integer:(int64_t)createdAt],
    @5 : [AncPrivateVaultCanonicalValue bytes:envelopeId],
    @620 : [AncPrivateVaultCanonicalValue bytes:issuerEndpointId],
    @621 : [AncPrivateVaultCanonicalValue bytes:oldBrokerEndpointId],
    @622 : [AncPrivateVaultCanonicalValue bytes:candidateEndpointId],
    @623 : [AncPrivateVaultCanonicalValue bytes:candidateSigningPublicKey],
    @624 : [AncPrivateVaultCanonicalValue bytes:candidateAgreementPublicKey],
    @625 : [AncPrivateVaultCanonicalValue bytes:candidateEnrollmentRef],
    @626 : [AncPrivateVaultCanonicalValue bytes:offerHash],
    @627 : [AncPrivateVaultCanonicalValue bytes:challengeHash],
    @628 : [AncPrivateVaultCanonicalValue bytes:sasDecisionHash],
    @629 : [AncPrivateVaultCanonicalValue integer:(int64_t)baseSequence],
    @630 : [AncPrivateVaultCanonicalValue bytes:baseHead],
    @631 : [AncPrivateVaultCanonicalValue bytes:baseMembership],
    @632 : [AncPrivateVaultCanonicalValue integer:(int64_t)baseEpoch],
    @633 : [AncPrivateVaultCanonicalValue bytes:drainId],
    @634 : [AncPrivateVaultCanonicalValue integer:(int64_t)drainGeneration],
    @635 : [AncPrivateVaultCanonicalValue integer:(int64_t)deadlineAt],
  };
}

static NSData *SignedApproval(
    NSDictionary<NSNumber *, AncPrivateVaultCanonicalValue *> *unsignedMap,
    const uint8_t *signingSeed) {
  if (unsignedMap == nil || signingSeed == NULL)
    return nil;
  AncPrivateVaultCanonicalStatus canonicalStatus;
  NSData *unsignedBytes = AncPrivateVaultCanonicalEncode(
      [AncPrivateVaultCanonicalValue map:unsignedMap], &canonicalStatus);
  NSMutableData *message =
      [NSMutableData dataWithBytes:kApprovalDomain
                            length:sizeof kApprovalDomain];
  [message appendData:unsignedBytes];
  uint8_t publicKey[32] = {0};
  uint8_t privateKey[64] = {0};
  uint8_t signature[64] = {0};
  BOOL signedApproval = unsignedBytes != nil &&
      anc_pv_ed25519_seed_keypair(publicKey, privateKey, signingSeed) ==
          ANC_PV_CRYPTO_OK &&
      anc_pv_ed25519_sign(signature, message.bytes, message.length,
                          privateKey) == ANC_PV_CRYPTO_OK;
  anc_pv_zeroize(message.mutableBytes, message.length);
  anc_pv_zeroize(publicKey, sizeof publicKey);
  anc_pv_zeroize(privateKey, sizeof privateKey);
  NSData *encoded = nil;
  if (signedApproval) {
    NSMutableDictionary *signedMap = [unsignedMap mutableCopy];
    signedMap[@636] = [AncPrivateVaultCanonicalValue
        bytes:[NSData dataWithBytes:signature length:64]];
    encoded = AncPrivateVaultCanonicalEncode(
        [AncPrivateVaultCanonicalValue map:signedMap], &canonicalStatus);
  }
  anc_pv_zeroize(signature, sizeof signature);
  return encoded.length > 0 && encoded.length <= 1024 ? encoded : nil;
}

#if ANC_PRIVATE_VAULT_TESTING
NSData *AncPrivateVaultBrokerReplacementApprovalSignForTesting(
    NSData *vaultId, uint64_t createdAt, NSData *envelopeId,
    NSData *issuerEndpointId, NSData *oldBrokerEndpointId,
    NSData *candidateEndpointId, NSData *candidateSigningPublicKey,
    NSData *candidateAgreementPublicKey, NSData *offerHash,
    NSData *challengeHash, NSData *sasDecisionHash, uint64_t baseSequence,
    NSData *baseHead, NSData *baseMembership, uint64_t baseEpoch,
    NSData *drainId, uint64_t drainGeneration, uint64_t deadlineAt,
    const uint8_t *signingSeed) {
  return SignedApproval(
      UnsignedMap(vaultId, createdAt, envelopeId, issuerEndpointId,
                  oldBrokerEndpointId, candidateEndpointId,
                  candidateSigningPublicKey, candidateAgreementPublicKey,
                  envelopeId, offerHash, challengeHash, sasDecisionHash,
                  baseSequence, baseHead, baseMembership, baseEpoch, drainId,
                  drainGeneration, deadlineAt),
      signingSeed);
}
#endif

static AncPrivateVaultBrokerReplacementApproval *
ParsedApproval(NSData *encoded,
               NSDictionary<NSNumber *, AncPrivateVaultCanonicalValue *> *map) {
  NSData *freezeId =
      AncPrivateVaultBrokerReplacementApprovalFreezeId(encoded);
  if (freezeId == nil)
    return nil;
  AncPrivateVaultBrokerReplacementApproval *result = class_createInstance(
      AncPrivateVaultBrokerReplacementApproval.class, 0);
  result.encodedApproval = [encoded copy];
  result.freezeId = freezeId;
  result.createdAtSeconds =
      (uint64_t)Field(map, @4, AncPrivateVaultCanonicalTypeInteger).integerValue;
  result.envelopeId =
      [Field(map, @5, AncPrivateVaultCanonicalTypeBytes).bytesValue copy];
  result.issuerEndpointId =
      [Field(map, @620, AncPrivateVaultCanonicalTypeBytes).bytesValue copy];
  result.oldBrokerEndpointId =
      [Field(map, @621, AncPrivateVaultCanonicalTypeBytes).bytesValue copy];
  result.candidateBrokerEndpointId =
      [Field(map, @622, AncPrivateVaultCanonicalTypeBytes).bytesValue copy];
  result.candidateSigningPublicKey =
      [Field(map, @623, AncPrivateVaultCanonicalTypeBytes).bytesValue copy];
  result.candidateKeyAgreementPublicKey =
      [Field(map, @624, AncPrivateVaultCanonicalTypeBytes).bytesValue copy];
  result.candidateEnrollmentRef =
      [Field(map, @625, AncPrivateVaultCanonicalTypeBytes).bytesValue copy];
  result.offerHash =
      [Field(map, @626, AncPrivateVaultCanonicalTypeBytes).bytesValue copy];
  result.challengeHash =
      [Field(map, @627, AncPrivateVaultCanonicalTypeBytes).bytesValue copy];
  result.sasDecisionHash =
      [Field(map, @628, AncPrivateVaultCanonicalTypeBytes).bytesValue copy];
  result.baseSequence = (uint64_t)Field(
      map, @629, AncPrivateVaultCanonicalTypeInteger).integerValue;
  result.baseHeadHash =
      [Field(map, @630, AncPrivateVaultCanonicalTypeBytes).bytesValue copy];
  result.baseMembershipHash =
      [Field(map, @631, AncPrivateVaultCanonicalTypeBytes).bytesValue copy];
  result.baseEpoch = (uint64_t)Field(
      map, @632, AncPrivateVaultCanonicalTypeInteger).integerValue;
  result.drainId =
      [Field(map, @633, AncPrivateVaultCanonicalTypeBytes).bytesValue copy];
  result.drainGeneration = (uint64_t)Field(
      map, @634, AncPrivateVaultCanonicalTypeInteger).integerValue;
  result.deadlineAtSeconds = (uint64_t)Field(
      map, @635, AncPrivateVaultCanonicalTypeInteger).integerValue;
  return result;
}

AncPrivateVaultBrokerReplacementApproval *
AncPrivateVaultVerifyBrokerReplacementApproval(
    NSData *encoded, AncPrivateVaultControlLogState *state,
    NSData *oldBrokerEndpointId, NSData *candidateEndpointId,
    NSData *candidateSigningPublicKey, NSData *candidateAgreementPublicKey,
    NSData *candidateEnrollmentRef, NSData *offerHash, NSData *challengeHash,
    NSData *sasDecisionHash, NSData *drainId, uint64_t drainGeneration,
    uint64_t deadlineAt, uint64_t expectedCreatedAt, uint64_t nowSeconds,
    AncPrivateVaultBrokerReplacementApprovalStatus *status) {
  SetStatus(status, AncPrivateVaultBrokerReplacementApprovalStatusInvalid);
  @try {
    if (encoded.length == 0 || encoded.length > 1024 || state == nil ||
        !Exact(oldBrokerEndpointId, 16) || !Exact(candidateEndpointId, 16) ||
        !Exact(candidateSigningPublicKey, 32) ||
        !Exact(candidateAgreementPublicKey, 32) ||
        !Exact(candidateEnrollmentRef, 16) || !Exact(offerHash, 32) ||
        !Exact(challengeHash, 32) || !Exact(sasDecisionHash, 32) ||
        !Exact(drainId, 16) || drainGeneration == 0 || deadlineAt == 0 ||
        expectedCreatedAt == 0 || nowSeconds == 0 ||
        nowSeconds > kMaxSafeInteger)
      return nil;
    AncPrivateVaultCanonicalStatus canonicalStatus;
    AncPrivateVaultCanonicalValue *root =
        AncPrivateVaultCanonicalDecode(encoded, 1024, &canonicalStatus);
    NSDictionary<NSNumber *, AncPrivateVaultCanonicalValue *> *map =
        root.type == AncPrivateVaultCanonicalTypeMap ? root.mapValue : nil;
    NSArray<NSNumber *> *keys = @[
      @1, @2, @3, @4, @5, @620, @621, @622, @623, @624, @625, @626, @627,
      @628, @629, @630, @631, @632, @633, @634, @635, @636
    ];
    if (!ExactKeys(map, keys))
      return nil;
    AncPrivateVaultCanonicalValue *created =
        Field(map, @4, AncPrivateVaultCanonicalTypeInteger);
    AncPrivateVaultCanonicalValue *sequence =
        Field(map, @629, AncPrivateVaultCanonicalTypeInteger);
    AncPrivateVaultCanonicalValue *epoch =
        Field(map, @632, AncPrivateVaultCanonicalTypeInteger);
    AncPrivateVaultCanonicalValue *generation =
        Field(map, @634, AncPrivateVaultCanonicalTypeInteger);
    AncPrivateVaultCanonicalValue *deadline =
        Field(map, @635, AncPrivateVaultCanonicalTypeInteger);
    AncPrivateVaultCanonicalValue *signature =
        Field(map, @636, AncPrivateVaultCanonicalTypeBytes);
    NSData *vaultId = HexBytes(state.vaultId);
    NSData *issuerId =
        Field(map, @620, AncPrivateVaultCanonicalTypeBytes).bytesValue;
    BOOL valid =
        [Field(map, @1, AncPrivateVaultCanonicalTypeText).textValue
            isEqualToString:@"anc/v1"] &&
        Same(Field(map, @2, AncPrivateVaultCanonicalTypeBytes).bytesValue,
             vaultId) &&
        [Field(map, @3, AncPrivateVaultCanonicalTypeText).textValue
            isEqualToString:@"broker_replacement_approval"] &&
        created.integerValue > 0 &&
        (uint64_t)created.integerValue == expectedCreatedAt &&
        Exact(Field(map, @5, AncPrivateVaultCanonicalTypeBytes).bytesValue,
              16) &&
        Exact(issuerId, 16) &&
        Same(Field(map, @621, AncPrivateVaultCanonicalTypeBytes).bytesValue,
             oldBrokerEndpointId) &&
        Same(Field(map, @622, AncPrivateVaultCanonicalTypeBytes).bytesValue,
             candidateEndpointId) &&
        Same(Field(map, @623, AncPrivateVaultCanonicalTypeBytes).bytesValue,
             candidateSigningPublicKey) &&
        Same(Field(map, @624, AncPrivateVaultCanonicalTypeBytes).bytesValue,
             candidateAgreementPublicKey) &&
        Same(Field(map, @625, AncPrivateVaultCanonicalTypeBytes).bytesValue,
             candidateEnrollmentRef) &&
        Same(Field(map, @5, AncPrivateVaultCanonicalTypeBytes).bytesValue,
             candidateEnrollmentRef) &&
        Same(Field(map, @626, AncPrivateVaultCanonicalTypeBytes).bytesValue,
             offerHash) &&
        Same(Field(map, @627, AncPrivateVaultCanonicalTypeBytes).bytesValue,
             challengeHash) &&
        Same(Field(map, @628, AncPrivateVaultCanonicalTypeBytes).bytesValue,
             sasDecisionHash) &&
        sequence.integerValue > 0 &&
        (uint64_t)sequence.integerValue == state.sequence &&
        Same(Field(map, @630, AncPrivateVaultCanonicalTypeBytes).bytesValue,
             state.headHash) &&
        Same(Field(map, @631, AncPrivateVaultCanonicalTypeBytes).bytesValue,
             state.membershipHash) &&
        epoch.integerValue > 0 &&
        (uint64_t)epoch.integerValue == state.epoch &&
        Same(Field(map, @633, AncPrivateVaultCanonicalTypeBytes).bytesValue,
             drainId) &&
        generation.integerValue > 0 &&
        (uint64_t)generation.integerValue == drainGeneration &&
        deadline.integerValue > 0 &&
        (uint64_t)deadline.integerValue == deadlineAt &&
        Exact(signature.bytesValue, 64);
    if (!valid)
      return nil;
    uint64_t createdAt = (uint64_t)created.integerValue;
    if (createdAt > nowSeconds + 60 ||
        (createdAt <= nowSeconds && nowSeconds - createdAt > 900) ||
        deadlineAt <= nowSeconds || deadlineAt <= createdAt ||
        deadlineAt - createdAt > kMaximumDeadlineSeconds) {
      SetStatus(status, AncPrivateVaultBrokerReplacementApprovalStatusExpired);
      return nil;
    }
    if (Same(issuerId, oldBrokerEndpointId) ||
        Same(candidateEndpointId, oldBrokerEndpointId) ||
        Same(candidateEndpointId, issuerId)) {
      SetStatus(status, AncPrivateVaultBrokerReplacementApprovalStatusConflict);
      return nil;
    }
    AncPrivateVaultControlLogMember *issuer = Member(state, issuerId);
    AncPrivateVaultControlLogMember *oldBroker =
        Member(state, oldBrokerEndpointId);
    NSUInteger brokerCount = 0;
    for (AncPrivateVaultControlLogMember *member in state.activeMembers)
      if ([member.role isEqualToString:@"broker"])
        brokerCount += 1;
    NSString *candidateHex = Hex(candidateEndpointId);
    if (issuer == nil || ![issuer.role isEqualToString:@"endpoint"] ||
        issuer.unattended || !Exact(issuer.signingPublicKey, 32) ||
        oldBroker == nil || ![oldBroker.role isEqualToString:@"broker"] ||
        !oldBroker.unattended || brokerCount != 1 ||
        Member(state, candidateEndpointId) != nil ||
        [state.removedEndpointIds containsObject:candidateHex]) {
      SetStatus(status, AncPrivateVaultBrokerReplacementApprovalStatusConflict);
      return nil;
    }
    NSMutableDictionary *unsignedMap = [map mutableCopy];
    [unsignedMap removeObjectForKey:@636];
    NSData *unsignedBytes = AncPrivateVaultCanonicalEncode(
        [AncPrivateVaultCanonicalValue map:unsignedMap], &canonicalStatus);
    NSMutableData *message =
        [NSMutableData dataWithBytes:kApprovalDomain
                              length:sizeof kApprovalDomain];
    [message appendData:unsignedBytes];
    BOOL signatureValid = unsignedBytes != nil &&
        anc_pv_ed25519_verify(signature.bytesValue.bytes, message.bytes,
                              message.length, issuer.signingPublicKey.bytes) ==
            ANC_PV_CRYPTO_OK;
    anc_pv_zeroize(message.mutableBytes, message.length);
    if (!signatureValid) {
      SetStatus(status,
                AncPrivateVaultBrokerReplacementApprovalStatusInvalidSignature);
      return nil;
    }
    AncPrivateVaultBrokerReplacementApproval *result =
        ParsedApproval(encoded, map);
    SetStatus(status,
              result == nil
                  ? AncPrivateVaultBrokerReplacementApprovalStatusCryptoFailed
                  : AncPrivateVaultBrokerReplacementApprovalStatusOK);
    return result;
  } @catch (__unused NSException *exception) {
    SetStatus(status, AncPrivateVaultBrokerReplacementApprovalStatusInvalid);
    return nil;
  }
}

static BOOL RandomDistinctIds(uint8_t envelope[16], uint8_t drain[16]) {
  for (NSUInteger attempt = 0; attempt < 8; attempt += 1) {
    memset(envelope, 0, 16);
    memset(drain, 0, 16);
    if (SecRandomCopyBytes(kSecRandomDefault, 16, envelope) == errSecSuccess &&
        SecRandomCopyBytes(kSecRandomDefault, 16, drain) == errSecSuccess &&
        anc_pv_memcmp(envelope, (uint8_t[16]){0}, 16) != ANC_PV_CRYPTO_OK &&
        anc_pv_memcmp(drain, (uint8_t[16]){0}, 16) != ANC_PV_CRYPTO_OK &&
        anc_pv_memcmp(envelope, drain, 16) != ANC_PV_CRYPTO_OK)
      return YES;
  }
  return NO;
}

AncPrivateVaultBrokerReplacementApproval *
AncPrivateVaultBuildBrokerReplacementApproval(
    AncPrivateVaultControlLogState *state, NSData *encodedOffer,
    NSData *encodedChallenge, NSData *encodedSasDecision,
    NSData *oldBrokerEndpointId, uint64_t authenticatedHeadSignedAtSeconds,
    uint64_t nowSeconds, uint64_t deadlineAt,
    const uint8_t *issuerSigningSeed,
    AncPrivateVaultBrokerReplacementApprovalStatus *status) {
  SetStatus(status, AncPrivateVaultBrokerReplacementApprovalStatusInvalid);
  @try {
    if (state == nil || !Exact(oldBrokerEndpointId, 16) ||
        issuerSigningSeed == NULL || nowSeconds == 0 ||
        nowSeconds > kMaxSafeInteger)
      return nil;
    if (deadlineAt == 0) {
      if (nowSeconds > kMaxSafeInteger - kDefaultDeadlineSeconds)
        return nil;
      deadlineAt = nowSeconds + kDefaultDeadlineSeconds;
    }
    if (deadlineAt <= nowSeconds ||
        deadlineAt - nowSeconds > kMaximumDeadlineSeconds) {
      SetStatus(status, AncPrivateVaultBrokerReplacementApprovalStatusExpired);
      return nil;
    }
    AncPrivateVaultControlLogMember *issuer = Issuer(state, issuerSigningSeed);
    NSData *issuerId = issuer == nil ? nil : HexBytes(issuer.endpointId);
    if (issuerId == nil || Same(issuerId, oldBrokerEndpointId)) {
      SetStatus(status, AncPrivateVaultBrokerReplacementApprovalStatusConflict);
      return nil;
    }
    AncPrivateVaultBrokerReplacementApprovalStatus sasStatus;
    AncPrivateVaultEnrollmentSasReceipt *sas =
        AncPrivateVaultBrokerReplacementSasDecisionVerify(
            encodedOffer, encodedChallenge, encodedSasDecision, state,
            oldBrokerEndpointId, authenticatedHeadSignedAtSeconds, nowSeconds,
            &sasStatus);
    if (sas == nil) {
      SetStatus(status, sasStatus);
      return nil;
    }
    AncPrivateVaultEnrollmentChallengeStatus challengeStatus;
    AncPrivateVaultEnrollmentChallengeResult *challenge =
        AncPrivateVaultBrokerReplacementChallengeVerify(
            encodedOffer, encodedChallenge, state, oldBrokerEndpointId,
            authenticatedHeadSignedAtSeconds, nowSeconds, &challengeStatus);
    if (challenge == nil) {
      SetStatus(status, AncPrivateVaultBrokerReplacementApprovalStatusConflict);
      return nil;
    }
    uint8_t envelopeBytes[16] = {0};
    uint8_t drainBytes[16] = {0};
    if (!RandomDistinctIds(envelopeBytes, drainBytes)) {
      SetStatus(status,
                AncPrivateVaultBrokerReplacementApprovalStatusCryptoFailed);
      return nil;
    }
    NSData *envelopeId = [NSData dataWithBytes:envelopeBytes length:16];
    NSData *drainId = [NSData dataWithBytes:drainBytes length:16];
    anc_pv_zeroize(envelopeBytes, sizeof envelopeBytes);
    anc_pv_zeroize(drainBytes, sizeof drainBytes);
    NSData *vaultId = HexBytes(state.vaultId);
    NSDictionary *unsignedMap = UnsignedMap(
        vaultId, nowSeconds, envelopeId, issuerId, oldBrokerEndpointId,
        challenge.candidateEndpointId, challenge.candidateSigningPublicKey,
        challenge.candidateKeyAgreementPublicKey, envelopeId,
        challenge.offerHash, challenge.challengeHash, sas.receiptHash,
        state.sequence, state.headHash, state.membershipHash, state.epoch,
        drainId, 1, deadlineAt);
    NSData *encoded = SignedApproval(unsignedMap, issuerSigningSeed);
    if (encoded == nil) {
      SetStatus(status,
                AncPrivateVaultBrokerReplacementApprovalStatusEncodingFailed);
      return nil;
    }
    return AncPrivateVaultVerifyBrokerReplacementApproval(
        encoded, state, oldBrokerEndpointId, challenge.candidateEndpointId,
        challenge.candidateSigningPublicKey,
        challenge.candidateKeyAgreementPublicKey, envelopeId,
        challenge.offerHash, challenge.challengeHash, sas.receiptHash, drainId,
        1, deadlineAt, nowSeconds, nowSeconds, status);
  } @catch (__unused NSException *exception) {
    SetStatus(status, AncPrivateVaultBrokerReplacementApprovalStatusInvalid);
    return nil;
  }
}
