#import "PrivateVaultBrokerReplacementBuilder.h"

#import "PrivateVaultAncCanonical.h"
#import "PrivateVaultCrypto.h"
#import "PrivateVaultRecoveryWrap.h"
#import "PrivateVaultRecoveryWrapInternal.h"

#import <math.h>

static const uint8_t kDrainDomain[] = "anc/v1/broker-drain-attestation";
static const uint8_t kDrainCeremonyDomain[] = "anc/v1/broker-drain-ceremony";
static const uint8_t kWrapDomain[] = "anc/v1/recovery-wrap";
static const uint8_t kLogDomain[] = "anc/v1/log-entry";
static const uint64_t kMaximumSafeInteger = UINT64_C(9007199254740991);
static const NSUInteger kMaximumDrainAttestationBytes = 1024;

@interface AncPrivateVaultControlLogMember (BrokerReplacementBuilderWritable)
@property(nonatomic, readwrite) NSString *endpointId;
@property(nonatomic, readwrite) NSString *role;
@property(nonatomic, readwrite) BOOL unattended;
@property(nonatomic, readwrite) NSData *signingPublicKey;
@property(nonatomic, readwrite) NSData *keyAgreementPublicKey;
@property(nonatomic, readwrite) NSString *enrollmentRef;
@end

@interface AncPrivateVaultPreparedBrokerReplacement ()
- (instancetype)initPrivateWithEntry:(NSData *)entry
                                wrap:(NSData *)wrap
                          transcript:(NSData *)transcript
                           drainHash:(NSData *)drainHash
                           nextState:(AncPrivateVaultControlLogState *)state;
@end

@implementation AncPrivateVaultPreparedBrokerReplacement
@synthesize signedEntry = _signedEntry;
@synthesize recoveryWrap = _recoveryWrap;
@synthesize transcriptDigest = _transcriptDigest;
@synthesize drainAttestationHash = _drainAttestationHash;
@synthesize nextState = _nextState;
+ (BOOL)accessInstanceVariablesDirectly { return NO; }
- (instancetype)initPrivateWithEntry:(NSData *)entry
                                wrap:(NSData *)wrap
                          transcript:(NSData *)transcript
                           drainHash:(NSData *)drainHash
                           nextState:(AncPrivateVaultControlLogState *)state {
  self = [super init];
  if (self != nil) {
    _signedEntry = [entry copy];
    _recoveryWrap = [wrap copy];
    _transcriptDigest = [transcript copy];
    _drainAttestationHash = [drainHash copy];
    _nextState = state;
  }
  return self;
}
@end

static void SetStatus(AncPrivateVaultBrokerReplacementBuilderStatus *status,
                      AncPrivateVaultBrokerReplacementBuilderStatus value) {
  if (status != NULL)
    *status = value;
}
static AncPrivateVaultCanonicalValue *T(NSString *value) {
  return [AncPrivateVaultCanonicalValue text:value];
}
static AncPrivateVaultCanonicalValue *B(NSData *value) {
  return [AncPrivateVaultCanonicalValue bytes:value];
}
static AncPrivateVaultCanonicalValue *I(uint64_t value) {
  return value <= INT64_MAX
             ? [AncPrivateVaultCanonicalValue integer:(int64_t)value]
             : nil;
}
static AncPrivateVaultCanonicalValue *A(NSArray *value) {
  return [AncPrivateVaultCanonicalValue array:value];
}
static NSData *Encode(NSDictionary *map) {
  AncPrivateVaultCanonicalStatus status;
  NSData *encoded = AncPrivateVaultCanonicalEncode(
      [AncPrivateVaultCanonicalValue map:map], &status);
  return status == AncPrivateVaultCanonicalStatusOK ? encoded : nil;
}
static NSData *Exact(NSData *value, NSUInteger length) {
  return [value isKindOfClass:NSData.class] && value.length == length
             ? [NSData dataWithBytes:value.bytes length:length]
             : nil;
}
static NSData *HexData(NSString *hex, NSUInteger length) {
  if (![hex isKindOfClass:NSString.class] || hex.length != length * 2)
    return nil;
  NSMutableData *result = [NSMutableData dataWithLength:length];
  uint8_t *bytes = result.mutableBytes;
  for (NSUInteger index = 0; index < length; index++) {
    unichar high = [hex characterAtIndex:index * 2];
    unichar low = [hex characterAtIndex:index * 2 + 1];
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
static NSString *Hex(NSData *data) {
  if (![data isKindOfClass:NSData.class])
    return nil;
  NSMutableString *result = [NSMutableString stringWithCapacity:data.length * 2];
  const uint8_t *bytes = data.bytes;
  for (NSUInteger index = 0; index < data.length; index++)
    [result appendFormat:@"%02x", bytes[index]];
  return result;
}
static NSString *Timestamp(uint64_t seconds) {
  NSDate *date = [NSDate dateWithTimeIntervalSince1970:(NSTimeInterval)seconds];
  NSISO8601DateFormatter *formatter = [NSISO8601DateFormatter new];
  formatter.timeZone = [NSTimeZone timeZoneForSecondsFromGMT:0];
  formatter.formatOptions = NSISO8601DateFormatWithInternetDateTime |
                            NSISO8601DateFormatWithFractionalSeconds;
  return [formatter stringFromDate:date];
}
static BOOL TimestampSeconds(NSString *value, uint64_t *seconds) {
  if (![value isKindOfClass:NSString.class] || seconds == NULL)
    return NO;
  NSISO8601DateFormatter *formatter = [NSISO8601DateFormatter new];
  formatter.formatOptions = NSISO8601DateFormatWithInternetDateTime |
                            NSISO8601DateFormatWithFractionalSeconds;
  NSDate *date = [formatter dateFromString:value];
  if (date == nil) {
    formatter.formatOptions = NSISO8601DateFormatWithInternetDateTime;
    date = [formatter dateFromString:value];
  }
  NSTimeInterval interval = date.timeIntervalSince1970;
  if (date == nil || !isfinite(interval) || interval < 1 ||
      interval > (double)kMaximumSafeInteger - 1)
    return NO;
  *seconds = (uint64_t)ceil(interval);
  return *seconds > 0 && *seconds <= kMaximumSafeInteger;
}
static BOOL NonZero(NSData *value) {
  if (![value isKindOfClass:NSData.class] || value.length == 0)
    return NO;
  const uint8_t *bytes = value.bytes;
  uint8_t aggregate = 0;
  for (NSUInteger index = 0; index < value.length; index++)
    aggregate |= bytes[index];
  return aggregate != 0;
}
static NSData *Hash(const uint8_t *domain, size_t domainLength, NSData *data) {
  uint8_t digest[32] = {0};
  BOOL okay = data != nil &&
      anc_pv_blake2b_256_two_part(digest, domain, domainLength, data.bytes,
                                  data.length) == ANC_PV_CRYPTO_OK;
  NSData *result = okay ? [NSData dataWithBytes:digest length:32] : nil;
  anc_pv_zeroize(digest, sizeof digest);
  return result;
}
static NSData *Signature(const uint8_t *domain, size_t domainLength,
                         NSData *payload, const uint8_t seed[32],
                         NSData **publicKey) {
  uint8_t publicBytes[32] = {0}, privateBytes[64] = {0}, signature[64] = {0};
  NSMutableData *message = payload == nil ? nil
      : [NSMutableData dataWithBytes:domain length:domainLength];
  [message appendData:payload];
  BOOL okay = message != nil &&
      anc_pv_ed25519_seed_keypair(publicBytes, privateBytes, seed) ==
          ANC_PV_CRYPTO_OK &&
      anc_pv_ed25519_sign(signature, message.bytes, message.length,
                          privateBytes) == ANC_PV_CRYPTO_OK;
  NSData *result = okay ? [NSData dataWithBytes:signature length:64] : nil;
  if (publicKey != NULL)
    *publicKey = okay ? [NSData dataWithBytes:publicBytes length:32] : nil;
  anc_pv_zeroize(message.mutableBytes, message.length);
  anc_pv_zeroize(publicBytes, sizeof publicBytes);
  anc_pv_zeroize(privateBytes, sizeof privateBytes);
  anc_pv_zeroize(signature, sizeof signature);
  return result;
}
static AncPrivateVaultCanonicalValue *MemberValue(
    AncPrivateVaultControlLogMember *member) {
  return A(@[ T(member.endpointId), T(member.role),
              [AncPrivateVaultCanonicalValue boolean:member.unattended],
              B(member.signingPublicKey), B(member.keyAgreementPublicKey),
              T(member.enrollmentRef) ]);
}
static AncPrivateVaultControlLogMember *Issuer(
    AncPrivateVaultControlLogState *current, NSData *signingPublic,
    NSData *agreementPublic) {
  for (AncPrivateVaultControlLogMember *member in current.activeMembers)
    if ([member.role isEqualToString:@"endpoint"] && !member.unattended &&
        [member.signingPublicKey isEqualToData:signingPublic] &&
        (agreementPublic == nil ||
         [member.keyAgreementPublicKey isEqualToData:agreementPublic]))
      return member;
  return nil;
}

NSData *AncPrivateVaultCreateBrokerDrainAttestation(
    AncPrivateVaultControlLogState *current, NSData *oldBrokerId,
    NSData *candidateId, NSData *candidateSigning, NSData *candidateAgreement,
    NSData *candidateEnrollment, NSData *envelopeId, uint64_t createdAt,
    uint64_t drainGeneration, uint64_t drainedJobCount, NSData *drainDigest,
    uint64_t outstandingJobCount, const uint8_t issuerSigningSeed[32],
    AncPrivateVaultBrokerReplacementBuilderStatus *status) {
  SetStatus(status, AncPrivateVaultBrokerReplacementBuilderStatusInvalidArgument);
  NSData *vault = HexData(current.vaultId, 16);
  uint64_t authenticatedCreatedAt = 0;
  if (current == nil || vault == nil || Exact(oldBrokerId, 16) == nil ||
      Exact(candidateId, 16) == nil || Exact(candidateSigning, 32) == nil ||
      Exact(candidateAgreement, 32) == nil ||
      Exact(candidateEnrollment, 16) == nil || Exact(envelopeId, 16) == nil ||
      Exact(drainDigest, 32) == nil || issuerSigningSeed == NULL ||
      createdAt == 0 || createdAt > kMaximumSafeInteger ||
      drainGeneration == 0 || drainGeneration > kMaximumSafeInteger ||
      drainedJobCount > kMaximumSafeInteger ||
      outstandingJobCount > kMaximumSafeInteger || current.sequence == 0 ||
      current.sequence > kMaximumSafeInteger || current.epoch == 0 ||
      current.epoch > kMaximumSafeInteger || current.headHash.length != 32 ||
      !TimestampSeconds(current.signedAt, &authenticatedCreatedAt) ||
      createdAt != authenticatedCreatedAt)
    return nil;
  NSData *issuerPublic = nil;
  NSData *probe = Signature(kDrainDomain, sizeof kDrainDomain, [NSData data],
                            issuerSigningSeed, &issuerPublic);
  (void)probe;
  AncPrivateVaultControlLogMember *issuer = Issuer(current, issuerPublic, nil);
  if (issuer == nil) {
    SetStatus(status, AncPrivateVaultBrokerReplacementBuilderStatusIssuerRejected);
    return nil;
  }
  NSMutableDictionary *map = [@{
    @1:T(@"anc/v1"), @2:B(vault), @3:T(@"broker_drain_attestation"),
    @4:I(createdAt), @5:B(envelopeId),
    @600:B(HexData(issuer.endpointId, 16)), @601:B(oldBrokerId),
    @602:B(candidateId), @603:B(candidateSigning),
    @604:B(candidateAgreement), @605:B(candidateEnrollment),
    @606:I(current.sequence), @607:B(current.headHash), @608:I(current.epoch),
    @609:I(drainGeneration), @610:I(drainedJobCount), @611:B(drainDigest),
    @612:I(outstandingJobCount),
  } mutableCopy];
  NSData *unsignedBytes = Encode(map);
  NSData *signature = Signature(kDrainDomain, sizeof kDrainDomain,
                                unsignedBytes, issuerSigningSeed, NULL);
  if (unsignedBytes == nil || signature == nil) {
    SetStatus(status, AncPrivateVaultBrokerReplacementBuilderStatusCryptoFailed);
    return nil;
  }
  map[@613] = B(signature);
  NSData *encoded = Encode(map);
  if (encoded == nil || encoded.length > kMaximumDrainAttestationBytes) {
    SetStatus(status, AncPrivateVaultBrokerReplacementBuilderStatusEncodingFailed);
    return nil;
  }
  SetStatus(status, AncPrivateVaultBrokerReplacementBuilderStatusOK);
  return encoded;
}

NSData *AncPrivateVaultBrokerReplacementCeremonyId(NSData *attestation) {
  if (![attestation isKindOfClass:NSData.class] || attestation.length == 0 ||
      attestation.length > kMaximumDrainAttestationBytes)
    return nil;
  NSData *digest = Hash(kDrainCeremonyDomain, sizeof kDrainCeremonyDomain,
                        attestation);
  return digest.length == 32 ? [digest subdataWithRange:NSMakeRange(0, 16)] : nil;
}

static BOOL VerifyDrain(NSData *encoded, AncPrivateVaultControlLogState *current,
                        AncPrivateVaultControlLogMember *issuer,
                        NSData *oldBrokerId, NSData *candidateId,
                        NSData *candidateSigning, NSData *candidateAgreement,
                        NSData *candidateEnrollment, uint64_t trustedNow,
                        uint64_t *createdAt) {
  AncPrivateVaultCanonicalStatus canonicalStatus;
  AncPrivateVaultCanonicalValue *root = AncPrivateVaultCanonicalDecode(
      encoded, kMaximumDrainAttestationBytes, &canonicalStatus);
  NSDictionary<NSNumber *, AncPrivateVaultCanonicalValue *> *map =
      root.type == AncPrivateVaultCanonicalTypeMap ? root.mapValue : nil;
  NSSet *keys = [NSSet setWithArray:@[@1,@2,@3,@4,@5,@600,@601,@602,@603,
                                      @604,@605,@606,@607,@608,@609,@610,@611,
                                      @612,@613]];
  if (canonicalStatus != AncPrivateVaultCanonicalStatusOK ||
      map.count != keys.count ||
      ![keys isEqualToSet:[NSSet setWithArray:map.allKeys]] ||
      map[@1].type != AncPrivateVaultCanonicalTypeText ||
      ![map[@1].textValue isEqualToString:@"anc/v1"] ||
      map[@2].type != AncPrivateVaultCanonicalTypeBytes ||
      ![map[@2].bytesValue isEqualToData:HexData(current.vaultId, 16)] ||
      map[@3].type != AncPrivateVaultCanonicalTypeText ||
      ![map[@3].textValue isEqualToString:@"broker_drain_attestation"] ||
      map[@4].type != AncPrivateVaultCanonicalTypeInteger ||
      map[@4].integerValue <= 0 ||
      map[@5].type != AncPrivateVaultCanonicalTypeBytes ||
      map[@5].bytesValue.length != 16 ||
      map[@600].type != AncPrivateVaultCanonicalTypeBytes ||
      ![map[@600].bytesValue isEqualToData:HexData(issuer.endpointId, 16)] ||
      map[@601].type != AncPrivateVaultCanonicalTypeBytes ||
      ![map[@601].bytesValue isEqualToData:oldBrokerId] ||
      map[@602].type != AncPrivateVaultCanonicalTypeBytes ||
      ![map[@602].bytesValue isEqualToData:candidateId] ||
      map[@603].type != AncPrivateVaultCanonicalTypeBytes ||
      ![map[@603].bytesValue isEqualToData:candidateSigning] ||
      map[@604].type != AncPrivateVaultCanonicalTypeBytes ||
      ![map[@604].bytesValue isEqualToData:candidateAgreement] ||
      map[@605].type != AncPrivateVaultCanonicalTypeBytes ||
      ![map[@605].bytesValue isEqualToData:candidateEnrollment] ||
      map[@606].type != AncPrivateVaultCanonicalTypeInteger ||
      map[@606].integerValue != (int64_t)current.sequence ||
      map[@607].type != AncPrivateVaultCanonicalTypeBytes ||
      ![map[@607].bytesValue isEqualToData:current.headHash] ||
      map[@608].type != AncPrivateVaultCanonicalTypeInteger ||
      map[@608].integerValue != (int64_t)current.epoch ||
      map[@609].type != AncPrivateVaultCanonicalTypeInteger ||
      map[@609].integerValue <= 0 ||
      map[@610].type != AncPrivateVaultCanonicalTypeInteger ||
      map[@610].integerValue < 0 ||
      map[@611].type != AncPrivateVaultCanonicalTypeBytes ||
      map[@611].bytesValue.length != 32 ||
      map[@612].type != AncPrivateVaultCanonicalTypeInteger ||
      map[@612].integerValue != 0 ||
      map[@613].type != AncPrivateVaultCanonicalTypeBytes ||
      map[@613].bytesValue.length != 64)
    return NO;
  uint64_t baseCreatedAt = 0;
  uint64_t drainCreatedAt = (uint64_t)map[@4].integerValue;
  uint64_t futureLimit = trustedNow > kMaximumSafeInteger - UINT64_C(60)
      ? kMaximumSafeInteger : trustedNow + UINT64_C(60);
  if (createdAt == NULL || trustedNow == 0 ||
      trustedNow > kMaximumSafeInteger ||
      !TimestampSeconds(current.signedAt, &baseCreatedAt) ||
      drainCreatedAt != baseCreatedAt || drainCreatedAt > futureLimit ||
      (trustedNow > drainCreatedAt &&
       trustedNow - drainCreatedAt > UINT64_C(900)))
    return NO;
  NSMutableDictionary *unsignedMap = [map mutableCopy];
  [unsignedMap removeObjectForKey:@613];
  NSData *unsignedBytes = Encode(unsignedMap);
  NSMutableData *message = unsignedBytes == nil ? nil
      : [NSMutableData dataWithBytes:kDrainDomain length:sizeof kDrainDomain];
  [message appendData:unsignedBytes];
  BOOL verified = message != nil &&
      anc_pv_ed25519_verify(map[@613].bytesValue.bytes, message.bytes,
                            message.length, issuer.signingPublicKey.bytes) ==
          ANC_PV_CRYPTO_OK;
  anc_pv_zeroize(message.mutableBytes, message.length);
  if (verified)
    *createdAt = drainCreatedAt;
  return verified;
}

AncPrivateVaultPreparedBrokerReplacement *AncPrivateVaultBuildBrokerReplacement(
    AncPrivateVaultControlLogState *current, NSData *oldBrokerId,
    NSData *candidateId, NSData *candidateSigning, NSData *candidateAgreement,
    NSData *candidateEnrollment, NSData *drainAttestation,
    NSData *wrapEnvelopeId, NSData *entryEnvelopeId, NSData *wrapNonce,
    uint64_t trustedNow, const uint8_t pendingKey[32],
    const uint8_t signingSeed[32], const uint8_t agreementSeed[32],
    AncPrivateVaultBrokerReplacementBuilderStatus *status) {
  SetStatus(status, AncPrivateVaultBrokerReplacementBuilderStatusInvalidArgument);
  NSData *oldId = Exact(oldBrokerId, 16), *candidate = Exact(candidateId, 16);
  NSData *candidateSign = Exact(candidateSigning, 32);
  NSData *candidateAgree = Exact(candidateAgreement, 32);
  NSData *candidateEnroll = Exact(candidateEnrollment, 16);
  NSData *wrapEnvelope = Exact(wrapEnvelopeId, 16);
  NSData *entryEnvelope = Exact(entryEnvelopeId, 16);
  NSData *nonce = Exact(wrapNonce, 24);
  NSData *vault = HexData(current.vaultId, 16);
  NSData *ceremony = AncPrivateVaultBrokerReplacementCeremonyId(drainAttestation);
  uint64_t createdAt = 0;
  if (current == nil || oldId == nil || candidate == nil ||
      [oldId isEqualToData:candidate] || candidateSign == nil ||
      candidateAgree == nil || candidateEnroll == nil ||
      !NonZero(candidateSign) || !NonZero(candidateAgree) || ceremony == nil ||
      wrapEnvelope == nil || entryEnvelope == nil || nonce == nil ||
      vault == nil || pendingKey == NULL || signingSeed == NULL ||
      agreementSeed == NULL || trustedNow == 0 ||
      trustedNow > kMaximumSafeInteger || current.sequence >= kMaximumSafeInteger ||
      current.epoch >= kMaximumSafeInteger || current.headHash.length != 32 ||
      current.membershipHash.length != 32 || current.recoveryGeneration == 0 ||
      current.recoveryId.length != 32 ||
      current.recoverySigningPublicKey.length != 32 ||
      current.recoveryKeyAgreementPublicKey.length != 32)
    return nil;

  NSData *issuerPublic = nil;
  NSData *probe = Signature(kLogDomain, sizeof kLogDomain, [NSData data],
                            signingSeed, &issuerPublic);
  (void)probe;
  uint8_t agreementPublicBytes[32] = {0}, agreementPrivate[32] = {0};
  BOOL agreementOkay = anc_pv_box_seed_keypair(
      agreementPublicBytes, agreementPrivate, agreementSeed) == ANC_PV_CRYPTO_OK;
  NSData *agreementPublic = agreementOkay
      ? [NSData dataWithBytes:agreementPublicBytes length:32] : nil;
  AncPrivateVaultControlLogMember *issuer =
      Issuer(current, issuerPublic, agreementPublic);
  AncPrivateVaultControlLogMember *oldBroker = nil;
  NSUInteger brokerCount = 0;
  NSString *oldHex = Hex(oldId), *candidateHex = Hex(candidate);
  for (AncPrivateVaultControlLogMember *member in current.activeMembers) {
    if ([member.role isEqualToString:@"broker"]) {
      brokerCount += 1;
      if ([member.endpointId isEqualToString:oldHex])
        oldBroker = member;
    }
  }
  if (issuer == nil) {
    anc_pv_zeroize(agreementPrivate, sizeof agreementPrivate);
    anc_pv_zeroize(agreementPublicBytes, sizeof agreementPublicBytes);
    SetStatus(status, AncPrivateVaultBrokerReplacementBuilderStatusIssuerRejected);
    return nil;
  }
  if (brokerCount != 1 || oldBroker == nil ||
      [issuer.endpointId isEqualToString:oldHex] ||
      [[current.activeMembers valueForKey:@"endpointId"] containsObject:candidateHex] ||
      [current.removedEndpointIds containsObject:candidateHex]) {
    anc_pv_zeroize(agreementPrivate, sizeof agreementPrivate);
    anc_pv_zeroize(agreementPublicBytes, sizeof agreementPublicBytes);
    SetStatus(status, AncPrivateVaultBrokerReplacementBuilderStatusBrokerRejected);
    return nil;
  }
  if (!VerifyDrain(drainAttestation, current, issuer, oldId, candidate,
                   candidateSign, candidateAgree, candidateEnroll, trustedNow,
                   &createdAt)) {
    anc_pv_zeroize(agreementPrivate, sizeof agreementPrivate);
    anc_pv_zeroize(agreementPublicBytes, sizeof agreementPublicBytes);
    SetStatus(status, AncPrivateVaultBrokerReplacementBuilderStatusDrainRejected);
    return nil;
  }

  uint8_t plaintext[48] = {0}, ciphertext[64] = {0};
  memcpy(plaintext, "anc/v1/eek-wrap", 16);
  memcpy(plaintext + 16, pendingKey, 32);
  size_t written = 0;
  BOOL wrapped = agreementOkay &&
      anc_pv_box_wrap(ciphertext, sizeof ciphertext, &written, plaintext,
                      sizeof plaintext, nonce.bytes,
                      current.recoveryKeyAgreementPublicKey.bytes,
                      agreementPrivate) == ANC_PV_CRYPTO_OK &&
      written == sizeof ciphertext;
  anc_pv_zeroize(plaintext, sizeof plaintext);
  anc_pv_zeroize(agreementPrivate, sizeof agreementPrivate);
  anc_pv_zeroize(agreementPublicBytes, sizeof agreementPublicBytes);
  if (!wrapped) {
    anc_pv_zeroize(ciphertext, sizeof ciphertext);
    SetStatus(status, AncPrivateVaultBrokerReplacementBuilderStatusCryptoFailed);
    return nil;
  }

  NSMutableDictionary *wrapMap = [@{
    @1:T(@"anc/v1"), @2:B(vault), @3:T(@"recovery-wrap"), @4:I(createdAt),
    @5:B(wrapEnvelope), @400:B(ceremony), @401:I(current.recoveryGeneration),
    @402:B(HexData(current.recoveryId, 16)),
    @403:B(current.recoveryKeyAgreementPublicKey), @404:I(current.epoch + 1),
    @405:B(HexData(issuer.endpointId, 16)), @406:I(current.sequence + 1),
    @407:B(current.headHash), @408:B(current.membershipHash), @409:B(nonce),
    @410:B([NSData dataWithBytes:ciphertext length:sizeof ciphertext]),
  } mutableCopy];
  anc_pv_zeroize(ciphertext, sizeof ciphertext);
  NSData *wrapUnsigned = Encode(wrapMap);
  wrapMap[@411] = B(Signature(kWrapDomain, sizeof kWrapDomain, wrapUnsigned,
                              signingSeed, NULL));
  NSData *wrap = Encode(wrapMap);
  NSData *wrapHash = Hash(kWrapDomain, sizeof kWrapDomain, wrap);

  AncPrivateVaultControlLogMember *newBroker = [AncPrivateVaultControlLogMember new];
  newBroker.endpointId = candidateHex;
  newBroker.role = @"broker";
  newBroker.unattended = YES;
  newBroker.signingPublicKey = candidateSign;
  newBroker.keyAgreementPublicKey = candidateAgree;
  newBroker.enrollmentRef = Hex(candidateEnroll);
  NSMutableArray *nextMembers = [NSMutableArray array];
  for (AncPrivateVaultControlLogMember *member in current.activeMembers)
    if (member != oldBroker)
      [nextMembers addObject:member];
  [nextMembers addObject:newBroker];
  [nextMembers sortUsingComparator:^NSComparisonResult(
      AncPrivateVaultControlLogMember *left,
      AncPrivateVaultControlLogMember *right) {
    return [left.endpointId compare:right.endpointId];
  }];
  NSMutableArray *memberValues = [NSMutableArray array];
  for (AncPrivateVaultControlLogMember *member in nextMembers)
    [memberValues addObject:MemberValue(member)];
  NSDictionary *innerMap = @{
    @1:T(@"anc/v1"), @2:T(current.vaultId), @3:T(@"membership_commit"),
    @140:T(Hex(ceremony)), @141:T(@"broker_replacement"),
    @142:I(current.epoch + 1), @143:B(current.membershipHash),
    @144:A(memberValues), @145:A(@[T(oldHex)]),
    @146:[AncPrivateVaultCanonicalValue boolean:YES],
    @147:[AncPrivateVaultCanonicalValue boolean:YES],
    @148:[AncPrivateVaultCanonicalValue nullValue],
    @149:[AncPrivateVaultCanonicalValue nullValue],
    @155:I(current.recoveryGeneration), @156:T(current.recoveryId),
    @157:B(current.recoverySigningPublicKey),
    @158:B(current.recoveryKeyAgreementPublicKey), @159:B(wrapHash),
  };
  NSData *inner = Encode(innerMap);
  NSMutableDictionary *entryMap = [@{
    @1:T(@"anc/v1"), @2:T(current.vaultId), @3:T(@"log-entry"),
    @4:T(Timestamp(createdAt)), @5:T(Hex(entryEnvelope)),
    @110:I(current.sequence + 1), @111:B(current.headHash), @112:B(inner),
    @113:T(issuer.endpointId),
  } mutableCopy];
  NSData *entryUnsigned = Encode(entryMap);
  entryMap[@114] = B(Signature(kLogDomain, sizeof kLogDomain, entryUnsigned,
                               signingSeed, NULL));
  NSData *entry = Encode(entryMap);
  AncPrivateVaultRecoveryWrapRotationVerifier *verifier =
      [[AncPrivateVaultRecoveryWrapRotationVerifier alloc]
          initWithEncodedWrap:wrap trustedNowMilliseconds:createdAt * 1000];
  AncPrivateVaultControlLogReplayResult *replay = nil;
  AncPrivateVaultControlLogStatus replayStatus =
      entry == nil || verifier == nil ? AncPrivateVaultControlLogStatusFailed
      : [[AncPrivateVaultControlLog new] replaySignedEntry:entry
                                             currentState:current
                                                 verifier:verifier
                                                   result:&replay];
  if (wrap == nil || wrapHash == nil || inner == nil || entry == nil ||
      replayStatus != AncPrivateVaultControlLogStatusOK || replay == nil ||
      !verifier.isVerified || replay.state.activeMembers.count != nextMembers.count ||
      ![[replay.state.activeMembers valueForKey:@"endpointId"] containsObject:candidateHex] ||
      [[replay.state.activeMembers valueForKey:@"endpointId"] containsObject:oldHex] ||
      replay.state.epoch != current.epoch + 1 ||
      replay.state.sequence != current.sequence + 1 ||
      ![replay.state.recoveryWrapHash isEqualToData:wrapHash]) {
    SetStatus(status, AncPrivateVaultBrokerReplacementBuilderStatusVerificationFailed);
    return nil;
  }
  NSData *drainHash = Hash(kDrainCeremonyDomain, sizeof kDrainCeremonyDomain,
                           drainAttestation);
  SetStatus(status, AncPrivateVaultBrokerReplacementBuilderStatusOK);
  return [[AncPrivateVaultPreparedBrokerReplacement alloc]
      initPrivateWithEntry:entry wrap:wrap
                transcript:replay.state.membershipHash drainHash:drainHash
                 nextState:replay.state];
}
