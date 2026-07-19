#import <Foundation/Foundation.h>

#import "PrivateVaultAncCanonical.h"
#import "PrivateVaultBrokerReplacementApproval.h"
#import "PrivateVaultCrypto.h"
#import "PrivateVaultEnrollmentAuthorizer.h"
#import "PrivateVaultEnrollmentOffer.h"
#import "PrivateVaultGuardedMemory.h"

#include <assert.h>

@interface AncPrivateVaultControlLogMember (BrokerApprovalTests)
@property(nonatomic, readwrite) NSString *endpointId;
@property(nonatomic, readwrite) NSString *role;
@property(nonatomic, readwrite) BOOL unattended;
@property(nonatomic, readwrite) NSData *signingPublicKey;
@property(nonatomic, readwrite) NSData *keyAgreementPublicKey;
@property(nonatomic, readwrite) NSString *enrollmentRef;
@end

@interface AncPrivateVaultControlLogState (BrokerApprovalTests)
@property(nonatomic, readwrite) NSString *vaultId;
@property(nonatomic, readwrite) uint64_t sequence;
@property(nonatomic, readwrite) NSData *headHash;
@property(nonatomic, readwrite) NSData *membershipHash;
@property(nonatomic, readwrite) NSString *signedAt;
@property(nonatomic, readwrite)
    NSArray<AncPrivateVaultControlLogMember *> *activeMembers;
@property(nonatomic, readwrite) NSArray<NSString *> *removedEndpointIds;
@property(nonatomic, readwrite) uint64_t epoch;
@property(nonatomic, readwrite) uint64_t recoveryGeneration;
@property(nonatomic, readwrite) NSString *recoveryId;
@property(nonatomic, readwrite) NSData *recoverySigningPublicKey;
@property(nonatomic, readwrite) NSData *recoveryKeyAgreementPublicKey;
@property(nonatomic, readwrite) NSData *recoveryWrapHash;
@property(nonatomic, readwrite) NSString *freshnessMode;
@end

FOUNDATION_EXPORT NSData *
AncPrivateVaultBrokerReplacementApprovalSignForTesting(
    NSData *vaultId, uint64_t createdAt, NSData *envelopeId,
    NSData *issuerEndpointId, NSData *oldBrokerEndpointId,
    NSData *candidateEndpointId, NSData *candidateSigningPublicKey,
    NSData *candidateAgreementPublicKey, NSData *offerHash,
    NSData *challengeHash, NSData *sasDecisionHash, uint64_t baseSequence,
    NSData *baseHead, NSData *baseMembership, uint64_t baseEpoch,
    NSData *drainId, uint64_t drainGeneration, uint64_t deadlineAt,
    const uint8_t *signingSeed);

static NSData *Range(uint8_t start, NSUInteger length) {
  NSMutableData *result = [NSMutableData dataWithLength:length];
  uint8_t *bytes = result.mutableBytes;
  for (NSUInteger index = 0; index < length; index += 1)
    bytes[index] = (uint8_t)(start + index);
  return result;
}

static NSData *Repeated(uint8_t byte, NSUInteger length) {
  NSMutableData *result = [NSMutableData dataWithLength:length];
  memset(result.mutableBytes, byte, length);
  return result;
}

static NSString *HexString(NSData *data) {
  NSMutableString *result = [NSMutableString string];
  const uint8_t *bytes = data.bytes;
  for (NSUInteger index = 0; index < data.length; index += 1)
    [result appendFormat:@"%02x", bytes[index]];
  return result;
}

static NSData *Hex(NSString *hex) {
  NSMutableData *result = [NSMutableData dataWithLength:hex.length / 2];
  uint8_t *bytes = result.mutableBytes;
  for (NSUInteger index = 0; index < result.length; index += 1) {
    unsigned value = 0;
    assert(sscanf([[hex substringWithRange:NSMakeRange(index * 2, 2)] UTF8String],
                  "%2x", &value) == 1);
    bytes[index] = (uint8_t)value;
  }
  return result;
}

static AncPrivateVaultControlLogMember *Member(
    NSData *endpointId, NSString *role, BOOL unattended, NSData *signing,
    NSData *agreement, NSData *enrollmentRef) {
  AncPrivateVaultControlLogMember *member =
      [[AncPrivateVaultControlLogMember alloc] init];
  member.endpointId = HexString(endpointId);
  member.role = role;
  member.unattended = unattended;
  member.signingPublicKey = signing;
  member.keyAgreementPublicKey = agreement;
  member.enrollmentRef = HexString(enrollmentRef);
  return member;
}

static AncPrivateVaultControlLogState *State(
    NSData *vaultId, AncPrivateVaultControlLogMember *issuer,
    AncPrivateVaultControlLogMember *broker, uint64_t sequence, NSData *head,
    NSData *membership, uint64_t epoch) {
  AncPrivateVaultControlLogState *state =
      [[AncPrivateVaultControlLogState alloc] init];
  state.vaultId = HexString(vaultId);
  state.sequence = sequence;
  state.headHash = head;
  state.membershipHash = membership;
  state.signedAt = @"2026-07-19T12:00:00.000Z";
  state.activeMembers = @[ issuer, broker ];
  state.removedEndpointIds = @[];
  state.epoch = epoch;
  state.recoveryGeneration = 1;
  state.recoveryId = HexString(Repeated(0x91, 16));
  state.recoverySigningPublicKey = Repeated(0x92, 32);
  state.recoveryKeyAgreementPublicKey = Repeated(0x93, 32);
  state.recoveryWrapHash = Repeated(0x94, 32);
  state.freshnessMode = @"endpoint_witnessed";
  return state;
}

static AncPrivateVaultGuardedMemory *Guarded(const uint8_t seed[32]) {
  AncPrivateVaultGuardedMemoryStatus status;
  AncPrivateVaultGuardedMemory *memory =
      [AncPrivateVaultGuardedMemory memoryWithLength:32 status:&status];
  assert(memory != nil &&
         [memory borrow:^BOOL(uint8_t *bytes, size_t length) {
           assert(length == 32);
           memcpy(bytes, seed, 32);
           return YES;
         }] == AncPrivateVaultGuardedMemoryStatusOK);
  return memory;
}

static void FrozenVector(void) {
  uint8_t issuerSeed[32] = {0};
  for (NSUInteger index = 0; index < 32; index += 1)
    issuerSeed[index] = (uint8_t)(0xe0 + index);
  NSString *frozenHex =
      @"b60166616e632f76310250000102030405060708090a0b0c0d0e0f03781b62726f"
       "6b65725f7265706c6163656d656e745f617070726f76616c041a6a5c946905501011"
       "12131415161718191a1b1c1d1e1f19026c50202122232425262728292a2b2c2d2e2f"
       "19026d50303132333435363738393a3b3c3d3e3f19026e50404142434445464748494a"
       "4b4c4d4e4f19026f5820505152535455565758595a5b5c5d5e5f6061626364656667"
       "68696a6b6c6d6e6f1902705820707172737475767778797a7b7c7d7e7f8081828384"
       "85868788898a8b8c8d8e8f19027150101112131415161718191a1b1c1d1e1f190272"
       "5820909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf"
       "1902735820b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacb"
       "cccdcecf1902745820d0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7"
       "e8e9eaebecedeeef190275181f19027658201112131415161718191a1b1c1d1e1f20"
       "2122232425262728292a2b2c2d2e2f3019027758203132333435363738393a3b3c3d"
       "3e3f404142434445464748494a4b4c4d4e4f5019027807190279506162636465666768"
       "696a6b6c6d6e6f7019027a0b19027b1a6a5ca27919027c584000879828e6fbee5989"
       "d05e59cd6b998d826bf40c66d2afbe5116240d64110c0e42e1d7a184fce9d75f4d8"
       "f9ae18432215c5aed4e857f754fccdc198515344800";
  NSData *encoded = AncPrivateVaultBrokerReplacementApprovalSignForTesting(
      Range(0x00, 16), UINT64_C(1784452201), Range(0x10, 16),
      Range(0x20, 16), Range(0x30, 16), Range(0x40, 16), Range(0x50, 32),
      Range(0x70, 32), Range(0x90, 32), Range(0xb0, 32), Range(0xd0, 32), 31,
      Range(0x11, 32), Range(0x31, 32), 7, Range(0x61, 16), 11,
      UINT64_C(1784455801), issuerSeed);
  assert([encoded isEqualToData:Hex(frozenHex)]);
  assert([[AncPrivateVaultBrokerReplacementApprovalFreezeId(encoded)
      description] length] > 0);
  assert([AncPrivateVaultBrokerReplacementApprovalFreezeId(encoded)
      isEqualToData:Hex(@"ae073b3a1fe16f05bb2eb869e7970778")]);
  assert(AncPrivateVaultBrokerReplacementApprovalFreezeId(
             [encoded subdataWithRange:NSMakeRange(0, encoded.length - 1)]) ==
         nil);
  assert(AncPrivateVaultBrokerReplacementApprovalFreezeId(
             [@"not-an-approval" dataUsingEncoding:NSUTF8StringEncoding]) ==
         nil);

  uint8_t issuerPublic[32] = {0}, issuerPrivate[64] = {0};
  assert(anc_pv_ed25519_seed_keypair(issuerPublic, issuerPrivate, issuerSeed) ==
         ANC_PV_CRYPTO_OK);
  AncPrivateVaultControlLogState *state = State(
      Range(0x00, 16),
      Member(Range(0x20, 16), @"endpoint", NO,
             [NSData dataWithBytes:issuerPublic length:32], Repeated(0x22, 32),
             Repeated(0x23, 16)),
      Member(Range(0x30, 16), @"broker", YES, Repeated(0x33, 32),
             Repeated(0x34, 32), Repeated(0x35, 16)),
      31, Range(0x11, 32), Range(0x31, 32), 7);
  __block AncPrivateVaultBrokerReplacementApprovalStatus status =
      AncPrivateVaultBrokerReplacementApprovalStatusInvalid;
  AncPrivateVaultBrokerReplacementApproval *(^verify)(NSData *, uint64_t) =
      ^AncPrivateVaultBrokerReplacementApproval *(NSData *value,
                                                  uint64_t now) {
        return AncPrivateVaultVerifyBrokerReplacementApproval(
            value, state, Range(0x30, 16), Range(0x40, 16), Range(0x50, 32),
            Range(0x70, 32), Range(0x10, 16), Range(0x90, 32),
            Range(0xb0, 32), Range(0xd0, 32), Range(0x61, 16), 11,
            UINT64_C(1784455801), UINT64_C(1784452201), now, &status);
      };
  AncPrivateVaultBrokerReplacementApproval *verified =
      verify(encoded, UINT64_C(1784452201));
  assert(status == AncPrivateVaultBrokerReplacementApprovalStatusOK &&
         verified != nil);
  AncPrivateVaultCanonicalStatus canonicalStatus;
  AncPrivateVaultCanonicalValue *root =
      AncPrivateVaultCanonicalDecode(encoded, 1024, &canonicalStatus);
  NSMutableDictionary *extraMap = [root.mapValue mutableCopy];
  extraMap[@637] = [AncPrivateVaultCanonicalValue integer:1];
  NSData *extra = AncPrivateVaultCanonicalEncode(
      [AncPrivateVaultCanonicalValue map:extraMap], &canonicalStatus);
  assert(verify(extra, UINT64_C(1784452201)) == nil &&
         status == AncPrivateVaultBrokerReplacementApprovalStatusInvalid);
  assert(AncPrivateVaultBrokerReplacementApprovalFreezeId(extra) == nil);
  NSMutableDictionary *missingMap = [root.mapValue mutableCopy];
  [missingMap removeObjectForKey:@626];
  NSData *missing = AncPrivateVaultCanonicalEncode(
      [AncPrivateVaultCanonicalValue map:missingMap], &canonicalStatus);
  assert(verify(missing, UINT64_C(1784452201)) == nil &&
         status == AncPrivateVaultBrokerReplacementApprovalStatusInvalid);
  assert(AncPrivateVaultBrokerReplacementApprovalFreezeId(missing) == nil);
  NSMutableDictionary *wrongSuiteMap = [root.mapValue mutableCopy];
  wrongSuiteMap[@1] = [AncPrivateVaultCanonicalValue text:@"anc/v2"];
  NSData *wrongSuite = AncPrivateVaultCanonicalEncode(
      [AncPrivateVaultCanonicalValue map:wrongSuiteMap], &canonicalStatus);
  assert(AncPrivateVaultBrokerReplacementApprovalFreezeId(wrongSuite) == nil);
  NSMutableData *oversized = [NSMutableData dataWithLength:1025];
  assert(verify(oversized, UINT64_C(1784452201)) == nil &&
         status == AncPrivateVaultBrokerReplacementApprovalStatusInvalid);
  assert(verify(encoded, UINT64_C(1784453102)) == nil &&
         status == AncPrivateVaultBrokerReplacementApprovalStatusExpired);
  assert(verify(encoded, UINT64_C(1784455801)) == nil &&
         status == AncPrivateVaultBrokerReplacementApprovalStatusExpired);
  anc_pv_zeroize(issuerSeed, sizeof issuerSeed);
  anc_pv_zeroize(issuerPublic, sizeof issuerPublic);
  anc_pv_zeroize(issuerPrivate, sizeof issuerPrivate);
}

static void LiveBuilder(void) {
  uint8_t issuerSigningSeed[32] = {0x11};
  uint8_t issuerAgreementSeed[32] = {0x12};
  uint8_t candidateSigningSeed[32] = {0x21};
  uint8_t candidateAgreementSeed[32] = {0x22};
  uint8_t issuerSigningPublic[32] = {0}, issuerSigningPrivate[64] = {0};
  uint8_t issuerAgreementPublic[32] = {0}, issuerAgreementPrivate[32] = {0};
  assert(anc_pv_ed25519_seed_keypair(issuerSigningPublic,
                                     issuerSigningPrivate,
                                     issuerSigningSeed) == ANC_PV_CRYPTO_OK);
  assert(anc_pv_box_seed_keypair(issuerAgreementPublic, issuerAgreementPrivate,
                                 issuerAgreementSeed) == ANC_PV_CRYPTO_OK);
  NSData *vaultId = Repeated(0x01, 16);
  NSData *issuerId = Repeated(0x02, 16);
  NSData *oldBrokerId = Repeated(0x04, 16);
  NSData *candidateId = Repeated(0x03, 16);
  AncPrivateVaultControlLogState *state = State(
      vaultId,
      Member(issuerId, @"endpoint", NO,
             [NSData dataWithBytes:issuerSigningPublic length:32],
             [NSData dataWithBytes:issuerAgreementPublic length:32],
             Repeated(0x10, 16)),
      Member(oldBrokerId, @"broker", YES, Repeated(0x44, 32),
             Repeated(0x55, 32), Repeated(0x66, 16)),
      9, Repeated(0x71, 32), Repeated(0x72, 32), 7);
  AncPrivateVaultEnrollmentOfferStatus offerStatus;
  AncPrivateVaultEnrollmentOfferResult *offer =
      AncPrivateVaultEnrollmentOfferBuild(
          vaultId, candidateId, Repeated(0x0c, 16), Repeated(0x0e, 16),
          Repeated(0xa5, 32), @"broker", YES, 1721111111, 1721111711,
          candidateSigningSeed, candidateAgreementSeed, &offerStatus);
  assert(offerStatus == AncPrivateVaultEnrollmentOfferStatusOK && offer != nil);
  AncPrivateVaultGuardedMemory *signingGuard = Guarded(issuerSigningSeed);
  AncPrivateVaultGuardedMemory *agreementGuard = Guarded(issuerAgreementSeed);
  AncPrivateVaultEnrollmentAuthorizerStatus challengeStatus;
  AncPrivateVaultPreparedEnrollmentChallenge *challenge =
      AncPrivateVaultBuildBrokerReplacementChallenge(
          offer.encodedOffer, offer.candidateKeyProof, state, oldBrokerId,
          signingGuard, agreementGuard, Repeated(0x0f, 16),
          Repeated(0xa7, 32), 1721111100, 1721111120, 1721111720,
          &challengeStatus);
  assert(challengeStatus == AncPrivateVaultEnrollmentAuthorizerStatusOK &&
         challenge != nil);
  assert(AncPrivateVaultBuildEnrollmentChallenge(
             offer.encodedOffer, offer.candidateKeyProof, state, signingGuard,
             agreementGuard, Repeated(0x0f, 16), Repeated(0xa7, 32),
             1721111100, 1721111120, 1721111720, &challengeStatus) == nil &&
         challengeStatus ==
             AncPrivateVaultEnrollmentAuthorizerStatusVerification);
  AncPrivateVaultEnrollmentSasReceiptStatus receiptStatus;
  AncPrivateVaultEnrollmentSasReceipt *receipt =
      AncPrivateVaultEnrollmentSasReceiptBuild(
          challenge.verifiedChallenge, Repeated(0x45, 16), 1721111130,
          AncPrivateVaultEnrollmentSasDecisionConfirmed,
          candidateSigningSeed, &receiptStatus);
  assert(receiptStatus == AncPrivateVaultEnrollmentSasReceiptStatusOK &&
         receipt != nil);
  AncPrivateVaultBrokerReplacementApprovalStatus approvalStatus;
  assert(AncPrivateVaultBrokerReplacementSasDecisionVerify(
             offer.encodedOffer, challenge.encodedChallenge,
             receipt.encodedReceipt, state, oldBrokerId, 1721111100,
             1721111131, &approvalStatus) != nil &&
         approvalStatus == AncPrivateVaultBrokerReplacementApprovalStatusOK);
  AncPrivateVaultBrokerReplacementApproval *approval =
      AncPrivateVaultBuildBrokerReplacementApproval(
          state, offer.encodedOffer, challenge.encodedChallenge,
          receipt.encodedReceipt, oldBrokerId, 1721111100, 1721111131, 0,
          issuerSigningSeed, &approvalStatus);
  assert(approvalStatus == AncPrivateVaultBrokerReplacementApprovalStatusOK &&
         approval != nil && approval.encodedApproval.length <= 1024 &&
         approval.drainGeneration == 1 &&
         approval.deadlineAtSeconds == UINT64_C(1721114731) &&
         [approval.candidateEnrollmentRef isEqualToData:approval.envelopeId]);

  AncPrivateVaultControlLogState *extraBroker = State(
      vaultId, state.activeMembers[0], state.activeMembers[1], 9,
      Repeated(0x71, 32), Repeated(0x72, 32), 7);
  extraBroker.activeMembers = [extraBroker.activeMembers
      arrayByAddingObject:Member(Repeated(0x07, 16), @"broker", YES,
                                Repeated(0x08, 32), Repeated(0x09, 32),
                                Repeated(0x0a, 16))];
  AncPrivateVaultEnrollmentChallengeStatus verifyStatus;
  assert(AncPrivateVaultBrokerReplacementChallengeVerify(
             offer.encodedOffer, challenge.encodedChallenge, extraBroker,
             oldBrokerId, 1721111100, 1721111131, &verifyStatus) == nil &&
         verifyStatus == AncPrivateVaultEnrollmentChallengeStatusConflict);

  NSMutableData *tampered = [approval.encodedApproval mutableCopy];
  ((uint8_t *)tampered.mutableBytes)[tampered.length - 1] ^= 1;
  assert(AncPrivateVaultVerifyBrokerReplacementApproval(
             tampered, state, oldBrokerId, approval.candidateBrokerEndpointId,
             approval.candidateSigningPublicKey,
             approval.candidateKeyAgreementPublicKey,
             approval.candidateEnrollmentRef, approval.offerHash,
             approval.challengeHash, approval.sasDecisionHash,
             approval.drainId, 1, approval.deadlineAtSeconds,
             approval.createdAtSeconds, approval.createdAtSeconds,
             &approvalStatus) == nil &&
         approvalStatus ==
             AncPrivateVaultBrokerReplacementApprovalStatusInvalidSignature);

  assert([signingGuard close] == AncPrivateVaultGuardedMemoryStatusOK);
  assert([agreementGuard close] == AncPrivateVaultGuardedMemoryStatusOK);
  anc_pv_zeroize(issuerSigningSeed, sizeof issuerSigningSeed);
  anc_pv_zeroize(issuerAgreementSeed, sizeof issuerAgreementSeed);
  anc_pv_zeroize(candidateSigningSeed, sizeof candidateSigningSeed);
  anc_pv_zeroize(candidateAgreementSeed, sizeof candidateAgreementSeed);
  anc_pv_zeroize(issuerSigningPublic, sizeof issuerSigningPublic);
  anc_pv_zeroize(issuerSigningPrivate, sizeof issuerSigningPrivate);
  anc_pv_zeroize(issuerAgreementPublic, sizeof issuerAgreementPublic);
  anc_pv_zeroize(issuerAgreementPrivate, sizeof issuerAgreementPrivate);
}

int main(void) {
  @autoreleasepool {
    assert(anc_pv_crypto_init() == ANC_PV_CRYPTO_OK);
    FrozenVector();
    LiveBuilder();
    puts("private-vault broker replacement approval tests passed");
  }
  return 0;
}
