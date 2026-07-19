#import <Foundation/Foundation.h>

#import "PrivateVaultAncCanonical.h"
#import "PrivateVaultBrokerReplacementBuilder.h"
#import "PrivateVaultCrypto.h"

#include <assert.h>

@interface AncPrivateVaultControlLogMember (BrokerReplacementTest)
@property(nonatomic, readwrite) NSString *endpointId;
@property(nonatomic, readwrite) NSString *role;
@property(nonatomic, readwrite) BOOL unattended;
@property(nonatomic, readwrite) NSData *signingPublicKey;
@property(nonatomic, readwrite) NSData *keyAgreementPublicKey;
@property(nonatomic, readwrite) NSString *enrollmentRef;
@end
@interface AncPrivateVaultControlLogState (BrokerReplacementTest)
@property(nonatomic, readwrite) NSString *vaultId;
@property(nonatomic, readwrite) uint64_t sequence;
@property(nonatomic, readwrite) NSData *headHash;
@property(nonatomic, readwrite) NSData *membershipHash;
@property(nonatomic, readwrite) NSString *signedAt;
@property(nonatomic, readwrite) NSArray *activeMembers;
@property(nonatomic, readwrite) NSArray *removedEndpointIds;
@property(nonatomic, readwrite) uint64_t epoch;
@property(nonatomic, readwrite) uint64_t recoveryGeneration;
@property(nonatomic, readwrite) NSString *recoveryId;
@property(nonatomic, readwrite) NSData *recoverySigningPublicKey;
@property(nonatomic, readwrite) NSData *recoveryKeyAgreementPublicKey;
@property(nonatomic, readwrite) NSData *recoveryWrapHash;
@property(nonatomic, readwrite) NSString *freshnessMode;
@end

static NSData *Bytes(uint8_t byte, NSUInteger length) {
  NSMutableData *value = [NSMutableData dataWithLength:length];
  memset(value.mutableBytes, byte, length);
  return value;
}
static NSData *Range(uint8_t first, NSUInteger length) {
  NSMutableData *value = [NSMutableData dataWithLength:length];
  uint8_t *bytes = value.mutableBytes;
  for (NSUInteger index = 0; index < length; index++)
    bytes[index] = (uint8_t)(first + index);
  return value;
}
static NSData *DataFromHex(NSString *hex) {
  assert(hex.length % 2 == 0);
  NSMutableData *value = [NSMutableData dataWithLength:hex.length / 2];
  uint8_t *bytes = value.mutableBytes;
  for (NSUInteger index = 0; index < value.length; index++) {
    unsigned int byte = 0;
    NSString *pair = [hex substringWithRange:NSMakeRange(index * 2, 2)];
    assert([[NSScanner scannerWithString:pair] scanHexInt:&byte]);
    bytes[index] = (uint8_t)byte;
  }
  return value;
}
static NSString *Hex(NSData *value) {
  NSMutableString *result = [NSMutableString string];
  const uint8_t *bytes = value.bytes;
  for (NSUInteger index = 0; index < value.length; index++)
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
static AncPrivateVaultControlLogMember *Member(
    NSData *identifier, NSString *role, BOOL unattended, NSData *signing,
    NSData *agreement, uint8_t enrollment) {
  AncPrivateVaultControlLogMember *member = [AncPrivateVaultControlLogMember new];
  member.endpointId = Hex(identifier);
  member.role = role;
  member.unattended = unattended;
  member.signingPublicKey = signing;
  member.keyAgreementPublicKey = agreement;
  member.enrollmentRef = Hex(Bytes(enrollment, 16));
  return member;
}
static AncPrivateVaultControlLogState *State(
    NSData *issuerId, NSData *oldBrokerId, NSData *issuerSigning,
    NSData *issuerAgreement, NSData *recoveryAgreement) {
  AncPrivateVaultControlLogState *state = [AncPrivateVaultControlLogState new];
  state.vaultId = Hex(Bytes(0x20, 16));
  state.sequence = 7;
  state.headHash = Bytes(0x31, 32);
  state.membershipHash = Bytes(0x32, 32);
  state.signedAt = Timestamp(UINT64_C(1721296802));
  state.activeMembers = @[
    Member(issuerId, @"endpoint", NO, issuerSigning, issuerAgreement, 0x41),
    Member(oldBrokerId, @"broker", YES, Bytes(0x45, 32), Bytes(0x46, 32), 0x47),
  ];
  state.removedEndpointIds = @[];
  state.epoch = 3;
  state.recoveryGeneration = 2;
  state.recoveryId = Hex(Bytes(0x48, 16));
  state.recoverySigningPublicKey = Bytes(0x49, 32);
  state.recoveryKeyAgreementPublicKey = recoveryAgreement;
  state.recoveryWrapHash = Bytes(0x4a, 32);
  state.freshnessMode = @"endpoint_witnessed";
  return state;
}

static NSData *Drain(AncPrivateVaultControlLogState *state, NSData *oldBrokerId,
                     NSData *candidateId, NSData *candidateSigning,
                     NSData *candidateAgreement, NSData *candidateEnrollment,
                     const uint8_t signingSeed[32], uint64_t outstanding,
                     AncPrivateVaultBrokerReplacementBuilderStatus *status) {
  return AncPrivateVaultCreateBrokerDrainAttestation(
      state, oldBrokerId, candidateId, candidateSigning, candidateAgreement,
      candidateEnrollment, Bytes(0x50, 16), UINT64_C(1721296802), 9, 12,
      Bytes(0x51, 32), outstanding, signingSeed, status);
}

int main(void) {
  @autoreleasepool {
    assert(anc_pv_crypto_init() == ANC_PV_CRYPTO_OK);
    {
      uint8_t vectorSeed[32], vectorPublic[32], vectorPrivate[64];
      for (NSUInteger index = 0; index < 32; index++)
        vectorSeed[index] = (uint8_t)(0xe0 + index);
      assert(anc_pv_ed25519_seed_keypair(vectorPublic, vectorPrivate,
                                         vectorSeed) == ANC_PV_CRYPTO_OK);
      AncPrivateVaultControlLogState *vectorState =
          [AncPrivateVaultControlLogState new];
      vectorState.vaultId = Hex(Range(0x00, 16));
      vectorState.sequence = 31;
      vectorState.headHash = Range(0xa0, 32);
      vectorState.membershipHash = Bytes(0x44, 32);
      vectorState.signedAt = Timestamp(UINT64_C(1784452201));
      vectorState.activeMembers = @[
        Member(Range(0x20, 16), @"endpoint", NO,
               [NSData dataWithBytes:vectorPublic length:32], Bytes(0x01, 32),
               0x02),
        Member(Range(0x30, 16), @"broker", YES, Bytes(0x03, 32),
               Bytes(0x04, 32), 0x05),
      ];
      vectorState.removedEndpointIds = @[];
      vectorState.epoch = 7;
      vectorState.recoveryGeneration = 1;
      vectorState.recoveryId = Hex(Bytes(0x06, 16));
      vectorState.recoverySigningPublicKey = Bytes(0x07, 32);
      vectorState.recoveryKeyAgreementPublicKey = Bytes(0x08, 32);
      vectorState.recoveryWrapHash = Bytes(0x09, 32);
      vectorState.freshnessMode = @"endpoint_witnessed";
      AncPrivateVaultBrokerReplacementBuilderStatus vectorStatus;
      NSData *vector = AncPrivateVaultCreateBrokerDrainAttestation(
          vectorState, Range(0x30, 16), Range(0x40, 16), Range(0x50, 32),
          Range(0x70, 32), Range(0x90, 16), Range(0x10, 16),
          UINT64_C(1784452201), 11, 23, Range(0xc0, 32), 0, vectorSeed,
          &vectorStatus);
      NSString *expectedHex =
          @"b30166616e632f76310250000102030405060708090a0b0c0d0e0f03781862726f6b65725f647261696e5f6174746573746174696f6e041a6a5c94690550101112131415161718191a1b1c1d1e1f19025850202122232425262728292a2b2c2d2e2f19025950303132333435363738393a3b3c3d3e3f19025a50404142434445464748494a4b4c4d4e4f19025b5820505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f19025c5820707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f19025d50909192939495969798999a9b9c9d9e9f19025e181f19025f5820a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf190260071902610b190262171902635820c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf1902640019026558405bc0e8e5c0ea88d7e7c27c3ca7b058032df3bcbde664310312083be858b139f91dce9a23fc308a0a9a0a2e986b1f5f0f70729ea7e803302a0af03b84f0c68805";
      assert(vectorStatus == AncPrivateVaultBrokerReplacementBuilderStatusOK &&
             [vector isEqualToData:DataFromHex(expectedHex)] &&
             [AncPrivateVaultBrokerReplacementCeremonyId(vector)
                 isEqualToData:DataFromHex(@"ad7d174cac3f8e5784c199cd50841d33")]);
      anc_pv_zeroize(vectorSeed, sizeof vectorSeed);
      anc_pv_zeroize(vectorPublic, sizeof vectorPublic);
      anc_pv_zeroize(vectorPrivate, sizeof vectorPrivate);
    }
    uint8_t signingSeed[32], agreementSeed[32], pending[32], recoverySeed[32];
    memset(signingSeed, 0x11, 32);
    memset(agreementSeed, 0x12, 32);
    memset(pending, 0x13, 32);
    memset(recoverySeed, 0x14, 32);
    uint8_t signingPublic[32], signingPrivate[64], agreementPublic[32],
        agreementPrivate[32], recoveryPublic[32], recoveryPrivate[32];
    assert(anc_pv_ed25519_seed_keypair(signingPublic, signingPrivate,
                                       signingSeed) == ANC_PV_CRYPTO_OK);
    assert(anc_pv_box_seed_keypair(agreementPublic, agreementPrivate,
                                   agreementSeed) == ANC_PV_CRYPTO_OK);
    assert(anc_pv_box_seed_keypair(recoveryPublic, recoveryPrivate,
                                   recoverySeed) == ANC_PV_CRYPTO_OK);
    NSData *issuerId = Bytes(0x21, 16), *oldBrokerId = Bytes(0x22, 16),
           *candidateId = Bytes(0x23, 16), *candidateSigning = Bytes(0x24, 32),
           *candidateAgreement = Bytes(0x25, 32),
           *candidateEnrollment = Bytes(0x26, 16);
    AncPrivateVaultControlLogState *state = State(
        issuerId, oldBrokerId, [NSData dataWithBytes:signingPublic length:32],
        [NSData dataWithBytes:agreementPublic length:32],
        [NSData dataWithBytes:recoveryPublic length:32]);
    AncPrivateVaultBrokerReplacementBuilderStatus status;
    NSData *drain = Drain(state, oldBrokerId, candidateId, candidateSigning,
                          candidateAgreement, candidateEnrollment, signingSeed,
                          0, &status);
    assert(drain.length > 0 &&
           status == AncPrivateVaultBrokerReplacementBuilderStatusOK);
    NSData *ceremony = AncPrivateVaultBrokerReplacementCeremonyId(drain);
    assert(ceremony.length == 16);
    AncPrivateVaultPreparedBrokerReplacement *result =
        AncPrivateVaultBuildBrokerReplacement(
            state, oldBrokerId, candidateId, candidateSigning,
            candidateAgreement, candidateEnrollment, drain, Bytes(0x52, 16),
            Bytes(0x53, 16), Bytes(0x54, 24), UINT64_C(1721296802), pending,
            signingSeed, agreementSeed, &status);
    assert(result != nil &&
           status == AncPrivateVaultBrokerReplacementBuilderStatusOK);
    assert(result.signedEntry.length > 0 && result.recoveryWrap.length > 0 &&
           result.transcriptDigest.length == 32 &&
           result.drainAttestationHash.length == 32 &&
           result.nextState.sequence == 8 && result.nextState.epoch == 4 &&
           [[result.nextState.activeMembers valueForKey:@"endpointId"]
               containsObject:Hex(candidateId)] &&
           ![[result.nextState.activeMembers valueForKey:@"endpointId"]
               containsObject:Hex(oldBrokerId)] &&
           [result.nextState.removedEndpointIds containsObject:Hex(oldBrokerId)]);

    AncPrivateVaultPreparedBrokerReplacement *retry =
        AncPrivateVaultBuildBrokerReplacement(
            state, oldBrokerId, candidateId, candidateSigning,
            candidateAgreement, candidateEnrollment, drain, Bytes(0x52, 16),
            Bytes(0x53, 16), Bytes(0x54, 24), UINT64_C(1721296802), pending,
            signingSeed, agreementSeed, &status);
    assert(retry != nil && [retry.signedEntry isEqualToData:result.signedEntry] &&
           [retry.recoveryWrap isEqualToData:result.recoveryWrap] &&
           [retry.drainAttestationHash isEqualToData:result.drainAttestationHash]);

    uint64_t freshDrainTime = UINT64_C(1721296922);
    NSData *freshDrain = AncPrivateVaultCreateBrokerDrainAttestation(
        state, oldBrokerId, candidateId, candidateSigning,
        candidateAgreement, candidateEnrollment, Bytes(0x55, 16),
        freshDrainTime, 10, 12, Bytes(0x56, 32), 0, signingSeed, &status);
    assert(freshDrain.length > 0 &&
           AncPrivateVaultBuildBrokerReplacement(
               state, oldBrokerId, candidateId, candidateSigning,
               candidateAgreement, candidateEnrollment, freshDrain,
               Bytes(0x57, 16), Bytes(0x58, 16), Bytes(0x59, 24),
               freshDrainTime, pending, signingSeed, agreementSeed,
               &status) != nil);
    assert(AncPrivateVaultBuildBrokerReplacement(
               state, oldBrokerId, candidateId, candidateSigning,
               candidateAgreement, candidateEnrollment, freshDrain,
               Bytes(0x57, 16), Bytes(0x58, 16), Bytes(0x59, 24),
               freshDrainTime + UINT64_C(901), pending, signingSeed,
               agreementSeed, &status) == nil &&
           status == AncPrivateVaultBrokerReplacementBuilderStatusDrainRejected);
    assert(AncPrivateVaultBuildBrokerReplacement(
               state, oldBrokerId, candidateId, candidateSigning,
               candidateAgreement, candidateEnrollment, freshDrain,
               Bytes(0x57, 16), Bytes(0x58, 16), Bytes(0x59, 24),
               freshDrainTime - UINT64_C(61), pending, signingSeed,
               agreementSeed, &status) == nil &&
           status == AncPrivateVaultBrokerReplacementBuilderStatusDrainRejected);
    assert(AncPrivateVaultCreateBrokerDrainAttestation(
               state, oldBrokerId, candidateId, candidateSigning,
               candidateAgreement, candidateEnrollment, Bytes(0x55, 16),
               UINT64_C(1721296801), 10, 12, Bytes(0x56, 32), 0,
               signingSeed, &status) == nil);

    NSData *unresolved = Drain(state, oldBrokerId, candidateId, candidateSigning,
                               candidateAgreement, candidateEnrollment,
                               signingSeed, 1, &status);
    assert(unresolved.length > 0);
    assert(AncPrivateVaultBuildBrokerReplacement(
               state, oldBrokerId, candidateId, candidateSigning,
               candidateAgreement, candidateEnrollment, unresolved,
               Bytes(0x52, 16), Bytes(0x53, 16), Bytes(0x54, 24),
               UINT64_C(1721296802), pending, signingSeed, agreementSeed,
               &status) == nil &&
           status == AncPrivateVaultBrokerReplacementBuilderStatusDrainRejected);
    assert(AncPrivateVaultBuildBrokerReplacement(
               state, oldBrokerId, oldBrokerId, candidateSigning,
               candidateAgreement, candidateEnrollment, drain, Bytes(0x52, 16),
               Bytes(0x53, 16), Bytes(0x54, 24), UINT64_C(1721296802), pending,
               signingSeed, agreementSeed, &status) == nil);

    AncPrivateVaultControlLogState *wrongHead = State(
        issuerId, oldBrokerId, [NSData dataWithBytes:signingPublic length:32],
        [NSData dataWithBytes:agreementPublic length:32],
        [NSData dataWithBytes:recoveryPublic length:32]);
    wrongHead.headHash = Bytes(0xee, 32);
    assert(AncPrivateVaultBuildBrokerReplacement(
               wrongHead, oldBrokerId, candidateId, candidateSigning,
               candidateAgreement, candidateEnrollment, drain, Bytes(0x52, 16),
               Bytes(0x53, 16), Bytes(0x54, 24), UINT64_C(1721296802), pending,
               signingSeed, agreementSeed, &status) == nil &&
           status == AncPrivateVaultBrokerReplacementBuilderStatusDrainRejected);

    AncPrivateVaultControlLogState *wrongEpoch = State(
        issuerId, oldBrokerId, [NSData dataWithBytes:signingPublic length:32],
        [NSData dataWithBytes:agreementPublic length:32],
        [NSData dataWithBytes:recoveryPublic length:32]);
    wrongEpoch.epoch += 1;
    assert(AncPrivateVaultBuildBrokerReplacement(
               wrongEpoch, oldBrokerId, candidateId, candidateSigning,
               candidateAgreement, candidateEnrollment, drain, Bytes(0x52, 16),
               Bytes(0x53, 16), Bytes(0x54, 24), UINT64_C(1721296802), pending,
               signingSeed, agreementSeed, &status) == nil &&
           status == AncPrivateVaultBrokerReplacementBuilderStatusDrainRejected);
    AncPrivateVaultControlLogState *wrongVault = State(
        issuerId, oldBrokerId, [NSData dataWithBytes:signingPublic length:32],
        [NSData dataWithBytes:agreementPublic length:32],
        [NSData dataWithBytes:recoveryPublic length:32]);
    wrongVault.vaultId = Hex(Bytes(0xef, 16));
    assert(AncPrivateVaultBuildBrokerReplacement(
               wrongVault, oldBrokerId, candidateId, candidateSigning,
               candidateAgreement, candidateEnrollment, drain, Bytes(0x52, 16),
               Bytes(0x53, 16), Bytes(0x54, 24), UINT64_C(1721296802), pending,
               signingSeed, agreementSeed, &status) == nil &&
           status == AncPrivateVaultBrokerReplacementBuilderStatusDrainRejected);
    NSMutableData *tamperedDrain = [drain mutableCopy];
    ((uint8_t *)tamperedDrain.mutableBytes)[tamperedDrain.length / 2] ^= 1;
    assert(AncPrivateVaultBuildBrokerReplacement(
               state, oldBrokerId, candidateId, candidateSigning,
               candidateAgreement, candidateEnrollment, tamperedDrain,
               Bytes(0x52, 16), Bytes(0x53, 16), Bytes(0x54, 24),
               UINT64_C(1721296802), pending, signingSeed, agreementSeed,
               &status) == nil &&
           status == AncPrivateVaultBrokerReplacementBuilderStatusDrainRejected);

    uint8_t brokerSeed[32], brokerPublic[32], brokerPrivate[64];
    memset(brokerSeed, 0x33, sizeof brokerSeed);
    assert(anc_pv_ed25519_seed_keypair(brokerPublic, brokerPrivate,
                                       brokerSeed) == ANC_PV_CRYPTO_OK);
    AncPrivateVaultControlLogState *brokerIssuer = State(
        issuerId, oldBrokerId, [NSData dataWithBytes:signingPublic length:32],
        [NSData dataWithBytes:agreementPublic length:32],
        [NSData dataWithBytes:recoveryPublic length:32]);
    AncPrivateVaultControlLogMember *brokerMember = brokerIssuer.activeMembers[1];
    brokerMember.signingPublicKey =
        [NSData dataWithBytes:brokerPublic length:sizeof brokerPublic];
    assert(AncPrivateVaultCreateBrokerDrainAttestation(
               brokerIssuer, oldBrokerId, candidateId, candidateSigning,
               candidateAgreement, candidateEnrollment, Bytes(0x50, 16),
               UINT64_C(1721296802), 9, 12, Bytes(0x51, 32), 0, brokerSeed,
               &status) == nil &&
           status == AncPrivateVaultBrokerReplacementBuilderStatusIssuerRejected);
    anc_pv_zeroize(brokerSeed, sizeof brokerSeed);
    anc_pv_zeroize(brokerPublic, sizeof brokerPublic);
    anc_pv_zeroize(brokerPrivate, sizeof brokerPrivate);

    AncPrivateVaultControlLogState *twoBrokers = State(
        issuerId, oldBrokerId, [NSData dataWithBytes:signingPublic length:32],
        [NSData dataWithBytes:agreementPublic length:32],
        [NSData dataWithBytes:recoveryPublic length:32]);
    twoBrokers.activeMembers = [twoBrokers.activeMembers arrayByAddingObject:
        Member(Bytes(0x27, 16), @"broker", YES, Bytes(0x28, 32),
               Bytes(0x29, 32), 0x2a)];
    NSData *twoDrain = Drain(twoBrokers, oldBrokerId, candidateId,
                             candidateSigning, candidateAgreement,
                             candidateEnrollment, signingSeed, 0, &status);
    assert(twoDrain.length > 0);
    assert(AncPrivateVaultBuildBrokerReplacement(
               twoBrokers, oldBrokerId, candidateId, candidateSigning,
               candidateAgreement, candidateEnrollment, twoDrain,
               Bytes(0x52, 16), Bytes(0x53, 16), Bytes(0x54, 24),
               UINT64_C(1721296802), pending, signingSeed, agreementSeed,
               &status) == nil &&
           status == AncPrivateVaultBrokerReplacementBuilderStatusBrokerRejected);

    AncPrivateVaultControlLogState *resurrection = State(
        issuerId, oldBrokerId, [NSData dataWithBytes:signingPublic length:32],
        [NSData dataWithBytes:agreementPublic length:32],
        [NSData dataWithBytes:recoveryPublic length:32]);
    resurrection.removedEndpointIds = @[Hex(candidateId)];
    NSData *resurrectionDrain = Drain(
        resurrection, oldBrokerId, candidateId, candidateSigning,
        candidateAgreement, candidateEnrollment, signingSeed, 0, &status);
    assert(resurrectionDrain.length > 0);
    assert(AncPrivateVaultBuildBrokerReplacement(
               resurrection, oldBrokerId, candidateId, candidateSigning,
               candidateAgreement, candidateEnrollment, resurrectionDrain,
               Bytes(0x52, 16), Bytes(0x53, 16), Bytes(0x54, 24),
               UINT64_C(1721296802), pending, signingSeed, agreementSeed,
               &status) == nil &&
           status == AncPrivateVaultBrokerReplacementBuilderStatusBrokerRejected);

    anc_pv_zeroize(signingSeed, sizeof signingSeed);
    anc_pv_zeroize(agreementSeed, sizeof agreementSeed);
    anc_pv_zeroize(pending, sizeof pending);
    anc_pv_zeroize(recoverySeed, sizeof recoverySeed);
    anc_pv_zeroize(signingPrivate, sizeof signingPrivate);
    anc_pv_zeroize(agreementPrivate, sizeof agreementPrivate);
    anc_pv_zeroize(recoveryPrivate, sizeof recoveryPrivate);
    puts("private vault broker replacement builder tests passed");
  }
  return 0;
}
