#import <Foundation/Foundation.h>

#import "PrivateVaultAncCanonical.h"
#import "PrivateVaultCrypto.h"
#import "PrivateVaultRotationEvidence.h"

#include <assert.h>

static NSData *Fill(uint8_t byte, NSUInteger length) {
  NSMutableData *data = [NSMutableData dataWithLength:length];
  memset(data.mutableBytes, byte, length);
  return data;
}

static NSData *Hex(NSString *hex) {
  if (![hex isKindOfClass:NSString.class] || hex.length % 2 != 0)
    return nil;
  NSMutableData *data = [NSMutableData dataWithLength:hex.length / 2];
  uint8_t *bytes = data.mutableBytes;
  for (NSUInteger index = 0; index < data.length; index += 1) {
    unsigned value = 0;
    assert(sscanf([[hex substringWithRange:NSMakeRange(index * 2, 2)] UTF8String],
                  "%2x", &value) == 1);
    bytes[index] = (uint8_t)value;
  }
  return data;
}

static NSDictionary *Fixture(void) {
  NSString *path = NSProcessInfo.processInfo.environment[
      @"ANC_ROTATION_EVIDENCE_FIXTURE_PATH"];
  NSData *data = [NSData dataWithContentsOfFile:path];
  assert(data != nil);
  NSDictionary *fixture = [NSJSONSerialization JSONObjectWithData:data
                                                           options:0
                                                             error:nil];
  assert([fixture isKindOfClass:NSDictionary.class]);
  return fixture;
}

static NSData *F(NSDictionary *fixture, NSString *key) {
  NSData *value = Hex(fixture[key]);
  assert(value != nil);
  return value;
}

static NSData *Receipt(NSString *vaultId, NSString *entryId, uint64_t sequence,
                       NSData *headHash, NSData *recoveryHash,
                       uint64_t recoveryLength) {
  AncPrivateVaultCanonicalStatus status;
  NSData *encoded = AncPrivateVaultCanonicalEncode(
      [AncPrivateVaultCanonicalValue map:@{
        @1 : [AncPrivateVaultCanonicalValue text:@"anc/v1"],
        @2 : [AncPrivateVaultCanonicalValue integer:1],
        @3 : [AncPrivateVaultCanonicalValue
            text:@"control-log-rotation-append-receipt"],
        @4 : [AncPrivateVaultCanonicalValue text:vaultId],
        @5 : [AncPrivateVaultCanonicalValue text:entryId],
        @6 : [AncPrivateVaultCanonicalValue integer:(int64_t)sequence],
        @7 : [AncPrivateVaultCanonicalValue bytes:headHash],
        @8 : [AncPrivateVaultCanonicalValue bytes:recoveryHash],
        @9 : [AncPrivateVaultCanonicalValue integer:(int64_t)recoveryLength],
      }],
      &status);
  assert(status == AncPrivateVaultCanonicalStatusOK && encoded.length <= 1024);
  return encoded;
}

static NSArray<AncPrivateVaultRotationEvidenceRecipient *> *Recipients(
    NSDictionary *fixture, NSData *offerOne, NSData *offerTwo) {
  AncPrivateVaultRotationEvidenceRecipient *one =
      [[AncPrivateVaultRotationEvidenceRecipient alloc]
          initWithEndpointId:Fill(3, 16)
             signingPublicKey:F(fixture, @"issuerPublicKey")
        keyAgreementPublicKey:Fill(0x41, 32)
                  eekWrapHash:Fill(21, 32)
                 encodedOffer:offerOne];
  AncPrivateVaultRotationEvidenceRecipient *two =
      [[AncPrivateVaultRotationEvidenceRecipient alloc]
          initWithEndpointId:Fill(6, 16)
             signingPublicKey:F(fixture, @"recipientTwoPublicKey")
        keyAgreementPublicKey:Fill(0x42, 32)
                  eekWrapHash:Fill(22, 32)
                 encodedOffer:offerTwo];
  assert(one != nil && two != nil);
  return @[ one, two ];
}

static NSArray<AncPrivateVaultRotationLiveRevision *> *LiveRevisions(void) {
  AncPrivateVaultRotationLiveRevision *first =
      [[AncPrivateVaultRotationLiveRevision alloc]
          initWithObjectId:Fill(0x31, 16)
                   revision:2
            priorRevisionId:Fill(0x32, 32)
          rotatedRevisionId:Fill(0x33, 32)];
  AncPrivateVaultRotationLiveRevision *second =
      [[AncPrivateVaultRotationLiveRevision alloc]
          initWithObjectId:Fill(0x21, 16)
                   revision:1
            priorRevisionId:Fill(0x22, 32)
          rotatedRevisionId:Fill(0x23, 32)];
  assert(first != nil && second != nil);
  return @[ first, second ];
}

static BOOL Verify(NSDictionary *fixture, NSData *checkpoint,
                   NSArray<NSData *> *acknowledgements,
                   NSArray<NSData *> *destructions, NSData *completion,
                   NSData *receipt,
                   NSArray<AncPrivateVaultRotationEvidenceRecipient *>
                       *recipients,
                   const uint8_t pendingEpochKey[32],
                   AncPrivateVaultRotationEvidenceStatus *status) {
  return AncPrivateVaultVerifyCompletedRotationEvidence(
      checkpoint, acknowledgements, destructions, completion, receipt,
      @"rotation-entry-0001", @"vault-rotation-test", Fill(0x63, 32), 128,
      Fill(1, 16), Fill(3, 16), F(fixture, @"issuerPublicKey"), recipients,
      LiveRevisions(), pendingEpochKey, UINT64_C(1784451801), status);
}

static void CoreNativeVectorsAndAggregate(void) {
  NSDictionary *fixture = Fixture();
  uint8_t issuerSeed[32] = {0};
  uint8_t secondSeed[32] = {0};
  uint8_t epochKey[32] = {0};
  memset(issuerSeed, 10, sizeof issuerSeed);
  memset(secondSeed, 12, sizeof secondSeed);
  memset(epochKey, 7, sizeof epochKey);
  AncPrivateVaultRotationEvidenceStatus status;
  NSData *checkpoint = AncPrivateVaultRotationEvidenceBuildCheckpoint(
      Fill(1, 16), UINT64_C(1784451780), Fill(13, 16), Fill(2, 16), 8,
      Fill(14, 32), 3, 4, Fill(15, 16), Fill(16, 32), 9, Fill(17, 32), 2,
      2, F(fixture, @"liveRevisionSetHash"),
      F(fixture, @"recipientSetHash"), Fill(18, 32), Fill(3, 16),
      Fill(4, 16), issuerSeed, &status);
  assert(status == AncPrivateVaultRotationEvidenceStatusOK &&
         [checkpoint isEqualToData:F(fixture, @"checkpoint")]);
  NSData *checkpointHash =
      AncPrivateVaultRotationEvidenceHashCheckpoint(checkpoint, Fill(1, 16));
  assert([checkpointHash isEqualToData:F(fixture, @"checkpointHash")]);

  NSData *offerOne = AncPrivateVaultRotationEvidenceBuildOffer(
      Fill(1, 16), UINT64_C(1784451790), Fill(21, 16), Fill(2, 16),
      checkpointHash, Fill(21, 32), Fill(3, 16), Fill(3, 16), 4,
      UINT64_C(1784452100), issuerSeed, &status);
  NSData *offerTwo = AncPrivateVaultRotationEvidenceBuildOffer(
      Fill(1, 16), UINT64_C(1784451790), Fill(22, 16), Fill(2, 16),
      checkpointHash, Fill(22, 32), Fill(6, 16), Fill(3, 16), 4,
      UINT64_C(1784452100), issuerSeed, &status);
  assert([offerOne isEqualToData:F(fixture, @"offerOne")]);
  assert([offerTwo isEqualToData:F(fixture, @"offerTwo")]);
  NSData *offerHashOne =
      AncPrivateVaultRotationEvidenceHashOffer(offerOne, Fill(1, 16));
  NSData *offerHashTwo =
      AncPrivateVaultRotationEvidenceHashOffer(offerTwo, Fill(1, 16));

  NSData *ackOne = AncPrivateVaultRotationEvidenceBuildAcknowledgement(
      Fill(1, 16), UINT64_C(1784451800), Fill(41, 16), Fill(2, 16),
      checkpointHash, Fill(21, 32), offerHashOne, Fill(3, 16), 4, issuerSeed,
      epochKey, &status);
  NSData *ackTwo = AncPrivateVaultRotationEvidenceBuildAcknowledgement(
      Fill(1, 16), UINT64_C(1784451800), Fill(42, 16), Fill(2, 16),
      checkpointHash, Fill(22, 32), offerHashTwo, Fill(6, 16), 4, secondSeed,
      epochKey, &status);
  assert([ackOne isEqualToData:F(fixture, @"acknowledgementOne")]);
  assert([ackTwo isEqualToData:F(fixture, @"acknowledgementTwo")]);

  NSData *destroyOne = AncPrivateVaultRotationEvidenceBuildDestruction(
      Fill(1, 16), UINT64_C(1784451800), Fill(0x51, 16), Fill(2, 16),
      checkpointHash, Fill(18, 32), Fill(3, 16), 3, 4, 8, issuerSeed,
      &status);
  NSData *destroyTwo = AncPrivateVaultRotationEvidenceBuildDestruction(
      Fill(1, 16), UINT64_C(1784451800), Fill(0x52, 16), Fill(2, 16),
      checkpointHash, Fill(18, 32), Fill(6, 16), 3, 4, 8, secondSeed,
      &status);
  assert([destroyOne isEqualToData:F(fixture, @"destructionOne")]);
  assert([destroyTwo isEqualToData:F(fixture, @"destructionTwo")]);

  NSData *receipt = F(fixture, @"hostedReceipt");
  NSData *receiptHash =
      AncPrivateVaultRotationEvidenceHashHostedReceipt(receipt);
  NSData *completion = AncPrivateVaultRotationEvidenceBuildCompletion(
      Fill(1, 16), UINT64_C(1784451801), Fill(0x61, 16), Fill(2, 16),
      checkpointHash, Fill(18, 32), receiptHash, Fill(3, 16), 9,
      Fill(18, 32), F(fixture, @"recipientSetHash"), issuerSeed, &status);
  assert([receipt isEqualToData:Receipt(@"vault-rotation-test",
                                       @"rotation-entry-0001", 9,
                                       Fill(18, 32), Fill(0x63, 32), 128)]);
  assert([completion isEqualToData:F(fixture, @"completion")]);
  NSArray *recipients = Recipients(fixture, offerOne, offerTwo);
  assert([AncPrivateVaultRotationEvidenceHashRecipientSet(recipients)
      isEqualToData:F(fixture, @"recipientSetHash")]);
  assert([AncPrivateVaultRotationEvidenceHashLiveRevisionSet(LiveRevisions())
      isEqualToData:F(fixture, @"liveRevisionSetHash")]);
  assert(Verify(fixture, checkpoint, @[ ackOne, ackTwo ],
                @[ destroyOne, destroyTwo ], completion, receipt, recipients,
                epochKey, &status));
  assert(status == AncPrivateVaultRotationEvidenceStatusOK);

  AncPrivateVaultRotationPreparationEvidence *preparation =
      AncPrivateVaultVerifyRotationPreparationEvidence(
          checkpoint, Fill(1, 16), Fill(3, 16),
          F(fixture, @"issuerPublicKey"), recipients, LiveRevisions(),
          UINT64_C(1784451801), &status);
  assert(preparation != nil &&
         status == AncPrivateVaultRotationEvidenceStatusOK);
  AncPrivateVaultRotationAcknowledgementEvidence *acknowledgementEvidence =
      AncPrivateVaultVerifyRotationAcknowledgementEvidence(
          preparation, @[ ackOne, ackTwo ], epochKey,
          UINT64_C(1784451801), &status);
  assert(acknowledgementEvidence != nil &&
         status == AncPrivateVaultRotationEvidenceStatusOK);
  AncPrivateVaultRotationDestructionEvidence *destructionEvidence =
      AncPrivateVaultVerifyRotationDestructionEvidence(
          preparation, @[ destroyOne, destroyTwo ],
          UINT64_C(1784451801), &status);
  assert(destructionEvidence != nil &&
         status == AncPrivateVaultRotationEvidenceStatusOK);
  assert(AncPrivateVaultVerifyRotationAcknowledgementEvidence(
             preparation, @[ ackOne ], epochKey, UINT64_C(1784451801),
             &status) == nil);
  assert(AncPrivateVaultVerifyRotationDestructionEvidence(
             preparation, @[ destroyOne ], UINT64_C(1784451801),
             &status) == nil);
  AncPrivateVaultRotationCustodyEvidence *custody =
      AncPrivateVaultVerifyRotationCustodyEvidence(
          preparation, @[ ackOne, ackTwo ], @[ destroyOne, destroyTwo ],
          epochKey, UINT64_C(1784451801), &status);
  assert(custody != nil && status == AncPrivateVaultRotationEvidenceStatusOK);
  assert(AncPrivateVaultVerifyRotationCustodyEvidence(
             preparation, @[ ackOne ], @[ destroyOne, destroyTwo ], epochKey,
             UINT64_C(1784451801), &status) == nil);
  assert(AncPrivateVaultVerifyRotationCustodyEvidence(
             preparation, @[ ackOne, ackOne ], @[ destroyOne, destroyTwo ],
             epochKey, UINT64_C(1784451801), &status) == nil);
  assert(AncPrivateVaultVerifyRotationCustodyEvidence(
             preparation, @[ ackOne, ackTwo, ackTwo ],
             @[ destroyOne, destroyTwo ], epochKey,
             UINT64_C(1784451801), &status) == nil);
  assert(AncPrivateVaultVerifyRotationCustodyEvidence(
             preparation, @[ ackOne, ackTwo ], @[ destroyOne ], epochKey,
             UINT64_C(1784451801), &status) == nil);
  assert(AncPrivateVaultVerifyRotationCustodyEvidence(
             preparation, @[ ackOne, ackTwo ], @[ destroyOne, destroyOne ],
             epochKey, UINT64_C(1784451801), &status) == nil);
  assert(AncPrivateVaultVerifyRotationCustodyEvidence(
             preparation, @[ ackOne, ackTwo ],
             @[ destroyOne, destroyTwo, destroyTwo ], epochKey,
             UINT64_C(1784451801), &status) == nil);
  assert(!AncPrivateVaultVerifyCompletedRotationEvidence(
      checkpoint, @[ ackOne, ackTwo ], @[ destroyOne, destroyTwo ],
      Fill(0xee, 32), receipt, @"rotation-entry-0001",
      @"vault-rotation-test", Fill(0x63, 32), 128, Fill(1, 16),
      Fill(3, 16), F(fixture, @"issuerPublicKey"), recipients,
      LiveRevisions(), epochKey, UINT64_C(1784451801), &status));

  NSArray<AncPrivateVaultRotationLiveRevision *> *live = LiveRevisions();
  assert([AncPrivateVaultRotationEvidenceHashLiveRevisionSet(live)
      isEqualToData:AncPrivateVaultRotationEvidenceHashLiveRevisionSet(
                        @[ live[1], live[0] ])]);
  assert(AncPrivateVaultVerifyRotationPreparationEvidence(
             checkpoint, Fill(1, 16), Fill(3, 16),
             F(fixture, @"issuerPublicKey"), recipients, @[ live[0] ],
             UINT64_C(1784451801), &status) == nil);
  assert(AncPrivateVaultVerifyRotationPreparationEvidence(
             checkpoint, Fill(1, 16), Fill(3, 16),
             F(fixture, @"issuerPublicKey"), recipients,
             @[ live[0], live[1], live[1] ], UINT64_C(1784451801),
             &status) == nil);
  assert(AncPrivateVaultRotationEvidenceHashLiveRevisionSet(
             @[ live[0], live[0] ]) == nil);
  AncPrivateVaultRotationLiveRevision *substitutedLive =
      [[AncPrivateVaultRotationLiveRevision alloc]
          initWithObjectId:live[1].objectId
                   revision:live[1].revision
            priorRevisionId:Fill(0xee, 32)
          rotatedRevisionId:live[1].rotatedRevisionId];
  assert(AncPrivateVaultVerifyRotationPreparationEvidence(
             checkpoint, Fill(1, 16), Fill(3, 16),
             F(fixture, @"issuerPublicKey"), recipients,
             @[ live[0], substitutedLive ], UINT64_C(1784451801),
             &status) == nil);

  NSData *wrongObjectCountCheckpoint =
      AncPrivateVaultRotationEvidenceBuildCheckpoint(
          Fill(1, 16), UINT64_C(1784451780), Fill(13, 16), Fill(2, 16), 8,
          Fill(14, 32), 3, 4, Fill(15, 16), Fill(16, 32), 9, Fill(17, 32),
          1, 2, F(fixture, @"liveRevisionSetHash"),
          F(fixture, @"recipientSetHash"), Fill(18, 32), Fill(3, 16),
          Fill(4, 16), issuerSeed, &status);
  assert(AncPrivateVaultVerifyRotationPreparationEvidence(
             wrongObjectCountCheckpoint, Fill(1, 16), Fill(3, 16),
             F(fixture, @"issuerPublicKey"), recipients, live,
             UINT64_C(1784451801), &status) == nil);
  NSData *wrongRevisionCountCheckpoint =
      AncPrivateVaultRotationEvidenceBuildCheckpoint(
          Fill(1, 16), UINT64_C(1784451780), Fill(13, 16), Fill(2, 16), 8,
          Fill(14, 32), 3, 4, Fill(15, 16), Fill(16, 32), 9, Fill(17, 32),
          2, 1, F(fixture, @"liveRevisionSetHash"),
          F(fixture, @"recipientSetHash"), Fill(18, 32), Fill(3, 16),
          Fill(4, 16), issuerSeed, &status);
  assert(AncPrivateVaultVerifyRotationPreparationEvidence(
             wrongRevisionCountCheckpoint, Fill(1, 16), Fill(3, 16),
             F(fixture, @"issuerPublicKey"), recipients, live,
             UINT64_C(1784451801), &status) == nil);
  NSData *wrongLiveHashCheckpoint =
      AncPrivateVaultRotationEvidenceBuildCheckpoint(
          Fill(1, 16), UINT64_C(1784451780), Fill(13, 16), Fill(2, 16), 8,
          Fill(14, 32), 3, 4, Fill(15, 16), Fill(16, 32), 9, Fill(17, 32),
          2, 2, Fill(0xee, 32), F(fixture, @"recipientSetHash"),
          Fill(18, 32), Fill(3, 16), Fill(4, 16), issuerSeed, &status);
  assert(AncPrivateVaultVerifyRotationPreparationEvidence(
             wrongLiveHashCheckpoint, Fill(1, 16), Fill(3, 16),
             F(fixture, @"issuerPublicKey"), recipients, live,
             UINT64_C(1784451801), &status) == nil);

  assert(!AncPrivateVaultVerifyCompletedRotationEvidence(
      checkpoint, @[ ackOne, ackTwo ], @[ destroyOne, destroyTwo ], completion,
      receipt, @"rotation-entry-0001", @"vault-rotation-test",
      Fill(0x63, 32), 128, Fill(0xee, 16), Fill(3, 16),
      F(fixture, @"issuerPublicKey"), recipients, LiveRevisions(), epochKey,
      UINT64_C(1784451801), &status));

  NSData *wrongCeremonyAck =
      AncPrivateVaultRotationEvidenceBuildAcknowledgement(
          Fill(1, 16), UINT64_C(1784451800), Fill(41, 16), Fill(0xee, 16),
          checkpointHash, Fill(21, 32), offerHashOne, Fill(3, 16), 4,
          issuerSeed, epochKey, &status);
  assert(!Verify(fixture, checkpoint, @[ wrongCeremonyAck, ackTwo ],
                 @[ destroyOne, destroyTwo ], completion, receipt, recipients,
                 epochKey, &status));
  NSData *wrongCheckpointAck =
      AncPrivateVaultRotationEvidenceBuildAcknowledgement(
          Fill(1, 16), UINT64_C(1784451800), Fill(41, 16), Fill(2, 16),
          Fill(0xee, 32), Fill(21, 32), offerHashOne, Fill(3, 16), 4,
          issuerSeed, epochKey, &status);
  assert(!Verify(fixture, checkpoint, @[ wrongCheckpointAck, ackTwo ],
                 @[ destroyOne, destroyTwo ], completion, receipt, recipients,
                 epochKey, &status));
  NSData *wrongControlDestruction =
      AncPrivateVaultRotationEvidenceBuildDestruction(
          Fill(1, 16), UINT64_C(1784451800), Fill(0x51, 16), Fill(2, 16),
          checkpointHash, Fill(0xee, 32), Fill(3, 16), 3, 4, 8, issuerSeed,
          &status);
  assert(!Verify(fixture, checkpoint, @[ ackOne, ackTwo ],
                 @[ wrongControlDestruction, destroyTwo ], completion, receipt,
                 recipients, epochKey, &status));

  assert(!Verify(fixture, checkpoint, @[ ackOne ],
                 @[ destroyOne, destroyTwo ], completion, receipt, recipients,
                 epochKey, &status));
  assert(!Verify(fixture, checkpoint, @[ ackOne, ackOne ],
                 @[ destroyOne, destroyTwo ], completion, receipt, recipients,
                 epochKey, &status));
  assert(!Verify(fixture, checkpoint, @[ ackOne, ackTwo ], @[ destroyOne ],
                 completion, receipt, recipients, epochKey, &status));
  assert(!Verify(fixture, checkpoint, @[ ackOne, ackTwo ],
                 @[ destroyOne, destroyOne ], completion, receipt, recipients,
                 epochKey, &status));

  AncPrivateVaultRotationEvidenceRecipient *substituted =
      [[AncPrivateVaultRotationEvidenceRecipient alloc]
          initWithEndpointId:Fill(6, 16)
             signingPublicKey:F(fixture, @"recipientTwoPublicKey")
        keyAgreementPublicKey:Fill(0xee, 32)
                  eekWrapHash:Fill(22, 32)
                 encodedOffer:offerTwo];
  assert(!Verify(fixture, checkpoint, @[ ackOne, ackTwo ],
                 @[ destroyOne, destroyTwo ], completion, receipt,
                 @[ recipients[0], substituted ], epochKey, &status));
  uint8_t wrongEpochKey[32] = {0};
  memset(wrongEpochKey, 0xee, sizeof wrongEpochKey);
  assert(!Verify(fixture, checkpoint, @[ ackOne, ackTwo ],
                 @[ destroyOne, destroyTwo ], completion, receipt, recipients,
                 wrongEpochKey, &status));

  NSData *wrongReceipt = Receipt(@"vault-rotation-test",
                                 @"rotation-entry-other", 9, Fill(18, 32),
                                 Fill(0x63, 32), 128);
  NSData *wrongReceiptCompletion =
      AncPrivateVaultRotationEvidenceBuildCompletion(
          Fill(1, 16), UINT64_C(1784451801), Fill(0x61, 16), Fill(2, 16),
          checkpointHash, Fill(18, 32),
          AncPrivateVaultRotationEvidenceHashHostedReceipt(wrongReceipt),
          Fill(3, 16), 9, Fill(18, 32), F(fixture, @"recipientSetHash"),
          issuerSeed, &status);
  assert(!Verify(fixture, checkpoint, @[ ackOne, ackTwo ],
                 @[ destroyOne, destroyTwo ], wrongReceiptCompletion,
                 wrongReceipt, recipients, epochKey, &status));

  NSData *wrongSequenceReceipt = Receipt(
      @"vault-rotation-test", @"rotation-entry-0001", 10, Fill(18, 32),
      Fill(0x63, 32), 128);
  NSData *wrongSequenceCompletion =
      AncPrivateVaultRotationEvidenceBuildCompletion(
          Fill(1, 16), UINT64_C(1784451801), Fill(0x61, 16), Fill(2, 16),
          checkpointHash, Fill(18, 32),
          AncPrivateVaultRotationEvidenceHashHostedReceipt(
              wrongSequenceReceipt),
          Fill(3, 16), 10, Fill(18, 32), F(fixture, @"recipientSetHash"),
          issuerSeed, &status);
  assert(!Verify(fixture, checkpoint, @[ ackOne, ackTwo ],
                 @[ destroyOne, destroyTwo ], wrongSequenceCompletion,
                 wrongSequenceReceipt, recipients, epochKey, &status));

  NSData *wrongHeadReceipt = Receipt(
      @"vault-rotation-test", @"rotation-entry-0001", 9, Fill(0xee, 32),
      Fill(0x63, 32), 128);
  NSData *wrongHeadCompletion = AncPrivateVaultRotationEvidenceBuildCompletion(
      Fill(1, 16), UINT64_C(1784451801), Fill(0x61, 16), Fill(2, 16),
      checkpointHash, Fill(18, 32),
      AncPrivateVaultRotationEvidenceHashHostedReceipt(wrongHeadReceipt),
      Fill(3, 16), 9, Fill(0xee, 32), F(fixture, @"recipientSetHash"),
      issuerSeed, &status);
  assert(!Verify(fixture, checkpoint, @[ ackOne, ackTwo ],
                 @[ destroyOne, destroyTwo ], wrongHeadCompletion,
                 wrongHeadReceipt, recipients, epochKey, &status));

  NSMutableData *oversized = [NSMutableData dataWithLength:1025];
  assert(!Verify(fixture, oversized, @[ ackOne, ackTwo ],
                 @[ destroyOne, destroyTwo ], completion, receipt, recipients,
                 epochKey, &status));
  NSMutableArray *tooManyRecipients = [NSMutableArray array];
  for (NSUInteger index = 0; index < 65; index += 1)
    [tooManyRecipients addObject:recipients[0]];
  assert(!Verify(fixture, checkpoint, @[ ackOne, ackTwo ],
                 @[ destroyOne, destroyTwo ], completion, receipt,
                 tooManyRecipients, epochKey, &status));
  assert(AncPrivateVaultRotationEvidenceBuildCheckpoint(
             Fill(1, 16), UINT64_C(1784451780), Fill(13, 16), Fill(2, 16),
             8, Fill(14, 32), 3, 4, Fill(15, 16), Fill(16, 32), 9,
             Fill(17, 32), 2, 10001, F(fixture, @"liveRevisionSetHash"),
             F(fixture, @"recipientSetHash"), Fill(18, 32), Fill(3, 16),
             Fill(4, 16), issuerSeed, &status) == nil);
  assert(AncPrivateVaultRotationEvidenceBuildOffer(
             Fill(1, 16), UINT64_C(1784451790), Fill(21, 16), Fill(2, 16),
             checkpointHash, Fill(21, 32), Fill(3, 16), Fill(3, 16), 4,
             UINT64_C(1784451789), issuerSeed, &status) == nil);

  anc_pv_zeroize(issuerSeed, sizeof issuerSeed);
  anc_pv_zeroize(secondSeed, sizeof secondSeed);
  anc_pv_zeroize(epochKey, sizeof epochKey);
  anc_pv_zeroize(wrongEpochKey, sizeof wrongEpochKey);
}

int main(void) {
  @autoreleasepool {
    assert(anc_pv_crypto_init() == ANC_PV_CRYPTO_OK);
    CoreNativeVectorsAndAggregate();
    NSLog(@"Private Vault rotation evidence tests passed");
  }
  return 0;
}
