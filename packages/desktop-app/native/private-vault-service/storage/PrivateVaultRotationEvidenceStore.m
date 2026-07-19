#import "PrivateVaultRotationEvidenceStore.h"

#import "PrivateVaultAncCanonical.h"
#import "PrivateVaultCrypto.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

static NSString *const kAncRotationEvidenceDirectory = @"rotation-evidence";
static NSString *const kAncRotationEvidenceSuffix = @".rotation-evidence";
/* 10,000 canonical live-revision tuples are <1 MiB (16 + integer + 32 + 32
 * bytes plus canonical framing each). Recipients and all four 64-artifact
 * rosters remain <300 KiB, so 2 MiB leaves conservative framing headroom while
 * retaining a strict allocation and file-size ceiling. */
static const NSUInteger kAncRotationEvidenceMaximumRecordBytes = 2 * 1024 * 1024;
static const uint64_t kAncRotationEvidenceMaximumSafeInteger =
    UINT64_C(9007199254740991);
static const uint8_t kAncRotationEvidenceDigestDomain[] =
    "anc/v1/private-vault/rotation-evidence-store/content-digest";

typedef NS_ENUM(NSInteger, AncRotationEvidenceReadStatus) {
  AncRotationEvidenceReadStatusOK = 0,
  AncRotationEvidenceReadStatusNotFound,
  AncRotationEvidenceReadStatusUnsafe,
  AncRotationEvidenceReadStatusFailed,
};

@interface AncPrivateVaultRotationEvidenceStoreRecipient ()
@property(nonatomic, readwrite) NSData *endpointId;
@property(nonatomic, readwrite) NSData *signingPublicKey;
@property(nonatomic, readwrite) NSData *keyAgreementPublicKey;
@property(nonatomic, readwrite) NSData *encodedOffer;
@property(nonatomic, readwrite) NSData *encodedEEKWrap;
@end

@interface AncPrivateVaultRotationEvidenceStoreLiveRevision ()
@property(nonatomic, readwrite) NSData *objectId;
@property(nonatomic, readwrite) uint64_t revision;
@property(nonatomic, readwrite) NSData *priorRevisionId;
@property(nonatomic, readwrite) NSData *rotatedRevisionId;
@end

@interface AncPrivateVaultRotationEvidenceStoreCheckpoint ()
@property(nonatomic, readwrite) NSData *vaultId;
@property(nonatomic, readwrite) NSData *ceremonyId;
@property(nonatomic, readwrite) NSData *targetEndpointId;
@property(nonatomic, readwrite) uint64_t preparationFenceGeneration;
@property(nonatomic, readwrite) NSData *preparationRecordDigest;
@property(nonatomic, readwrite) uint64_t generation;
@property(nonatomic, readwrite) NSData *contentDigest;
@property(nonatomic, readwrite) NSData *encodedCheckpoint;
@property(nonatomic, readwrite)
    NSArray<AncPrivateVaultRotationEvidenceStoreRecipient *> *recipients;
@property(nonatomic, readwrite)
    NSArray<AncPrivateVaultRotationEvidenceStoreLiveRevision *> *liveRevisions;
@property(nonatomic, readwrite) NSDictionary<NSData *, NSData *> *acknowledgements;
@property(nonatomic, readwrite) NSDictionary<NSData *, NSData *> *destructions;
@property(nonatomic, readwrite) AncPrivateVaultRotationEvidenceStorePhase phase;
@end

@interface AncPrivateVaultRotationEvidenceStore ()
@property(nonatomic, copy) NSURL *stateRootURL;
@property(nonatomic) dispatch_queue_t queue;
@property(nonatomic) BOOL rootPinned;
@property(nonatomic) dev_t rootDevice;
@property(nonatomic) ino_t rootInode;
@property(nonatomic) uid_t rootOwner;
@property(nonatomic) BOOL statePinned;
@property(nonatomic) dev_t stateDevice;
@property(nonatomic) ino_t stateInode;
@property(nonatomic) uid_t stateOwner;
@property(nonatomic) BOOL directoryPinned;
@property(nonatomic) dev_t directoryDevice;
@property(nonatomic) ino_t directoryInode;
@property(nonatomic) uid_t directoryOwner;
@end

#if ANC_PRIVATE_VAULT_TESTING
static AncPrivateVaultRotationEvidenceStoreFaultHook
    gAncRotationEvidenceStoreFaultHook;
void AncPrivateVaultRotationEvidenceStoreSetFaultHookForTesting(
    AncPrivateVaultRotationEvidenceStoreFaultHook hook) {
  gAncRotationEvidenceStoreFaultHook = [hook copy];
}
#endif

static BOOL AncRotationEvidenceFault(
    AncPrivateVaultRotationEvidenceStoreFaultPoint point) {
#if ANC_PRIVATE_VAULT_TESTING
  return gAncRotationEvidenceStoreFaultHook != nil &&
         gAncRotationEvidenceStoreFaultHook(point);
#else
  (void)point;
  return NO;
#endif
}

static dispatch_queue_t AncRotationEvidenceQueue(void) {
  static dispatch_queue_t queue;
  static dispatch_once_t onceToken;
  dispatch_once(&onceToken, ^{
    queue = dispatch_queue_create(
        "com.agentnative.private-vault.rotation-evidence-store",
        DISPATCH_QUEUE_SERIAL);
  });
  return queue;
}

static NSData *AncRotationEvidenceBoundedCopy(NSData *source,
                                               NSUInteger exactLength,
                                               NSUInteger maximumLength) {
  if (![source isKindOfClass:NSData.class])
    return nil;
  @try {
    NSUInteger length = source.length;
    if ((exactLength != 0 && length != exactLength) || length == 0 ||
        length > maximumLength)
      return nil;
    NSMutableData *copy = [NSMutableData dataWithLength:length];
    [source getBytes:copy.mutableBytes length:length];
    if (source.length != length)
      return nil;
    return [NSData dataWithData:copy];
  } @catch (__unused NSException *exception) {
    return nil;
  }
}

static NSComparisonResult AncRotationEvidenceCompareData(NSData *left,
                                                          NSData *right) {
  NSUInteger shared = MIN(left.length, right.length);
  int order = memcmp(left.bytes, right.bytes, shared);
  if (order < 0)
    return NSOrderedAscending;
  if (order > 0)
    return NSOrderedDescending;
  if (left.length < right.length)
    return NSOrderedAscending;
  if (left.length > right.length)
    return NSOrderedDescending;
  return NSOrderedSame;
}

static BOOL AncRotationEvidenceExactKeys(NSDictionary<NSNumber *, id> *map,
                                          NSArray<NSNumber *> *keys) {
  return map.count == keys.count &&
         [[NSSet setWithArray:map.allKeys]
             isEqualToSet:[NSSet setWithArray:keys]];
}

static AncPrivateVaultCanonicalValue *AncRotationEvidenceField(
    NSDictionary<NSNumber *, AncPrivateVaultCanonicalValue *> *map,
    NSNumber *key, AncPrivateVaultCanonicalType type) {
  AncPrivateVaultCanonicalValue *value = map[key];
  return value.type == type ? value : nil;
}

static NSData *AncRotationEvidenceEncodeValue(
    AncPrivateVaultCanonicalValue *value) {
  AncPrivateVaultCanonicalStatus status;
  NSData *encoded = AncPrivateVaultCanonicalEncode(value, &status);
  return status == AncPrivateVaultCanonicalStatusOK ? encoded : nil;
}

static BOOL AncRotationEvidenceCanonicalArtifact(NSData *artifact) {
  if (artifact.length == 0 ||
      artifact.length > ANC_PV_ROTATION_EVIDENCE_STORE_MAX_ARTIFACT_BYTES)
    return NO;
  AncPrivateVaultCanonicalStatus status;
  AncPrivateVaultCanonicalValue *value = AncPrivateVaultCanonicalDecode(
      artifact, ANC_PV_ROTATION_EVIDENCE_STORE_MAX_ARTIFACT_BYTES, &status);
  return status == AncPrivateVaultCanonicalStatusOK && value != nil &&
         [[AncRotationEvidenceEncodeValue(value) copy] isEqualToData:artifact];
}

static NSData *AncRotationEvidenceDigest(NSData *body) {
  if (body.length == 0 || body.length > kAncRotationEvidenceMaximumRecordBytes)
    return nil;
  uint8_t digest[ANC_PV_ROTATION_EVIDENCE_STORE_DIGEST_BYTES] = {0};
  BOOL okay = anc_pv_blake2b_256_two_part(
                  digest, kAncRotationEvidenceDigestDomain,
                  sizeof kAncRotationEvidenceDigestDomain, body.bytes,
                  body.length) == ANC_PV_CRYPTO_OK;
  NSData *result = okay ? [NSData dataWithBytes:digest length:sizeof digest]
                        : nil;
  anc_pv_zeroize(digest, sizeof digest);
  return result;
}

@implementation AncPrivateVaultRotationEvidenceStoreRecipient

- (instancetype)initWithEndpointId:(NSData *)endpointId
                  signingPublicKey:(NSData *)signingPublicKey
             keyAgreementPublicKey:(NSData *)keyAgreementPublicKey
                      encodedOffer:(NSData *)encodedOffer
                    encodedEEKWrap:(NSData *)encodedEEKWrap {
  NSData *endpoint = AncRotationEvidenceBoundedCopy(
      endpointId, ANC_PV_ROTATION_EVIDENCE_STORE_ID_BYTES,
      ANC_PV_ROTATION_EVIDENCE_STORE_ID_BYTES);
  NSData *signing = AncRotationEvidenceBoundedCopy(
      signingPublicKey, ANC_PV_ROTATION_EVIDENCE_STORE_PUBLIC_KEY_BYTES,
      ANC_PV_ROTATION_EVIDENCE_STORE_PUBLIC_KEY_BYTES);
  NSData *agreement = AncRotationEvidenceBoundedCopy(
      keyAgreementPublicKey, ANC_PV_ROTATION_EVIDENCE_STORE_PUBLIC_KEY_BYTES,
      ANC_PV_ROTATION_EVIDENCE_STORE_PUBLIC_KEY_BYTES);
  NSData *offer = AncRotationEvidenceBoundedCopy(
      encodedOffer, 0, ANC_PV_ROTATION_EVIDENCE_STORE_MAX_ARTIFACT_BYTES);
  NSData *wrap = AncRotationEvidenceBoundedCopy(
      encodedEEKWrap, 0, ANC_PV_ROTATION_EVIDENCE_STORE_MAX_ARTIFACT_BYTES);
  if (endpoint == nil || signing == nil || agreement == nil || offer == nil ||
      wrap == nil || !AncRotationEvidenceCanonicalArtifact(offer) ||
      !AncRotationEvidenceCanonicalArtifact(wrap) ||
      (self = [super init]) == nil)
    return nil;
  _endpointId = endpoint;
  _signingPublicKey = signing;
  _keyAgreementPublicKey = agreement;
  _encodedOffer = offer;
  _encodedEEKWrap = wrap;
  return self;
}

@end

@implementation AncPrivateVaultRotationEvidenceStoreLiveRevision

- (instancetype)initWithObjectId:(NSData *)objectId
                         revision:(uint64_t)revision
                  priorRevisionId:(NSData *)priorRevisionId
                rotatedRevisionId:(NSData *)rotatedRevisionId {
  NSData *object = AncRotationEvidenceBoundedCopy(
      objectId, ANC_PV_ROTATION_EVIDENCE_STORE_ID_BYTES,
      ANC_PV_ROTATION_EVIDENCE_STORE_ID_BYTES);
  NSData *prior = AncRotationEvidenceBoundedCopy(
      priorRevisionId, ANC_PV_ROTATION_EVIDENCE_STORE_DIGEST_BYTES,
      ANC_PV_ROTATION_EVIDENCE_STORE_DIGEST_BYTES);
  NSData *rotated = AncRotationEvidenceBoundedCopy(
      rotatedRevisionId, ANC_PV_ROTATION_EVIDENCE_STORE_DIGEST_BYTES,
      ANC_PV_ROTATION_EVIDENCE_STORE_DIGEST_BYTES);
  if (object == nil || prior == nil || rotated == nil || revision == 0 ||
      revision > kAncRotationEvidenceMaximumSafeInteger ||
      (self = [super init]) == nil)
    return nil;
  _objectId = object;
  _revision = revision;
  _priorRevisionId = prior;
  _rotatedRevisionId = rotated;
  return self;
}

@end

@implementation AncPrivateVaultRotationEvidenceStoreCheckpoint
@end

static NSArray<AncPrivateVaultRotationEvidenceStoreRecipient *> *
AncRotationEvidenceRecipientsSnapshot(NSArray *input) {
  if (![input isKindOfClass:NSArray.class] || input.count == 0 ||
      input.count > ANC_PV_ROTATION_EVIDENCE_STORE_MAX_RECIPIENTS)
    return nil;
  NSMutableArray *result = [NSMutableArray arrayWithCapacity:input.count];
  for (id candidate in input) {
    if (![candidate
            isKindOfClass:AncPrivateVaultRotationEvidenceStoreRecipient.class])
      return nil;
    AncPrivateVaultRotationEvidenceStoreRecipient *recipient = candidate;
    AncPrivateVaultRotationEvidenceStoreRecipient *copy =
        [[AncPrivateVaultRotationEvidenceStoreRecipient alloc]
            initWithEndpointId:recipient.endpointId
              signingPublicKey:recipient.signingPublicKey
         keyAgreementPublicKey:recipient.keyAgreementPublicKey
                  encodedOffer:recipient.encodedOffer
                encodedEEKWrap:recipient.encodedEEKWrap];
    if (copy == nil)
      return nil;
    [result addObject:copy];
  }
  [result sortUsingComparator:^NSComparisonResult(
              AncPrivateVaultRotationEvidenceStoreRecipient *left,
              AncPrivateVaultRotationEvidenceStoreRecipient *right) {
    return AncRotationEvidenceCompareData(left.endpointId, right.endpointId);
  }];
  for (NSUInteger index = 1; index < result.count; index += 1) {
    AncPrivateVaultRotationEvidenceStoreRecipient *previous =
        result[index - 1];
    AncPrivateVaultRotationEvidenceStoreRecipient *current = result[index];
    if ([previous.endpointId isEqualToData:current.endpointId])
      return nil;
  }
  return [NSArray arrayWithArray:result];
}

static NSArray<AncPrivateVaultRotationEvidenceStoreLiveRevision *> *
AncRotationEvidenceLiveRevisionsSnapshot(NSArray *input) {
  if (![input isKindOfClass:NSArray.class] ||
      input.count > ANC_PV_ROTATION_EVIDENCE_STORE_MAX_LIVE_REVISIONS)
    return nil;
  NSMutableArray *result = [NSMutableArray arrayWithCapacity:input.count];
  for (id candidate in input) {
    if (![candidate
            isKindOfClass:AncPrivateVaultRotationEvidenceStoreLiveRevision.class])
      return nil;
    AncPrivateVaultRotationEvidenceStoreLiveRevision *revision = candidate;
    AncPrivateVaultRotationEvidenceStoreLiveRevision *copy =
        [[AncPrivateVaultRotationEvidenceStoreLiveRevision alloc]
            initWithObjectId:revision.objectId
                    revision:revision.revision
             priorRevisionId:revision.priorRevisionId
           rotatedRevisionId:revision.rotatedRevisionId];
    if (copy == nil)
      return nil;
    [result addObject:copy];
  }
  [result sortUsingComparator:^NSComparisonResult(
              AncPrivateVaultRotationEvidenceStoreLiveRevision *left,
              AncPrivateVaultRotationEvidenceStoreLiveRevision *right) {
    NSComparisonResult objects =
        AncRotationEvidenceCompareData(left.objectId, right.objectId);
    if (objects != NSOrderedSame)
      return objects;
    if (left.revision < right.revision)
      return NSOrderedAscending;
    if (left.revision > right.revision)
      return NSOrderedDescending;
    return NSOrderedSame;
  }];
  for (NSUInteger index = 1; index < result.count; index += 1) {
    AncPrivateVaultRotationEvidenceStoreLiveRevision *previous =
        result[index - 1];
    AncPrivateVaultRotationEvidenceStoreLiveRevision *current = result[index];
    if ([previous.objectId isEqualToData:current.objectId] &&
        previous.revision == current.revision)
      return nil;
  }
  return [NSArray arrayWithArray:result];
}

static NSArray<AncPrivateVaultCanonicalValue *> *
AncRotationEvidenceEncodeRecipients(
    NSArray<AncPrivateVaultRotationEvidenceStoreRecipient *> *recipients) {
  NSMutableArray *encoded = [NSMutableArray arrayWithCapacity:recipients.count];
  for (AncPrivateVaultRotationEvidenceStoreRecipient *recipient in recipients) {
    AncPrivateVaultCanonicalValue *value = [AncPrivateVaultCanonicalValue map:@{
      @1 : [AncPrivateVaultCanonicalValue bytes:recipient.endpointId],
      @2 : [AncPrivateVaultCanonicalValue bytes:recipient.signingPublicKey],
      @3 : [AncPrivateVaultCanonicalValue
          bytes:recipient.keyAgreementPublicKey],
      @4 : [AncPrivateVaultCanonicalValue bytes:recipient.encodedOffer],
      @5 : [AncPrivateVaultCanonicalValue bytes:recipient.encodedEEKWrap],
    }];
    if (value == nil)
      return nil;
    [encoded addObject:value];
  }
  return encoded;
}

static NSArray<AncPrivateVaultCanonicalValue *> *
AncRotationEvidenceEncodeLiveRevisions(
    NSArray<AncPrivateVaultRotationEvidenceStoreLiveRevision *> *revisions) {
  NSMutableArray *encoded = [NSMutableArray arrayWithCapacity:revisions.count];
  for (AncPrivateVaultRotationEvidenceStoreLiveRevision *revision in revisions) {
    AncPrivateVaultCanonicalValue *value = [AncPrivateVaultCanonicalValue array:@[
      [AncPrivateVaultCanonicalValue bytes:revision.objectId],
      [AncPrivateVaultCanonicalValue integer:(int64_t)revision.revision],
      [AncPrivateVaultCanonicalValue bytes:revision.priorRevisionId],
      [AncPrivateVaultCanonicalValue bytes:revision.rotatedRevisionId],
    ]];
    if (value == nil)
      return nil;
    [encoded addObject:value];
  }
  return encoded;
}

static NSArray<AncPrivateVaultCanonicalValue *> *
AncRotationEvidenceEncodeEvidence(NSDictionary<NSData *, NSData *> *evidence) {
  NSArray<NSData *> *endpoints = [evidence.allKeys
      sortedArrayUsingComparator:^NSComparisonResult(NSData *left,
                                                       NSData *right) {
        return AncRotationEvidenceCompareData(left, right);
      }];
  NSMutableArray *encoded = [NSMutableArray arrayWithCapacity:endpoints.count];
  for (NSData *endpoint in endpoints) {
    AncPrivateVaultCanonicalValue *value = [AncPrivateVaultCanonicalValue map:@{
      @1 : [AncPrivateVaultCanonicalValue bytes:endpoint],
      @2 : [AncPrivateVaultCanonicalValue bytes:evidence[endpoint]],
    }];
    if (value == nil)
      return nil;
    [encoded addObject:value];
  }
  return encoded;
}

static NSData *AncRotationEvidenceEncodeCheckpoint(
    AncPrivateVaultRotationEvidenceStoreCheckpoint *checkpoint) {
  if (checkpoint == nil || checkpoint.generation == 0 ||
      checkpoint.generation > kAncRotationEvidenceMaximumSafeInteger ||
      checkpoint.preparationFenceGeneration == 0 ||
      checkpoint.preparationFenceGeneration >
          kAncRotationEvidenceMaximumSafeInteger)
    return nil;
  NSArray *recipients = AncRotationEvidenceEncodeRecipients(checkpoint.recipients);
  NSArray *liveRevisions =
      AncRotationEvidenceEncodeLiveRevisions(checkpoint.liveRevisions);
  NSArray *acknowledgements =
      AncRotationEvidenceEncodeEvidence(checkpoint.acknowledgements);
  NSArray *destructions =
      AncRotationEvidenceEncodeEvidence(checkpoint.destructions);
  if (recipients == nil || liveRevisions == nil || acknowledgements == nil ||
      destructions == nil)
    return nil;
  NSDictionary *bodyMap = @{
    @1 : [AncPrivateVaultCanonicalValue text:@"anc/v1"],
    @2 : [AncPrivateVaultCanonicalValue bytes:checkpoint.vaultId],
    @3 : [AncPrivateVaultCanonicalValue text:@"rotation-evidence-ledger"],
    @4 : [AncPrivateVaultCanonicalValue integer:1],
    @5 : [AncPrivateVaultCanonicalValue integer:(int64_t)checkpoint.generation],
    @6 : [AncPrivateVaultCanonicalValue bytes:checkpoint.ceremonyId],
    @7 : [AncPrivateVaultCanonicalValue bytes:checkpoint.targetEndpointId],
    @8 : [AncPrivateVaultCanonicalValue
        integer:(int64_t)checkpoint.preparationFenceGeneration],
    @9 : [AncPrivateVaultCanonicalValue
        bytes:checkpoint.preparationRecordDigest],
    @10 : [AncPrivateVaultCanonicalValue bytes:checkpoint.encodedCheckpoint],
    @11 : [AncPrivateVaultCanonicalValue array:recipients],
    @12 : [AncPrivateVaultCanonicalValue integer:(int64_t)checkpoint.phase],
    @13 : [AncPrivateVaultCanonicalValue array:acknowledgements],
    @14 : [AncPrivateVaultCanonicalValue array:destructions],
    @16 : [AncPrivateVaultCanonicalValue array:liveRevisions],
  };
  NSData *body = AncRotationEvidenceEncodeValue(
      [AncPrivateVaultCanonicalValue map:bodyMap]);
  NSData *digest = AncRotationEvidenceDigest(body);
  if (body == nil || digest == nil)
    return nil;
  NSMutableDictionary *recordMap = [bodyMap mutableCopy];
  recordMap[@15] = [AncPrivateVaultCanonicalValue bytes:digest];
  NSData *record = AncRotationEvidenceEncodeValue(
      [AncPrivateVaultCanonicalValue map:recordMap]);
  return record.length <= kAncRotationEvidenceMaximumRecordBytes ? record : nil;
}

static NSDictionary<NSData *, NSData *> *AncRotationEvidenceDecodeEvidence(
    AncPrivateVaultCanonicalValue *value,
    NSSet<NSData *> *recipientEndpoints) {
  if (value.type != AncPrivateVaultCanonicalTypeArray ||
      value.arrayValue.count > recipientEndpoints.count)
    return nil;
  NSMutableDictionary *evidence = [NSMutableDictionary dictionary];
  NSData *previous = nil;
  for (AncPrivateVaultCanonicalValue *entry in value.arrayValue) {
    NSDictionary *map = entry.mapValue;
    NSData *endpoint = AncRotationEvidenceField(
                           map, @1, AncPrivateVaultCanonicalTypeBytes)
                           .bytesValue;
    NSData *artifact = AncRotationEvidenceField(
                           map, @2, AncPrivateVaultCanonicalTypeBytes)
                           .bytesValue;
    if (entry.type != AncPrivateVaultCanonicalTypeMap ||
        !AncRotationEvidenceExactKeys(map, @[ @1, @2 ]) ||
        endpoint.length != ANC_PV_ROTATION_EVIDENCE_STORE_ID_BYTES ||
        artifact.length == 0 ||
        artifact.length > ANC_PV_ROTATION_EVIDENCE_STORE_MAX_ARTIFACT_BYTES ||
        ![recipientEndpoints containsObject:endpoint] || evidence[endpoint] != nil ||
        (previous != nil &&
         AncRotationEvidenceCompareData(previous, endpoint) != NSOrderedAscending))
      return nil;
    evidence[[endpoint copy]] = [artifact copy];
    previous = endpoint;
  }
  return [NSDictionary dictionaryWithDictionary:evidence];
}

static AncPrivateVaultRotationEvidenceStoreCheckpoint *
AncRotationEvidenceDecodeCheckpoint(NSData *record, NSData *expectedVaultId) {
  if (record.length == 0 ||
      record.length > kAncRotationEvidenceMaximumRecordBytes ||
      expectedVaultId.length != ANC_PV_ROTATION_EVIDENCE_STORE_ID_BYTES)
    return nil;
  AncPrivateVaultCanonicalStatus status;
  AncPrivateVaultCanonicalValue *root = AncPrivateVaultCanonicalDecode(
      record, kAncRotationEvidenceMaximumRecordBytes, &status);
  NSDictionary *map = root.mapValue;
  NSArray *keys = @[
    @1, @2, @3, @4, @5, @6, @7, @8, @9, @10, @11, @12, @13, @14,
    @15, @16
  ];
  if (status != AncPrivateVaultCanonicalStatusOK ||
      root.type != AncPrivateVaultCanonicalTypeMap ||
      !AncRotationEvidenceExactKeys(map, keys))
    return nil;
  NSData *roundTrip = AncRotationEvidenceEncodeValue(root);
  if (![roundTrip isEqualToData:record])
    return nil;
  NSData *vault =
      AncRotationEvidenceField(map, @2, AncPrivateVaultCanonicalTypeBytes)
          .bytesValue;
  NSData *ceremony =
      AncRotationEvidenceField(map, @6, AncPrivateVaultCanonicalTypeBytes)
          .bytesValue;
  NSData *target =
      AncRotationEvidenceField(map, @7, AncPrivateVaultCanonicalTypeBytes)
          .bytesValue;
  NSData *preparationDigest =
      AncRotationEvidenceField(map, @9, AncPrivateVaultCanonicalTypeBytes)
          .bytesValue;
  NSData *encodedCheckpoint =
      AncRotationEvidenceField(map, @10, AncPrivateVaultCanonicalTypeBytes)
          .bytesValue;
  NSData *contentDigest =
      AncRotationEvidenceField(map, @15, AncPrivateVaultCanonicalTypeBytes)
          .bytesValue;
  int64_t version =
      AncRotationEvidenceField(map, @4, AncPrivateVaultCanonicalTypeInteger)
          .integerValue;
  int64_t generation =
      AncRotationEvidenceField(map, @5, AncPrivateVaultCanonicalTypeInteger)
          .integerValue;
  int64_t fence =
      AncRotationEvidenceField(map, @8, AncPrivateVaultCanonicalTypeInteger)
          .integerValue;
  int64_t phaseValue =
      AncRotationEvidenceField(map, @12, AncPrivateVaultCanonicalTypeInteger)
          .integerValue;
  if (![[AncRotationEvidenceField(map, @1,
                                  AncPrivateVaultCanonicalTypeText) textValue]
          isEqualToString:@"anc/v1"] ||
      ![[AncRotationEvidenceField(map, @3,
                                  AncPrivateVaultCanonicalTypeText) textValue]
          isEqualToString:@"rotation-evidence-ledger"] ||
      version != 1 || generation <= 0 ||
      (uint64_t)generation > kAncRotationEvidenceMaximumSafeInteger ||
      fence <= 0 || (uint64_t)fence > kAncRotationEvidenceMaximumSafeInteger ||
      ![vault isEqualToData:expectedVaultId] ||
      ceremony.length != ANC_PV_ROTATION_EVIDENCE_STORE_ID_BYTES ||
      target.length != ANC_PV_ROTATION_EVIDENCE_STORE_ID_BYTES ||
      preparationDigest.length !=
          ANC_PV_ROTATION_EVIDENCE_STORE_DIGEST_BYTES ||
      encodedCheckpoint.length == 0 ||
      encodedCheckpoint.length >
          ANC_PV_ROTATION_EVIDENCE_STORE_MAX_ARTIFACT_BYTES ||
      contentDigest.length != ANC_PV_ROTATION_EVIDENCE_STORE_DIGEST_BYTES ||
      phaseValue < AncPrivateVaultRotationEvidenceStorePhaseAcknowledgements ||
      phaseValue > AncPrivateVaultRotationEvidenceStorePhaseComplete)
    return nil;
  NSMutableDictionary *bodyMap = [map mutableCopy];
  [bodyMap removeObjectForKey:@15];
  NSData *body = AncRotationEvidenceEncodeValue(
      [AncPrivateVaultCanonicalValue map:bodyMap]);
  if (![[AncRotationEvidenceDigest(body) copy] isEqualToData:contentDigest])
    return nil;

  AncPrivateVaultCanonicalValue *recipientArray =
      AncRotationEvidenceField(map, @11, AncPrivateVaultCanonicalTypeArray);
  if (recipientArray.arrayValue.count == 0 ||
      recipientArray.arrayValue.count >
          ANC_PV_ROTATION_EVIDENCE_STORE_MAX_RECIPIENTS)
    return nil;
  NSMutableArray *recipients =
      [NSMutableArray arrayWithCapacity:recipientArray.arrayValue.count];
  NSMutableSet *recipientEndpoints = [NSMutableSet set];
  NSData *previous = nil;
  for (AncPrivateVaultCanonicalValue *entry in recipientArray.arrayValue) {
    NSDictionary *recipientMap = entry.mapValue;
    if (entry.type != AncPrivateVaultCanonicalTypeMap ||
        !AncRotationEvidenceExactKeys(recipientMap, @[ @1, @2, @3, @4, @5 ]))
      return nil;
    AncPrivateVaultRotationEvidenceStoreRecipient *recipient =
        [[AncPrivateVaultRotationEvidenceStoreRecipient alloc]
            initWithEndpointId:AncRotationEvidenceField(
                                   recipientMap, @1,
                                   AncPrivateVaultCanonicalTypeBytes)
                                   .bytesValue
              signingPublicKey:AncRotationEvidenceField(
                                   recipientMap, @2,
                                   AncPrivateVaultCanonicalTypeBytes)
                                   .bytesValue
         keyAgreementPublicKey:AncRotationEvidenceField(
                                   recipientMap, @3,
                                   AncPrivateVaultCanonicalTypeBytes)
                                   .bytesValue
                  encodedOffer:AncRotationEvidenceField(
                                   recipientMap, @4,
                                   AncPrivateVaultCanonicalTypeBytes)
                                   .bytesValue
                encodedEEKWrap:AncRotationEvidenceField(
                                   recipientMap, @5,
                                   AncPrivateVaultCanonicalTypeBytes)
                                   .bytesValue];
    if (recipient == nil ||
        [recipientEndpoints containsObject:recipient.endpointId] ||
        (previous != nil &&
         AncRotationEvidenceCompareData(previous, recipient.endpointId) !=
             NSOrderedAscending))
      return nil;
    [recipients addObject:recipient];
    [recipientEndpoints addObject:recipient.endpointId];
    previous = recipient.endpointId;
  }
  AncPrivateVaultCanonicalValue *liveRevisionArray =
      AncRotationEvidenceField(map, @16, AncPrivateVaultCanonicalTypeArray);
  if (liveRevisionArray == nil || liveRevisionArray.arrayValue.count >
      ANC_PV_ROTATION_EVIDENCE_STORE_MAX_LIVE_REVISIONS)
    return nil;
  NSMutableArray *liveRevisions =
      [NSMutableArray arrayWithCapacity:liveRevisionArray.arrayValue.count];
  AncPrivateVaultRotationEvidenceStoreLiveRevision *priorLiveRevision = nil;
  for (AncPrivateVaultCanonicalValue *entry in
       liveRevisionArray.arrayValue) {
    if (entry.type != AncPrivateVaultCanonicalTypeArray ||
        entry.arrayValue.count != 4)
      return nil;
    NSArray<AncPrivateVaultCanonicalValue *> *fields = entry.arrayValue;
    if (fields[0].type != AncPrivateVaultCanonicalTypeBytes ||
        fields[1].type != AncPrivateVaultCanonicalTypeInteger ||
        fields[2].type != AncPrivateVaultCanonicalTypeBytes ||
        fields[3].type != AncPrivateVaultCanonicalTypeBytes ||
        fields[1].integerValue <= 0)
      return nil;
    AncPrivateVaultRotationEvidenceStoreLiveRevision *revision =
        [[AncPrivateVaultRotationEvidenceStoreLiveRevision alloc]
            initWithObjectId:fields[0].bytesValue
                    revision:(uint64_t)fields[1].integerValue
             priorRevisionId:fields[2].bytesValue
           rotatedRevisionId:fields[3].bytesValue];
    if (revision == nil)
      return nil;
    if (priorLiveRevision != nil) {
      NSComparisonResult objects = AncRotationEvidenceCompareData(
          priorLiveRevision.objectId, revision.objectId);
      if (objects == NSOrderedDescending ||
          (objects == NSOrderedSame &&
           priorLiveRevision.revision >= revision.revision))
        return nil;
    }
    [liveRevisions addObject:revision];
    priorLiveRevision = revision;
  }
  NSDictionary *acks = AncRotationEvidenceDecodeEvidence(
      AncRotationEvidenceField(map, @13, AncPrivateVaultCanonicalTypeArray),
      recipientEndpoints);
  NSDictionary *destructions = AncRotationEvidenceDecodeEvidence(
      AncRotationEvidenceField(map, @14, AncPrivateVaultCanonicalTypeArray),
      recipientEndpoints);
  if (acks == nil || destructions == nil)
    return nil;
  NSUInteger count = recipients.count;
  AncPrivateVaultRotationEvidenceStorePhase expectedPhase;
  if (acks.count < count) {
    if (destructions.count != 0)
      return nil;
    expectedPhase =
        AncPrivateVaultRotationEvidenceStorePhaseAcknowledgements;
  } else if (destructions.count < count) {
    expectedPhase = AncPrivateVaultRotationEvidenceStorePhaseDestructions;
  } else {
    expectedPhase = AncPrivateVaultRotationEvidenceStorePhaseComplete;
  }
  if ((AncPrivateVaultRotationEvidenceStorePhase)phaseValue != expectedPhase)
    return nil;
  AncPrivateVaultRotationEvidenceStoreCheckpoint *result =
      [[AncPrivateVaultRotationEvidenceStoreCheckpoint alloc] init];
  result.vaultId = [vault copy];
  result.ceremonyId = [ceremony copy];
  result.targetEndpointId = [target copy];
  result.preparationFenceGeneration = (uint64_t)fence;
  result.preparationRecordDigest = [preparationDigest copy];
  result.generation = (uint64_t)generation;
  result.contentDigest = [contentDigest copy];
  result.encodedCheckpoint = [encodedCheckpoint copy];
  result.recipients = [NSArray arrayWithArray:recipients];
  result.liveRevisions = [NSArray arrayWithArray:liveRevisions];
  result.acknowledgements = acks;
  result.destructions = destructions;
  result.phase = expectedPhase;
  return result;
}

static BOOL AncRotationEvidenceCheckpointEqual(
    AncPrivateVaultRotationEvidenceStoreCheckpoint *left,
    AncPrivateVaultRotationEvidenceStoreCheckpoint *right) {
  return left != nil && right != nil && left.generation == right.generation &&
         left.preparationFenceGeneration ==
             right.preparationFenceGeneration &&
         [left.vaultId isEqualToData:right.vaultId] &&
         [left.ceremonyId isEqualToData:right.ceremonyId] &&
         [left.targetEndpointId isEqualToData:right.targetEndpointId] &&
         [left.preparationRecordDigest
             isEqualToData:right.preparationRecordDigest] &&
         [left.contentDigest isEqualToData:right.contentDigest];
}

static BOOL AncRotationEvidenceRecipientsEqual(
    NSArray<AncPrivateVaultRotationEvidenceStoreRecipient *> *left,
    NSArray<AncPrivateVaultRotationEvidenceStoreRecipient *> *right) {
  if (left.count != right.count)
    return NO;
  for (NSUInteger index = 0; index < left.count; index += 1) {
    AncPrivateVaultRotationEvidenceStoreRecipient *a = left[index];
    AncPrivateVaultRotationEvidenceStoreRecipient *b = right[index];
    if (![a.endpointId isEqualToData:b.endpointId] ||
        ![a.signingPublicKey isEqualToData:b.signingPublicKey] ||
        ![a.keyAgreementPublicKey isEqualToData:b.keyAgreementPublicKey] ||
        ![a.encodedOffer isEqualToData:b.encodedOffer] ||
        ![a.encodedEEKWrap isEqualToData:b.encodedEEKWrap])
      return NO;
  }
  return YES;
}

static BOOL AncRotationEvidenceLiveRevisionsEqual(
    NSArray<AncPrivateVaultRotationEvidenceStoreLiveRevision *> *left,
    NSArray<AncPrivateVaultRotationEvidenceStoreLiveRevision *> *right) {
  if (left.count != right.count)
    return NO;
  for (NSUInteger index = 0; index < left.count; index += 1) {
    AncPrivateVaultRotationEvidenceStoreLiveRevision *a = left[index];
    AncPrivateVaultRotationEvidenceStoreLiveRevision *b = right[index];
    if (a.revision != b.revision || ![a.objectId isEqualToData:b.objectId] ||
        ![a.priorRevisionId isEqualToData:b.priorRevisionId] ||
        ![a.rotatedRevisionId isEqualToData:b.rotatedRevisionId])
      return NO;
  }
  return YES;
}

static BOOL AncRotationEvidenceCheckpointBindingEqual(
    AncPrivateVaultRotationEvidenceStoreCheckpoint *left,
    AncPrivateVaultRotationEvidenceStoreCheckpoint *right) {
  return left != nil && right != nil &&
         left.preparationFenceGeneration ==
             right.preparationFenceGeneration &&
         [left.vaultId isEqualToData:right.vaultId] &&
         [left.ceremonyId isEqualToData:right.ceremonyId] &&
         [left.targetEndpointId isEqualToData:right.targetEndpointId] &&
         [left.preparationRecordDigest
             isEqualToData:right.preparationRecordDigest] &&
         [left.encodedCheckpoint isEqualToData:right.encodedCheckpoint] &&
         AncRotationEvidenceRecipientsEqual(left.recipients,
                                             right.recipients) &&
         AncRotationEvidenceLiveRevisionsEqual(left.liveRevisions,
                                                right.liveRevisions);
}

static NSString *AncRotationEvidenceVaultHex(NSData *vaultId) {
  if (vaultId.length != ANC_PV_ROTATION_EVIDENCE_STORE_ID_BYTES)
    return nil;
  NSMutableString *hex = [NSMutableString stringWithCapacity:32];
  const uint8_t *bytes = vaultId.bytes;
  for (NSUInteger index = 0; index < vaultId.length; index += 1)
    [hex appendFormat:@"%02x", bytes[index]];
  return hex;
}

static BOOL AncRotationEvidenceDirectorySecure(int descriptor,
                                                dev_t expectedDevice) {
  struct stat state;
  return descriptor >= 0 && fstat(descriptor, &state) == 0 &&
         S_ISDIR(state.st_mode) && state.st_uid == geteuid() &&
         (state.st_mode & 0777) == 0700 &&
         (expectedDevice == 0 || state.st_dev == expectedDevice);
}

static BOOL AncRotationEvidenceFileSecure(int descriptor, struct stat *output) {
  struct stat state;
  BOOL okay = descriptor >= 0 && fstat(descriptor, &state) == 0 &&
              S_ISREG(state.st_mode) && state.st_uid == geteuid() &&
              state.st_nlink == 1 && (state.st_mode & 0777) == 0600 &&
              state.st_size > 0 &&
              state.st_size <= (off_t)kAncRotationEvidenceMaximumRecordBytes;
  if (okay && output != NULL)
    *output = state;
  return okay;
}

@implementation AncPrivateVaultRotationEvidenceStore

- (instancetype)initWithStateRootURL:(NSURL *)stateRootURL {
  if ((self = [super init]) == nil || stateRootURL == nil ||
      !stateRootURL.isFileURL)
    return nil;
  NSString *path = stateRootURL.path;
  if (path.length == 0 || !path.isAbsolutePath ||
      ![path.stringByStandardizingPath isEqualToString:path])
    return nil;
  _stateRootURL = [stateRootURL copy];
  _queue = AncRotationEvidenceQueue();
  return self;
}

- (BOOL)pinDirectory:(int)descriptor
              pinned:(BOOL *)pinned
              device:(dev_t *)device
               inode:(ino_t *)inode
               owner:(uid_t *)owner
      expectedDevice:(dev_t)expectedDevice {
  struct stat state;
  if (!AncRotationEvidenceDirectorySecure(descriptor, expectedDevice) ||
      fstat(descriptor, &state) != 0)
    return NO;
  if (!*pinned) {
    *pinned = YES;
    *device = state.st_dev;
    *inode = state.st_ino;
    *owner = state.st_uid;
    return YES;
  }
  return *device == state.st_dev && *inode == state.st_ino &&
         *owner == state.st_uid;
}

- (BOOL)prepareDirectory {
  const char *path = self.stateRootURL.fileSystemRepresentation;
  struct stat pathState;
  if (lstat(path, &pathState) != 0 || !S_ISDIR(pathState.st_mode) ||
      pathState.st_uid != geteuid() || (pathState.st_mode & 0777) != 0700)
    return NO;
  int root = open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  struct stat openedRoot;
  if (root < 0 || fstat(root, &openedRoot) != 0 ||
      openedRoot.st_dev != pathState.st_dev ||
      openedRoot.st_ino != pathState.st_ino ||
      ![self pinDirectory:root
                   pinned:&_rootPinned
                   device:&_rootDevice
                    inode:&_rootInode
                    owner:&_rootOwner
           expectedDevice:0]) {
    if (root >= 0)
      close(root);
    return NO;
  }
  int state =
      openat(root, "state", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  if (state < 0 && errno == ENOENT) {
    if (mkdirat(root, "state", 0700) != 0 || fsync(root) != 0) {
      close(root);
      return NO;
    }
    state = openat(root, "state",
                   O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  }
  if (![self pinDirectory:state
                   pinned:&_statePinned
                   device:&_stateDevice
                    inode:&_stateInode
                    owner:&_stateOwner
           expectedDevice:self.rootDevice]) {
    if (state >= 0)
      close(state);
    close(root);
    return NO;
  }
  int directory = openat(state, kAncRotationEvidenceDirectory.UTF8String,
                         O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  if (directory < 0 && errno == ENOENT) {
    if (mkdirat(state, kAncRotationEvidenceDirectory.UTF8String, 0700) != 0 ||
        fsync(state) != 0) {
      close(state);
      close(root);
      return NO;
    }
    directory = openat(state, kAncRotationEvidenceDirectory.UTF8String,
                       O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  }
  BOOL valid = [self pinDirectory:directory
                           pinned:&_directoryPinned
                           device:&_directoryDevice
                            inode:&_directoryInode
                            owner:&_directoryOwner
                   expectedDevice:self.stateDevice];
  BOOL parentsClosed = close(state) == 0 && close(root) == 0;
  if (!valid || !parentsClosed) {
    if (directory >= 0)
      close(directory);
    return NO;
  }
  int listingFD = dup(directory);
  DIR *listing = listingFD < 0 ? NULL : fdopendir(listingFD);
  if (listing == NULL) {
    if (listingFD >= 0)
      close(listingFD);
    close(directory);
    return NO;
  }
  if (flock(directory, LOCK_EX) != 0) {
    closedir(listing);
    close(directory);
    return NO;
  }
  NSRegularExpression *live = [NSRegularExpression
      regularExpressionWithPattern:@"^[0-9a-f]{32}\\.rotation-evidence$"
                           options:0
                             error:nil];
  NSRegularExpression *temporary = [NSRegularExpression
      regularExpressionWithPattern:
          @"^\\.[0-9a-f]{32}\\.[0-9a-f-]{36}\\.tmp$"
                           options:0
                             error:nil];
  BOOL okay = YES;
  errno = 0;
  struct dirent *entry;
  while (okay && (entry = readdir(listing)) != NULL) {
    if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
      continue;
    NSString *name = [NSString stringWithUTF8String:entry->d_name];
    NSRange range = NSMakeRange(0, name.length);
    if (name == nil) {
      okay = NO;
    } else if ([live firstMatchInString:name options:0 range:range] != nil) {
      int file = openat(directory, entry->d_name,
                        O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
      okay = AncRotationEvidenceFileSecure(file, NULL) && close(file) == 0;
    } else if ([temporary firstMatchInString:name options:0 range:range] !=
               nil) {
      struct stat temporaryState;
      okay = fstatat(directory, entry->d_name, &temporaryState,
                     AT_SYMLINK_NOFOLLOW) == 0 &&
             S_ISREG(temporaryState.st_mode) &&
             temporaryState.st_uid == geteuid() && temporaryState.st_nlink == 1 &&
             (temporaryState.st_mode & 0777) == 0600 &&
             temporaryState.st_size >= 0 &&
             temporaryState.st_size <=
                 (off_t)kAncRotationEvidenceMaximumRecordBytes &&
             unlinkat(directory, entry->d_name, 0) == 0 &&
             fsync(directory) == 0;
    } else {
      okay = NO;
    }
  }
  okay = okay && errno == 0 && closedir(listing) == 0;
  okay = flock(directory, LOCK_UN) == 0 && okay;
  okay = close(directory) == 0 && okay;
  return okay;
}

- (int)openValidatedDirectory {
  int root = open(self.stateRootURL.fileSystemRepresentation,
                  O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  struct stat rootState;
  if (root < 0 || fstat(root, &rootState) != 0 || !self.rootPinned ||
      rootState.st_dev != self.rootDevice || rootState.st_ino != self.rootInode ||
      rootState.st_uid != self.rootOwner ||
      !AncRotationEvidenceDirectorySecure(root, 0)) {
    if (root >= 0)
      close(root);
    return -1;
  }
  int state =
      openat(root, "state", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  struct stat stateState;
  if (state < 0 || fstat(state, &stateState) != 0 || !self.statePinned ||
      stateState.st_dev != self.stateDevice ||
      stateState.st_ino != self.stateInode ||
      stateState.st_uid != self.stateOwner ||
      !AncRotationEvidenceDirectorySecure(state, self.rootDevice)) {
    if (state >= 0)
      close(state);
    close(root);
    return -1;
  }
  int directory = openat(state, kAncRotationEvidenceDirectory.UTF8String,
                         O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  struct stat directoryState;
  BOOL valid = directory >= 0 && fstat(directory, &directoryState) == 0 &&
               self.directoryPinned &&
               directoryState.st_dev == self.directoryDevice &&
               directoryState.st_ino == self.directoryInode &&
               directoryState.st_uid == self.directoryOwner &&
               AncRotationEvidenceDirectorySecure(directory, self.stateDevice);
  BOOL closed = close(state) == 0 && close(root) == 0;
  if (!valid || !closed) {
    if (directory >= 0)
      close(directory);
    return -1;
  }
  return directory;
}

- (AncRotationEvidenceReadStatus)readName:(NSString *)name
                                 directory:(int)directory
                                      data:(NSData **)data
                                     state:(struct stat *)state {
  if (data != NULL)
    *data = nil;
  int file = openat(directory, name.UTF8String,
                    O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
  if (file < 0)
    return errno == ENOENT ? AncRotationEvidenceReadStatusNotFound
                           : (errno == ELOOP
                                  ? AncRotationEvidenceReadStatusUnsafe
                                  : AncRotationEvidenceReadStatusFailed);
  struct stat before;
  if (!AncRotationEvidenceFileSecure(file, &before)) {
    close(file);
    return AncRotationEvidenceReadStatusUnsafe;
  }
  NSMutableData *contents =
      [NSMutableData dataWithLength:(NSUInteger)before.st_size];
  size_t offset = 0;
  while (offset < contents.length) {
    ssize_t amount = read(file, (uint8_t *)contents.mutableBytes + offset,
                          contents.length - offset);
    if (amount <= 0)
      break;
    offset += (size_t)amount;
  }
  uint8_t extra = 0;
  ssize_t extraCount = read(file, &extra, 1);
  struct stat after;
  struct stat path;
  BOOL stable = offset == contents.length && extraCount == 0 &&
                fstat(file, &after) == 0 &&
                fstatat(directory, name.UTF8String, &path,
                        AT_SYMLINK_NOFOLLOW) == 0 &&
                before.st_dev == after.st_dev && before.st_ino == after.st_ino &&
                before.st_size == after.st_size && before.st_nlink == 1 &&
                path.st_dev == before.st_dev && path.st_ino == before.st_ino &&
                path.st_size == before.st_size && path.st_nlink == 1;
  stable = close(file) == 0 && stable;
  if (!stable)
    return AncRotationEvidenceReadStatusFailed;
  if (data != NULL)
    *data = [NSData dataWithData:contents];
  if (state != NULL)
    *state = before;
  return AncRotationEvidenceReadStatusOK;
}

- (BOOL)writeAll:(int)descriptor data:(NSData *)data {
  size_t offset = 0;
  while (offset < data.length) {
    ssize_t amount = write(descriptor, (const uint8_t *)data.bytes + offset,
                           data.length - offset);
    if (amount <= 0)
      return NO;
    offset += (size_t)amount;
  }
  return YES;
}

- (AncPrivateVaultRotationEvidenceStoreStatus)
    installRecord:(NSData *)record
              name:(NSString *)name
         directory:(int)directory
      expectedState:(const struct stat *)expectedState {
  NSString *vaultHex = [name substringToIndex:32];
  NSString *temporary = [NSString
      stringWithFormat:@".%@.%@.tmp", vaultHex,
                       NSUUID.UUID.UUIDString.lowercaseString];
  int file = openat(directory, temporary.UTF8String,
                    O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                    0600);
  struct stat written;
  BOOL okay = file >= 0 && fstat(file, &written) == 0 &&
              S_ISREG(written.st_mode) && written.st_uid == geteuid() &&
              written.st_nlink == 1 && (written.st_mode & 0777) == 0600 &&
              written.st_size == 0 && [self writeAll:file data:record] &&
              fsync(file) == 0 &&
              fstat(file, &written) == 0 &&
              written.st_size == (off_t)record.length;
  if (file >= 0)
    okay = close(file) == 0 && okay;
  if (!okay) {
    unlinkat(directory, temporary.UTF8String, 0);
    return AncPrivateVaultRotationEvidenceStoreStatusStorageFailed;
  }
  if (AncRotationEvidenceFault(
          AncPrivateVaultRotationEvidenceStoreFaultAfterTemporaryFsync))
    return AncPrivateVaultRotationEvidenceStoreStatusStorageFailed;
  struct stat current;
  if (expectedState == NULL) {
    if (fstatat(directory, name.UTF8String, &current, AT_SYMLINK_NOFOLLOW) == 0 ||
        errno != ENOENT) {
      unlinkat(directory, temporary.UTF8String, 0);
      return AncPrivateVaultRotationEvidenceStoreStatusConflict;
    }
  } else if (fstatat(directory, name.UTF8String, &current,
                     AT_SYMLINK_NOFOLLOW) != 0 ||
             current.st_dev != expectedState->st_dev ||
             current.st_ino != expectedState->st_ino ||
             current.st_size != expectedState->st_size || current.st_nlink != 1 ||
             !S_ISREG(current.st_mode) || current.st_uid != geteuid() ||
             (current.st_mode & 0777) != 0600) {
    unlinkat(directory, temporary.UTF8String, 0);
    return AncPrivateVaultRotationEvidenceStoreStatusConflict;
  }
  if (AncRotationEvidenceFault(
          AncPrivateVaultRotationEvidenceStoreFaultBeforeRename))
    return AncPrivateVaultRotationEvidenceStoreStatusStorageFailed;
  int renamed = expectedState == NULL
                    ? renameatx_np(directory, temporary.UTF8String, directory,
                                   name.UTF8String, RENAME_EXCL)
                    : renameat(directory, temporary.UTF8String, directory,
                               name.UTF8String);
  if (renamed != 0) {
    unlinkat(directory, temporary.UTF8String, 0);
    return errno == EEXIST
               ? AncPrivateVaultRotationEvidenceStoreStatusConflict
               : AncPrivateVaultRotationEvidenceStoreStatusStorageFailed;
  }
  if (AncRotationEvidenceFault(
          AncPrivateVaultRotationEvidenceStoreFaultAfterRename) ||
      fsync(directory) != 0)
    return AncPrivateVaultRotationEvidenceStoreStatusStorageFailed;
  if (AncRotationEvidenceFault(
          AncPrivateVaultRotationEvidenceStoreFaultBeforeReadback))
    return AncPrivateVaultRotationEvidenceStoreStatusStorageFailed;
  NSData *readback = nil;
  AncRotationEvidenceReadStatus read =
      [self readName:name directory:directory data:&readback state:NULL];
  return read == AncRotationEvidenceReadStatusOK &&
                 [readback isEqualToData:record]
             ? AncPrivateVaultRotationEvidenceStoreStatusOK
             : AncPrivateVaultRotationEvidenceStoreStatusStorageFailed;
}

- (AncPrivateVaultRotationEvidenceStoreStatus)
    withLockedDirectory:(AncPrivateVaultRotationEvidenceStoreStatus (^)(int))block {
  if (![self prepareDirectory])
    return AncPrivateVaultRotationEvidenceStoreStatusStorageFailed;
  int directory = [self openValidatedDirectory];
  if (directory < 0 || flock(directory, LOCK_EX) != 0) {
    if (directory >= 0)
      close(directory);
    return AncPrivateVaultRotationEvidenceStoreStatusStorageFailed;
  }
  AncPrivateVaultRotationEvidenceStoreStatus result = block(directory);
  if (flock(directory, LOCK_UN) != 0 || close(directory) != 0)
    return AncPrivateVaultRotationEvidenceStoreStatusStorageFailed;
  return result;
}

- (AncPrivateVaultRotationEvidenceStoreStatus)
    createVaultId:(NSData *)vaultId
       ceremonyId:(NSData *)ceremonyId
  targetEndpointId:(NSData *)targetEndpointId
preparationFenceGeneration:(uint64_t)preparationFenceGeneration
preparationRecordDigest:(NSData *)preparationRecordDigest
 encodedCheckpoint:(NSData *)encodedCheckpoint
         recipients:
             (NSArray<AncPrivateVaultRotationEvidenceStoreRecipient *> *)recipients
      liveRevisions:
          (NSArray<AncPrivateVaultRotationEvidenceStoreLiveRevision *> *)
              liveRevisions
         checkpoint:
             (AncPrivateVaultRotationEvidenceStoreCheckpoint **)checkpoint {
  if (checkpoint != NULL)
    *checkpoint = nil;
  NSData *vault = AncRotationEvidenceBoundedCopy(
      vaultId, ANC_PV_ROTATION_EVIDENCE_STORE_ID_BYTES,
      ANC_PV_ROTATION_EVIDENCE_STORE_ID_BYTES);
  NSData *ceremony = AncRotationEvidenceBoundedCopy(
      ceremonyId, ANC_PV_ROTATION_EVIDENCE_STORE_ID_BYTES,
      ANC_PV_ROTATION_EVIDENCE_STORE_ID_BYTES);
  NSData *target = AncRotationEvidenceBoundedCopy(
      targetEndpointId, ANC_PV_ROTATION_EVIDENCE_STORE_ID_BYTES,
      ANC_PV_ROTATION_EVIDENCE_STORE_ID_BYTES);
  NSData *preparationDigest = AncRotationEvidenceBoundedCopy(
      preparationRecordDigest, ANC_PV_ROTATION_EVIDENCE_STORE_DIGEST_BYTES,
      ANC_PV_ROTATION_EVIDENCE_STORE_DIGEST_BYTES);
  NSData *canonicalCheckpoint = AncRotationEvidenceBoundedCopy(
      encodedCheckpoint, 0,
      ANC_PV_ROTATION_EVIDENCE_STORE_MAX_ARTIFACT_BYTES);
  NSArray *roster = AncRotationEvidenceRecipientsSnapshot(recipients);
  NSArray *revisionRoster =
      AncRotationEvidenceLiveRevisionsSnapshot(liveRevisions);
  if (vault == nil || ceremony == nil || target == nil ||
      preparationDigest == nil || canonicalCheckpoint == nil || roster == nil ||
      revisionRoster == nil ||
      !AncRotationEvidenceCanonicalArtifact(canonicalCheckpoint) ||
      preparationFenceGeneration == 0 ||
      preparationFenceGeneration > kAncRotationEvidenceMaximumSafeInteger)
    return AncPrivateVaultRotationEvidenceStoreStatusInvalid;
  AncPrivateVaultRotationEvidenceStoreCheckpoint *created =
      [[AncPrivateVaultRotationEvidenceStoreCheckpoint alloc] init];
  created.vaultId = vault;
  created.ceremonyId = ceremony;
  created.targetEndpointId = target;
  created.preparationFenceGeneration = preparationFenceGeneration;
  created.preparationRecordDigest = preparationDigest;
  created.generation = 1;
  created.encodedCheckpoint = canonicalCheckpoint;
  created.recipients = roster;
  created.liveRevisions = revisionRoster;
  created.acknowledgements = @{};
  created.destructions = @{};
  created.phase =
      AncPrivateVaultRotationEvidenceStorePhaseAcknowledgements;
  NSData *record = AncRotationEvidenceEncodeCheckpoint(created);
  AncPrivateVaultRotationEvidenceStoreCheckpoint *decoded =
      AncRotationEvidenceDecodeCheckpoint(record, vault);
  if (decoded == nil)
    return AncPrivateVaultRotationEvidenceStoreStatusInvalid;
  __block AncPrivateVaultRotationEvidenceStoreCheckpoint *resultCheckpoint = nil;
  __block AncPrivateVaultRotationEvidenceStoreStatus result;
  dispatch_sync(self.queue, ^{
    result = [self withLockedDirectory:^AncPrivateVaultRotationEvidenceStoreStatus(
                       int directory) {
      NSString *name = [AncRotationEvidenceVaultHex(vault)
          stringByAppendingString:kAncRotationEvidenceSuffix];
      NSData *existing = nil;
      AncRotationEvidenceReadStatus read =
          [self readName:name directory:directory data:&existing state:NULL];
      if (read == AncRotationEvidenceReadStatusOK) {
        AncPrivateVaultRotationEvidenceStoreCheckpoint *live =
            AncRotationEvidenceDecodeCheckpoint(existing, vault);
        if (live == nil)
          return AncPrivateVaultRotationEvidenceStoreStatusCorrupt;
        if (![existing isEqualToData:record])
          return AncPrivateVaultRotationEvidenceStoreStatusConflict;
        resultCheckpoint = live;
        return AncPrivateVaultRotationEvidenceStoreStatusOK;
      }
      if (read != AncRotationEvidenceReadStatusNotFound)
        return read == AncRotationEvidenceReadStatusUnsafe
                   ? AncPrivateVaultRotationEvidenceStoreStatusCorrupt
                   : AncPrivateVaultRotationEvidenceStoreStatusStorageFailed;
      AncPrivateVaultRotationEvidenceStoreStatus installed =
          [self installRecord:record
                         name:name
                    directory:directory
                 expectedState:NULL];
      if (installed == AncPrivateVaultRotationEvidenceStoreStatusOK)
        resultCheckpoint = decoded;
      return installed;
    }];
  });
  if (result == AncPrivateVaultRotationEvidenceStoreStatusOK &&
      checkpoint != NULL)
    *checkpoint = resultCheckpoint;
  return result;
}

- (AncPrivateVaultRotationEvidenceStoreStatus)
    readVaultId:(NSData *)vaultId
      checkpoint:(AncPrivateVaultRotationEvidenceStoreCheckpoint **)checkpoint {
  if (checkpoint != NULL)
    *checkpoint = nil;
  NSData *vault = AncRotationEvidenceBoundedCopy(
      vaultId, ANC_PV_ROTATION_EVIDENCE_STORE_ID_BYTES,
      ANC_PV_ROTATION_EVIDENCE_STORE_ID_BYTES);
  if (vault == nil)
    return AncPrivateVaultRotationEvidenceStoreStatusInvalid;
  __block AncPrivateVaultRotationEvidenceStoreCheckpoint *loaded = nil;
  __block AncPrivateVaultRotationEvidenceStoreStatus result;
  dispatch_sync(self.queue, ^{
    result = [self withLockedDirectory:^AncPrivateVaultRotationEvidenceStoreStatus(
                       int directory) {
      NSString *name = [AncRotationEvidenceVaultHex(vault)
          stringByAppendingString:kAncRotationEvidenceSuffix];
      NSData *record = nil;
      AncRotationEvidenceReadStatus read =
          [self readName:name directory:directory data:&record state:NULL];
      if (read == AncRotationEvidenceReadStatusNotFound)
        return AncPrivateVaultRotationEvidenceStoreStatusNotFound;
      if (read != AncRotationEvidenceReadStatusOK)
        return read == AncRotationEvidenceReadStatusUnsafe
                   ? AncPrivateVaultRotationEvidenceStoreStatusCorrupt
                   : AncPrivateVaultRotationEvidenceStoreStatusStorageFailed;
      loaded = AncRotationEvidenceDecodeCheckpoint(record, vault);
      return loaded == nil ? AncPrivateVaultRotationEvidenceStoreStatusCorrupt
                           : AncPrivateVaultRotationEvidenceStoreStatusOK;
    }];
  });
  if (result == AncPrivateVaultRotationEvidenceStoreStatusOK &&
      checkpoint != NULL)
    *checkpoint = loaded;
  return result;
}

- (AncPrivateVaultRotationEvidenceStoreStatus)
    storeEvidence:(NSData *)evidence
        endpointId:(NSData *)endpointId
           vaultId:(NSData *)vaultId
 expectedCheckpoint:
     (AncPrivateVaultRotationEvidenceStoreCheckpoint *)expectedCheckpoint
              kind:(BOOL)isDestruction
        checkpoint:
            (AncPrivateVaultRotationEvidenceStoreCheckpoint **)checkpoint {
  if (checkpoint != NULL)
    *checkpoint = nil;
  NSData *artifact = AncRotationEvidenceBoundedCopy(
      evidence, 0, ANC_PV_ROTATION_EVIDENCE_STORE_MAX_ARTIFACT_BYTES);
  NSData *endpoint = AncRotationEvidenceBoundedCopy(
      endpointId, ANC_PV_ROTATION_EVIDENCE_STORE_ID_BYTES,
      ANC_PV_ROTATION_EVIDENCE_STORE_ID_BYTES);
  NSData *vault = AncRotationEvidenceBoundedCopy(
      vaultId, ANC_PV_ROTATION_EVIDENCE_STORE_ID_BYTES,
      ANC_PV_ROTATION_EVIDENCE_STORE_ID_BYTES);
  if (artifact == nil || endpoint == nil || vault == nil ||
      expectedCheckpoint == nil ||
      !AncRotationEvidenceCanonicalArtifact(artifact))
    return AncPrivateVaultRotationEvidenceStoreStatusInvalid;
  __block AncPrivateVaultRotationEvidenceStoreCheckpoint *output = nil;
  __block AncPrivateVaultRotationEvidenceStoreStatus result;
  dispatch_sync(self.queue, ^{
    result = [self withLockedDirectory:^AncPrivateVaultRotationEvidenceStoreStatus(
                       int directory) {
      NSString *name = [AncRotationEvidenceVaultHex(vault)
          stringByAppendingString:kAncRotationEvidenceSuffix];
      NSData *record = nil;
      struct stat state;
      AncRotationEvidenceReadStatus read =
          [self readName:name directory:directory data:&record state:&state];
      if (read == AncRotationEvidenceReadStatusNotFound)
        return AncPrivateVaultRotationEvidenceStoreStatusNotFound;
      if (read != AncRotationEvidenceReadStatusOK)
        return read == AncRotationEvidenceReadStatusUnsafe
                   ? AncPrivateVaultRotationEvidenceStoreStatusCorrupt
                   : AncPrivateVaultRotationEvidenceStoreStatusStorageFailed;
      AncPrivateVaultRotationEvidenceStoreCheckpoint *live =
          AncRotationEvidenceDecodeCheckpoint(record, vault);
      if (live == nil)
        return AncPrivateVaultRotationEvidenceStoreStatusCorrupt;
      if (!AncRotationEvidenceCheckpointBindingEqual(live,
                                                      expectedCheckpoint))
        return AncPrivateVaultRotationEvidenceStoreStatusConflict;
      NSSet *roster = [NSSet setWithArray:[live.recipients
          valueForKey:@"endpointId"]];
      if (![roster containsObject:endpoint])
        return AncPrivateVaultRotationEvidenceStoreStatusConflict;
      NSDictionary<NSData *, NSData *> *current =
          isDestruction ? live.destructions : live.acknowledgements;
      NSData *existing = current[endpoint];
      if (existing != nil) {
        if (![existing isEqualToData:artifact])
          return AncPrivateVaultRotationEvidenceStoreStatusConflict;
        output = live;
        return AncPrivateVaultRotationEvidenceStoreStatusOK;
      }
      if (!AncRotationEvidenceCheckpointEqual(live, expectedCheckpoint) ||
          (isDestruction &&
           live.phase !=
               AncPrivateVaultRotationEvidenceStorePhaseDestructions) ||
          (!isDestruction &&
           live.phase !=
               AncPrivateVaultRotationEvidenceStorePhaseAcknowledgements))
        return AncPrivateVaultRotationEvidenceStoreStatusConflict;
      NSMutableDictionary *acks = [live.acknowledgements mutableCopy];
      NSMutableDictionary *destructions = [live.destructions mutableCopy];
      (isDestruction ? destructions : acks)[endpoint] = artifact;
      AncPrivateVaultRotationEvidenceStoreCheckpoint *next =
          [[AncPrivateVaultRotationEvidenceStoreCheckpoint alloc] init];
      next.vaultId = live.vaultId;
      next.ceremonyId = live.ceremonyId;
      next.targetEndpointId = live.targetEndpointId;
      next.preparationFenceGeneration = live.preparationFenceGeneration;
      next.preparationRecordDigest = live.preparationRecordDigest;
      next.generation = live.generation + 1;
      next.encodedCheckpoint = live.encodedCheckpoint;
      next.recipients = live.recipients;
      next.liveRevisions = live.liveRevisions;
      next.acknowledgements = [NSDictionary dictionaryWithDictionary:acks];
      next.destructions =
          [NSDictionary dictionaryWithDictionary:destructions];
      if (next.acknowledgements.count < next.recipients.count)
        next.phase =
            AncPrivateVaultRotationEvidenceStorePhaseAcknowledgements;
      else if (next.destructions.count < next.recipients.count)
        next.phase = AncPrivateVaultRotationEvidenceStorePhaseDestructions;
      else
        next.phase = AncPrivateVaultRotationEvidenceStorePhaseComplete;
      NSData *nextRecord = AncRotationEvidenceEncodeCheckpoint(next);
      AncPrivateVaultRotationEvidenceStoreCheckpoint *decoded =
          AncRotationEvidenceDecodeCheckpoint(nextRecord, vault);
      if (decoded == nil)
        return AncPrivateVaultRotationEvidenceStoreStatusCorrupt;
      AncPrivateVaultRotationEvidenceStoreStatus installed =
          [self installRecord:nextRecord
                         name:name
                    directory:directory
                 expectedState:&state];
      if (installed == AncPrivateVaultRotationEvidenceStoreStatusOK)
        output = decoded;
      return installed;
    }];
  });
  if (result == AncPrivateVaultRotationEvidenceStoreStatusOK &&
      checkpoint != NULL)
    *checkpoint = output;
  return result;
}

- (AncPrivateVaultRotationEvidenceStoreStatus)
    storeAcknowledgement:(NSData *)encodedAcknowledgement
              endpointId:(NSData *)endpointId
                 vaultId:(NSData *)vaultId
       expectedCheckpoint:
           (AncPrivateVaultRotationEvidenceStoreCheckpoint *)expectedCheckpoint
               checkpoint:
                   (AncPrivateVaultRotationEvidenceStoreCheckpoint **)checkpoint {
  return [self storeEvidence:encodedAcknowledgement
                  endpointId:endpointId
                     vaultId:vaultId
           expectedCheckpoint:expectedCheckpoint
                        kind:NO
                  checkpoint:checkpoint];
}

- (AncPrivateVaultRotationEvidenceStoreStatus)
    storeDestruction:(NSData *)encodedDestruction
           endpointId:(NSData *)endpointId
              vaultId:(NSData *)vaultId
    expectedCheckpoint:
        (AncPrivateVaultRotationEvidenceStoreCheckpoint *)expectedCheckpoint
            checkpoint:
                (AncPrivateVaultRotationEvidenceStoreCheckpoint **)checkpoint {
  return [self storeEvidence:encodedDestruction
                  endpointId:endpointId
                     vaultId:vaultId
           expectedCheckpoint:expectedCheckpoint
                        kind:YES
                  checkpoint:checkpoint];
}

- (AncPrivateVaultRotationEvidenceStoreStatus)
    deleteTerminalVaultId:(NSData *)vaultId
       expectedCheckpoint:
           (AncPrivateVaultRotationEvidenceStoreCheckpoint *)expectedCheckpoint {
  NSData *vault = AncRotationEvidenceBoundedCopy(
      vaultId, ANC_PV_ROTATION_EVIDENCE_STORE_ID_BYTES,
      ANC_PV_ROTATION_EVIDENCE_STORE_ID_BYTES);
  if (vault == nil || expectedCheckpoint == nil)
    return AncPrivateVaultRotationEvidenceStoreStatusInvalid;
  __block AncPrivateVaultRotationEvidenceStoreStatus result;
  dispatch_sync(self.queue, ^{
    result = [self withLockedDirectory:^AncPrivateVaultRotationEvidenceStoreStatus(
                       int directory) {
      NSString *name = [AncRotationEvidenceVaultHex(vault)
          stringByAppendingString:kAncRotationEvidenceSuffix];
      NSData *record = nil;
      struct stat witness;
      AncRotationEvidenceReadStatus read =
          [self readName:name directory:directory data:&record state:&witness];
      if (read == AncRotationEvidenceReadStatusNotFound)
        return AncPrivateVaultRotationEvidenceStoreStatusNotFound;
      if (read != AncRotationEvidenceReadStatusOK)
        return read == AncRotationEvidenceReadStatusUnsafe
                   ? AncPrivateVaultRotationEvidenceStoreStatusCorrupt
                   : AncPrivateVaultRotationEvidenceStoreStatusStorageFailed;
      AncPrivateVaultRotationEvidenceStoreCheckpoint *live =
          AncRotationEvidenceDecodeCheckpoint(record, vault);
      if (live == nil)
        return AncPrivateVaultRotationEvidenceStoreStatusCorrupt;
      if (live.phase != AncPrivateVaultRotationEvidenceStorePhaseComplete ||
          !AncRotationEvidenceCheckpointEqual(live, expectedCheckpoint))
        return AncPrivateVaultRotationEvidenceStoreStatusConflict;
      if (AncRotationEvidenceFault(
              AncPrivateVaultRotationEvidenceStoreFaultBeforeUnlink))
        return AncPrivateVaultRotationEvidenceStoreStatusStorageFailed;
      int file = openat(directory, name.UTF8String,
                        O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
      struct stat opened;
      BOOL okay = file >= 0 && fstat(file, &opened) == 0 &&
                  opened.st_dev == witness.st_dev &&
                  opened.st_ino == witness.st_ino &&
                  opened.st_size == witness.st_size && opened.st_nlink == 1 &&
                  unlinkat(directory, name.UTF8String, 0) == 0;
      struct stat after;
      okay = okay && fstat(file, &after) == 0 && after.st_nlink == 0 &&
             fsync(directory) == 0;
      if (file >= 0)
        okay = close(file) == 0 && okay;
      return okay ? AncPrivateVaultRotationEvidenceStoreStatusOK
                  : AncPrivateVaultRotationEvidenceStoreStatusStorageFailed;
    }];
  });
  return result;
}

@end
