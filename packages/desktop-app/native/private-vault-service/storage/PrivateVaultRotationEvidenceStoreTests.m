#import <Foundation/Foundation.h>

#import "PrivateVaultAncCanonical.h"
#import "PrivateVaultRotationEvidenceStore.h"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#define CHECK(value)                                                           \
  do {                                                                         \
    if (!(value)) {                                                            \
      fprintf(stderr, "CHECK failed at %s:%d: %s\n", __FILE__, __LINE__,       \
              #value);                                                         \
      return 1;                                                                \
    }                                                                          \
  } while (0)

static NSData *Bytes(NSUInteger length, uint8_t seed) {
  NSMutableData *data = [NSMutableData dataWithLength:length];
  uint8_t *bytes = data.mutableBytes;
  for (NSUInteger index = 0; index < length; index += 1)
    bytes[index] = (uint8_t)(seed + index * 17);
  return [NSData dataWithData:data];
}

static NSData *Artifact(NSUInteger payloadLength, uint8_t seed) {
  AncPrivateVaultCanonicalValue *value = [AncPrivateVaultCanonicalValue map:@{
    @1 : [AncPrivateVaultCanonicalValue text:@"anc/test/v1"],
    @2 : [AncPrivateVaultCanonicalValue bytes:Bytes(payloadLength, seed)],
  }];
  AncPrivateVaultCanonicalStatus status;
  NSData *encoded = AncPrivateVaultCanonicalEncode(value, &status);
  return status == AncPrivateVaultCanonicalStatusOK ? encoded : nil;
}

static NSURL *TemporaryRoot(void) {
  NSString *path = [NSTemporaryDirectory()
      stringByAppendingPathComponent:
          [@"anc-rotation-evidence-store-"
              stringByAppendingString:NSUUID.UUID.UUIDString]];
  BOOL created = [[NSFileManager defaultManager]
            createDirectoryAtPath:path
      withIntermediateDirectories:NO
                       attributes:@{NSFilePosixPermissions : @0700}
                            error:nil];
  return created ? [NSURL fileURLWithPath:path isDirectory:YES] : nil;
}

static void RemoveRoot(NSURL *root) {
  [[NSFileManager defaultManager] removeItemAtURL:root error:nil];
}

static AncPrivateVaultRotationEvidenceStoreRecipient *Recipient(uint8_t seed) {
  return [[AncPrivateVaultRotationEvidenceStoreRecipient alloc]
      initWithEndpointId:Bytes(16, seed)
        signingPublicKey:Bytes(32, seed + 1)
   keyAgreementPublicKey:Bytes(32, seed + 2)
            encodedOffer:Artifact(80, seed + 3)
          encodedEEKWrap:Artifact(96, seed + 4)];
}

static AncPrivateVaultRotationEvidenceStoreLiveRevision *LiveRevision(
    uint8_t objectSeed, uint64_t revision, uint8_t evidenceSeed) {
  return [[AncPrivateVaultRotationEvidenceStoreLiveRevision alloc]
      initWithObjectId:Bytes(16, objectSeed)
              revision:revision
       priorRevisionId:Bytes(32, evidenceSeed)
     rotatedRevisionId:Bytes(32, evidenceSeed + 1)];
}

static NSArray *DefaultLiveRevisions(void) {
  return @[
    LiveRevision(30, 9, 41), LiveRevision(20, 7, 42),
    LiveRevision(30, 3, 43)
  ];
}

static AncPrivateVaultRotationEvidenceStoreStatus CreateWithLiveRevisions(
    AncPrivateVaultRotationEvidenceStore *store, NSData *vault,
    NSData *ceremony, NSData *target, uint64_t fence, NSData *digest,
    NSArray *recipients, NSArray *liveRevisions,
    AncPrivateVaultRotationEvidenceStoreCheckpoint **checkpoint) {
  return [store createVaultId:vault
                   ceremonyId:ceremony
              targetEndpointId:target
    preparationFenceGeneration:fence
      preparationRecordDigest:digest
             encodedCheckpoint:Artifact(240, 91)
                     recipients:recipients
                  liveRevisions:liveRevisions
                     checkpoint:checkpoint];
}

static AncPrivateVaultRotationEvidenceStoreStatus Create(
    AncPrivateVaultRotationEvidenceStore *store, NSData *vault,
    NSData *ceremony, NSData *target, uint64_t fence, NSData *digest,
    NSArray *recipients,
    AncPrivateVaultRotationEvidenceStoreCheckpoint **checkpoint) {
  return CreateWithLiveRevisions(store, vault, ceremony, target, fence, digest,
                                 recipients, DefaultLiveRevisions(),
                                 checkpoint);
}

static NSURL *EvidenceDirectory(NSURL *root) {
  return [[root URLByAppendingPathComponent:@"state" isDirectory:YES]
      URLByAppendingPathComponent:@"rotation-evidence"
                      isDirectory:YES];
}

static NSString *VaultHex(NSData *vault) {
  NSMutableString *hex = [NSMutableString string];
  const uint8_t *bytes = vault.bytes;
  for (NSUInteger index = 0; index < vault.length; index += 1)
    [hex appendFormat:@"%02x", bytes[index]];
  return hex;
}

static NSURL *LedgerURL(NSURL *root, NSData *vault) {
  return [EvidenceDirectory(root)
      URLByAppendingPathComponent:
          [[VaultHex(vault) stringByAppendingString:@".rotation-evidence"]
              copy]];
}

static BOOL WriteExact(NSURL *url, NSData *data, mode_t mode) {
  int file = open(url.fileSystemRepresentation,
                  O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW, mode);
  if (file < 0)
    return NO;
  size_t offset = 0;
  while (offset < data.length) {
    ssize_t amount = write(file, (const uint8_t *)data.bytes + offset,
                           data.length - offset);
    if (amount <= 0)
      break;
    offset += (size_t)amount;
  }
  return offset == data.length && fsync(file) == 0 && close(file) == 0;
}

static int TestCreateReadBindingsAndBounds(void) {
  NSURL *root = TemporaryRoot();
  CHECK(root != nil);
  AncPrivateVaultRotationEvidenceStore *store =
      [[AncPrivateVaultRotationEvidenceStore alloc] initWithStateRootURL:root];
  NSData *vault = Bytes(16, 1);
  NSData *ceremony = Bytes(16, 2);
  NSData *target = Bytes(16, 3);
  NSData *digest = Bytes(32, 4);
  AncPrivateVaultRotationEvidenceStoreRecipient *second = Recipient(20);
  AncPrivateVaultRotationEvidenceStoreRecipient *first = Recipient(10);
  AncPrivateVaultRotationEvidenceStoreCheckpoint *created = nil;
  CHECK(Create(store, vault, ceremony, target, 7, digest,
               @[ second, first ], &created) ==
        AncPrivateVaultRotationEvidenceStoreStatusOK);
  CHECK(created.generation == 1);
  CHECK(created.phase ==
        AncPrivateVaultRotationEvidenceStorePhaseAcknowledgements);
  CHECK(created.recipients.count == 2);
  CHECK([created.recipients.firstObject.endpointId
      isEqualToData:first.endpointId]);
  CHECK(created.contentDigest.length == 32);
  CHECK(created.liveRevisions.count == 3);
  CHECK([created.liveRevisions[0].objectId
      isEqualToData:Bytes(16, 20)]);
  CHECK(created.liveRevisions[1].revision == 3);
  CHECK(created.liveRevisions[2].revision == 9);
  CHECK(![created.liveRevisions respondsToSelector:@selector(addObject:)]);
  CHECK(![created.liveRevisions[0].objectId
      respondsToSelector:@selector(mutableBytes)]);
  CHECK(![created.contentDigest respondsToSelector:@selector(mutableBytes)]);
  CHECK(![created.recipients respondsToSelector:@selector(addObject:)]);

  AncPrivateVaultRotationEvidenceStoreCheckpoint *idempotent = nil;
  CHECK(Create(store, vault, ceremony, target, 7, digest,
               @[ first, second ], &idempotent) ==
        AncPrivateVaultRotationEvidenceStoreStatusOK);
  CHECK([idempotent.contentDigest isEqualToData:created.contentDigest]);
  CHECK(Create(store, vault, Bytes(16, 8), target, 7, digest,
               @[ first, second ], NULL) ==
        AncPrivateVaultRotationEvidenceStoreStatusConflict);
  CHECK(Create(store, vault, ceremony, Bytes(16, 8), 7, digest,
               @[ first, second ], NULL) ==
        AncPrivateVaultRotationEvidenceStoreStatusConflict);
  CHECK(Create(store, vault, ceremony, target, 8, digest,
               @[ first, second ], NULL) ==
        AncPrivateVaultRotationEvidenceStoreStatusConflict);
  CHECK(Create(store, vault, ceremony, target, 7, Bytes(32, 9),
               @[ first, second ], NULL) ==
        AncPrivateVaultRotationEvidenceStoreStatusConflict);
  CHECK(Create(store, vault, ceremony, target, 7, digest,
               @[ first, first ], NULL) ==
        AncPrivateVaultRotationEvidenceStoreStatusInvalid);
  CHECK(Create(store, vault, ceremony, target, 7, digest, @[ first ], NULL) ==
        AncPrivateVaultRotationEvidenceStoreStatusConflict);
  NSArray *substitutedRevisions = @[
    LiveRevision(30, 9, 41), LiveRevision(20, 7, 42),
    LiveRevision(30, 4, 43)
  ];
  CHECK(CreateWithLiveRevisions(store, vault, ceremony, target, 7, digest,
                                @[ first, second ], substitutedRevisions,
                                NULL) ==
        AncPrivateVaultRotationEvidenceStoreStatusConflict);
  CHECK(Create(store, vault, ceremony, target, 0, digest, @[ first ], NULL) ==
        AncPrivateVaultRotationEvidenceStoreStatusInvalid);

  NSMutableArray *tooMany = [NSMutableArray array];
  for (NSUInteger index = 0; index < 65; index += 1)
    [tooMany addObject:Recipient((uint8_t)index)];
  NSData *otherVault = Bytes(16, 44);
  CHECK(Create(store, otherVault, ceremony, target, 7, digest, tooMany,
               NULL) == AncPrivateVaultRotationEvidenceStoreStatusInvalid);
  CHECK([[AncPrivateVaultRotationEvidenceStoreRecipient alloc]
            initWithEndpointId:Bytes(16, 1)
              signingPublicKey:Bytes(32, 2)
         keyAgreementPublicKey:Bytes(32, 3)
                  encodedOffer:Artifact(1025, 4)
                encodedEEKWrap:Artifact(10, 5)] == nil);
  AncPrivateVaultRotationEvidenceStoreLiveRevision *duplicate =
      LiveRevision(70, 5, 71);
  CHECK(CreateWithLiveRevisions(store, otherVault, ceremony, target, 7, digest,
                                @[ first ], @[ duplicate, duplicate ], NULL) ==
        AncPrivateVaultRotationEvidenceStoreStatusInvalid);
  CHECK(LiveRevision(1, 0, 2) == nil);
  AncPrivateVaultRotationEvidenceStoreCheckpoint *empty = nil;
  CHECK(CreateWithLiveRevisions(store, Bytes(16, 75), ceremony, target, 7,
                                digest, @[ first ], @[], &empty) ==
        AncPrivateVaultRotationEvidenceStoreStatusOK);
  CHECK(empty.liveRevisions.count == 0);
  RemoveRoot(root);
  return 0;
}

static int TestMaximumLiveRevisionRosterAndRestart(void) {
  NSURL *root = TemporaryRoot();
  CHECK(root != nil);
  AncPrivateVaultRotationEvidenceStore *store =
      [[AncPrivateVaultRotationEvidenceStore alloc] initWithStateRootURL:root];
  NSMutableArray *maximum = [NSMutableArray
      arrayWithCapacity:ANC_PV_ROTATION_EVIDENCE_STORE_MAX_LIVE_REVISIONS];
  for (NSUInteger index =
           ANC_PV_ROTATION_EVIDENCE_STORE_MAX_LIVE_REVISIONS;
       index > 0; index -= 1) {
    [maximum addObject:LiveRevision(201, index, (uint8_t)index)];
  }
  NSData *vault = Bytes(16, 202);
  AncPrivateVaultRotationEvidenceStoreCheckpoint *created = nil;
  CHECK(CreateWithLiveRevisions(store, vault, Bytes(16, 203), Bytes(16, 204),
                                55, Bytes(32, 205), @[ Recipient(206) ],
                                maximum, &created) ==
        AncPrivateVaultRotationEvidenceStoreStatusOK);
  CHECK(created.liveRevisions.count ==
        ANC_PV_ROTATION_EVIDENCE_STORE_MAX_LIVE_REVISIONS);
  CHECK(created.liveRevisions.firstObject.revision == 1);
  CHECK(created.liveRevisions.lastObject.revision ==
        ANC_PV_ROTATION_EVIDENCE_STORE_MAX_LIVE_REVISIONS);
  AncPrivateVaultRotationEvidenceStore *restart =
      [[AncPrivateVaultRotationEvidenceStore alloc] initWithStateRootURL:root];
  AncPrivateVaultRotationEvidenceStoreCheckpoint *loaded = nil;
  CHECK([restart readVaultId:vault checkpoint:&loaded] ==
        AncPrivateVaultRotationEvidenceStoreStatusOK);
  CHECK(loaded.liveRevisions.count == maximum.count);
  CHECK([loaded.contentDigest isEqualToData:created.contentDigest]);

  [maximum addObject:LiveRevision(201, 10001, 99)];
  CHECK(CreateWithLiveRevisions(store, Bytes(16, 210), Bytes(16, 203),
                                Bytes(16, 204), 55, Bytes(32, 205),
                                @[ Recipient(206) ], maximum, NULL) ==
        AncPrivateVaultRotationEvidenceStoreStatusInvalid);
  RemoveRoot(root);
  return 0;
}

static int TestExactRosterPhaseIdempotencyAndCAS(void) {
  NSURL *root = TemporaryRoot();
  AncPrivateVaultRotationEvidenceStore *store =
      [[AncPrivateVaultRotationEvidenceStore alloc] initWithStateRootURL:root];
  NSData *vault = Bytes(16, 31);
  AncPrivateVaultRotationEvidenceStoreRecipient *first = Recipient(40);
  AncPrivateVaultRotationEvidenceStoreRecipient *second = Recipient(50);
  AncPrivateVaultRotationEvidenceStoreCheckpoint *c1 = nil;
  CHECK(Create(store, vault, Bytes(16, 32), Bytes(16, 33), 19,
               Bytes(32, 34), @[ first, second ], &c1) ==
        AncPrivateVaultRotationEvidenceStoreStatusOK);

  CHECK([store storeDestruction:Artifact(100, 1)
                        endpointId:first.endpointId
                           vaultId:vault
                 expectedCheckpoint:c1
                         checkpoint:NULL] ==
        AncPrivateVaultRotationEvidenceStoreStatusConflict);
  CHECK([store storeAcknowledgement:Artifact(100, 2)
                              endpointId:Bytes(16, 99)
                                 vaultId:vault
                       expectedCheckpoint:c1
                               checkpoint:NULL] ==
        AncPrivateVaultRotationEvidenceStoreStatusConflict);

  NSData *ackOne = Artifact(180, 61);
  AncPrivateVaultRotationEvidenceStoreCheckpoint *c2 = nil;
  CHECK([store storeAcknowledgement:ackOne
                              endpointId:first.endpointId
                                 vaultId:vault
                       expectedCheckpoint:c1
                               checkpoint:&c2] ==
        AncPrivateVaultRotationEvidenceStoreStatusOK);
  CHECK(c2.generation == 2 && c2.acknowledgements.count == 1);
  CHECK(c2.liveRevisions.count == c1.liveRevisions.count);
  CHECK([c2.liveRevisions[1].rotatedRevisionId
      isEqualToData:c1.liveRevisions[1].rotatedRevisionId]);
  AncPrivateVaultRotationEvidenceStoreCheckpoint *retry = nil;
  CHECK([store storeAcknowledgement:ackOne
                              endpointId:first.endpointId
                                 vaultId:vault
                       expectedCheckpoint:c1
                               checkpoint:&retry] ==
        AncPrivateVaultRotationEvidenceStoreStatusOK);
  CHECK(retry.generation == c2.generation);
  CHECK(retry.liveRevisions.count == c2.liveRevisions.count);
  NSData *otherVault = Bytes(16, 35);
  AncPrivateVaultRotationEvidenceStoreCheckpoint *otherCheckpoint = nil;
  CHECK(Create(store, otherVault, Bytes(16, 36), Bytes(16, 37), 20,
               Bytes(32, 38), @[ Recipient(60) ], &otherCheckpoint) ==
        AncPrivateVaultRotationEvidenceStoreStatusOK);
  CHECK([store storeAcknowledgement:ackOne
                              endpointId:first.endpointId
                                 vaultId:vault
                       expectedCheckpoint:otherCheckpoint
                               checkpoint:NULL] ==
        AncPrivateVaultRotationEvidenceStoreStatusConflict);
  CHECK([store storeAcknowledgement:Artifact(180, 62)
                              endpointId:first.endpointId
                                 vaultId:vault
                       expectedCheckpoint:c2
                               checkpoint:NULL] ==
        AncPrivateVaultRotationEvidenceStoreStatusConflict);
  CHECK([store storeAcknowledgement:Artifact(180, 63)
                              endpointId:second.endpointId
                                 vaultId:vault
                       expectedCheckpoint:c1
                               checkpoint:NULL] ==
        AncPrivateVaultRotationEvidenceStoreStatusConflict);

  AncPrivateVaultRotationEvidenceStoreCheckpoint *c3 = nil;
  NSData *ackTwo = Artifact(181, 64);
  CHECK([store storeAcknowledgement:ackTwo
                              endpointId:second.endpointId
                                 vaultId:vault
                       expectedCheckpoint:c2
                               checkpoint:&c3] ==
        AncPrivateVaultRotationEvidenceStoreStatusOK);
  CHECK(c3.phase == AncPrivateVaultRotationEvidenceStorePhaseDestructions);
  CHECK([store storeAcknowledgement:ackTwo
                              endpointId:second.endpointId
                                 vaultId:vault
                       expectedCheckpoint:c2
                               checkpoint:&retry] ==
        AncPrivateVaultRotationEvidenceStoreStatusOK);

  AncPrivateVaultRotationEvidenceStoreCheckpoint *c4 = nil;
  NSData *destroyOne = Artifact(190, 70);
  CHECK([store storeDestruction:destroyOne
                        endpointId:first.endpointId
                           vaultId:vault
                 expectedCheckpoint:c3
                         checkpoint:&c4] ==
        AncPrivateVaultRotationEvidenceStoreStatusOK);
  CHECK(c4.phase == AncPrivateVaultRotationEvidenceStorePhaseDestructions);
  AncPrivateVaultRotationEvidenceStoreCheckpoint *c5 = nil;
  NSData *destroyTwo = Artifact(191, 71);
  CHECK([store storeDestruction:destroyTwo
                        endpointId:second.endpointId
                           vaultId:vault
                 expectedCheckpoint:c4
                         checkpoint:&c5] ==
        AncPrivateVaultRotationEvidenceStoreStatusOK);
  CHECK(c5.phase == AncPrivateVaultRotationEvidenceStorePhaseComplete);
  CHECK(c5.acknowledgements.count == 2 && c5.destructions.count == 2);
  CHECK([store deleteTerminalVaultId:vault expectedCheckpoint:c4] ==
        AncPrivateVaultRotationEvidenceStoreStatusConflict);
  CHECK([store deleteTerminalVaultId:vault expectedCheckpoint:c5] ==
        AncPrivateVaultRotationEvidenceStoreStatusOK);
  CHECK([store readVaultId:vault checkpoint:NULL] ==
        AncPrivateVaultRotationEvidenceStoreStatusNotFound);
  RemoveRoot(root);
  return 0;
}

static int TestCrashAndTornRecovery(void) {
  NSURL *root = TemporaryRoot();
  NSData *vault = Bytes(16, 81);
  AncPrivateVaultRotationEvidenceStoreRecipient *recipient = Recipient(82);
  AncPrivateVaultRotationEvidenceStore *store =
      [[AncPrivateVaultRotationEvidenceStore alloc] initWithStateRootURL:root];
  AncPrivateVaultRotationEvidenceStoreSetFaultHookForTesting(^BOOL(
      AncPrivateVaultRotationEvidenceStoreFaultPoint point) {
    return point ==
           AncPrivateVaultRotationEvidenceStoreFaultAfterTemporaryFsync;
  });
  CHECK(Create(store, vault, Bytes(16, 83), Bytes(16, 84), 12, Bytes(32, 85),
               @[ recipient ], NULL) ==
        AncPrivateVaultRotationEvidenceStoreStatusStorageFailed);
  AncPrivateVaultRotationEvidenceStoreSetFaultHookForTesting(nil);
  AncPrivateVaultRotationEvidenceStore *restart =
      [[AncPrivateVaultRotationEvidenceStore alloc] initWithStateRootURL:root];
  CHECK([restart readVaultId:vault checkpoint:NULL] ==
        AncPrivateVaultRotationEvidenceStoreStatusNotFound);
  AncPrivateVaultRotationEvidenceStoreCheckpoint *c1 = nil;
  CHECK(Create(restart, vault, Bytes(16, 83), Bytes(16, 84), 12,
               Bytes(32, 85), @[ recipient ], &c1) ==
        AncPrivateVaultRotationEvidenceStoreStatusOK);
  AncPrivateVaultRotationEvidenceStoreSetFaultHookForTesting(^BOOL(
      AncPrivateVaultRotationEvidenceStoreFaultPoint point) {
    return point == AncPrivateVaultRotationEvidenceStoreFaultAfterRename;
  });
  NSData *ack = Artifact(201, 90);
  CHECK([restart storeAcknowledgement:ack
                                endpointId:recipient.endpointId
                                   vaultId:vault
                         expectedCheckpoint:c1
                                 checkpoint:NULL] ==
        AncPrivateVaultRotationEvidenceStoreStatusStorageFailed);
  AncPrivateVaultRotationEvidenceStoreSetFaultHookForTesting(nil);
  AncPrivateVaultRotationEvidenceStore *afterCrash =
      [[AncPrivateVaultRotationEvidenceStore alloc] initWithStateRootURL:root];
  AncPrivateVaultRotationEvidenceStoreCheckpoint *recovered = nil;
  CHECK([afterCrash readVaultId:vault checkpoint:&recovered] ==
        AncPrivateVaultRotationEvidenceStoreStatusOK);
  CHECK(recovered.generation == 2 &&
        [recovered.acknowledgements[recipient.endpointId] isEqualToData:ack]);
  CHECK(recovered.liveRevisions.count == DefaultLiveRevisions().count);
  CHECK(recovered.liveRevisions[1].revision == 3);
  RemoveRoot(root);

  NSURL *tornRoot = TemporaryRoot();
  NSData *tornVault = Bytes(16, 101);
  AncPrivateVaultRotationEvidenceStore *tornStore =
      [[AncPrivateVaultRotationEvidenceStore alloc]
          initWithStateRootURL:tornRoot];
  CHECK(Create(tornStore, tornVault, Bytes(16, 102), Bytes(16, 103), 2,
               Bytes(32, 104), @[ Recipient(105) ], NULL) ==
        AncPrivateVaultRotationEvidenceStoreStatusOK);
  int file = open(LedgerURL(tornRoot, tornVault).fileSystemRepresentation,
                  O_WRONLY | O_TRUNC | O_NOFOLLOW);
  CHECK(file >= 0);
  uint8_t torn[7] = {1, 2, 3, 4, 5, 6, 7};
  CHECK(write(file, torn, sizeof torn) == sizeof torn);
  CHECK(fsync(file) == 0 && close(file) == 0);
  CHECK([tornStore readVaultId:tornVault checkpoint:NULL] ==
        AncPrivateVaultRotationEvidenceStoreStatusCorrupt);
  RemoveRoot(tornRoot);
  return 0;
}

static int TestSubstitutionSymlinkAndModes(void) {
  NSData *vault = Bytes(16, 111);
  AncPrivateVaultRotationEvidenceStoreRecipient *recipient = Recipient(112);

  NSURL *modeRoot = TemporaryRoot();
  AncPrivateVaultRotationEvidenceStore *modeStore =
      [[AncPrivateVaultRotationEvidenceStore alloc]
          initWithStateRootURL:modeRoot];
  CHECK(Create(modeStore, vault, Bytes(16, 113), Bytes(16, 114), 8,
               Bytes(32, 115), @[ recipient ], NULL) ==
        AncPrivateVaultRotationEvidenceStoreStatusOK);
  CHECK(chmod(LedgerURL(modeRoot, vault).fileSystemRepresentation, 0644) == 0);
  CHECK([modeStore readVaultId:vault checkpoint:NULL] ==
        AncPrivateVaultRotationEvidenceStoreStatusStorageFailed);
  RemoveRoot(modeRoot);

  NSURL *substitutionRoot = TemporaryRoot();
  AncPrivateVaultRotationEvidenceStore *substitutionStore =
      [[AncPrivateVaultRotationEvidenceStore alloc]
          initWithStateRootURL:substitutionRoot];
  CHECK(Create(substitutionStore, vault, Bytes(16, 113), Bytes(16, 114), 8,
               Bytes(32, 115), @[ recipient ], NULL) ==
        AncPrivateVaultRotationEvidenceStoreStatusOK);
  NSURL *ledger = LedgerURL(substitutionRoot, vault);
  NSData *original = [NSData dataWithContentsOfURL:ledger];
  NSMutableData *changed = [original mutableCopy];
  ((uint8_t *)changed.mutableBytes)[changed.length / 2] ^= 0x40;
  CHECK(WriteExact(ledger, changed, 0600));
  CHECK([substitutionStore readVaultId:vault checkpoint:NULL] ==
        AncPrivateVaultRotationEvidenceStoreStatusCorrupt);
  RemoveRoot(substitutionRoot);

  NSURL *symlinkRoot = TemporaryRoot();
  AncPrivateVaultRotationEvidenceStore *symlinkStore =
      [[AncPrivateVaultRotationEvidenceStore alloc]
          initWithStateRootURL:symlinkRoot];
  CHECK([symlinkStore readVaultId:vault checkpoint:NULL] ==
        AncPrivateVaultRotationEvidenceStoreStatusNotFound);
  NSURL *outside = TemporaryRoot();
  NSURL *outsideFile = [outside URLByAppendingPathComponent:@"ledger"];
  CHECK(WriteExact(outsideFile, Bytes(64, 3), 0600));
  CHECK(symlink(outsideFile.fileSystemRepresentation,
                LedgerURL(symlinkRoot, vault).fileSystemRepresentation) == 0);
  CHECK([symlinkStore readVaultId:vault checkpoint:NULL] ==
        AncPrivateVaultRotationEvidenceStoreStatusStorageFailed);
  RemoveRoot(symlinkRoot);
  RemoveRoot(outside);

  NSURL *rootMode = TemporaryRoot();
  CHECK(chmod(rootMode.fileSystemRepresentation, 0755) == 0);
  AncPrivateVaultRotationEvidenceStore *unsafeRoot =
      [[AncPrivateVaultRotationEvidenceStore alloc]
          initWithStateRootURL:rootMode];
  CHECK([unsafeRoot readVaultId:vault checkpoint:NULL] ==
        AncPrivateVaultRotationEvidenceStoreStatusStorageFailed);
  RemoveRoot(rootMode);

  NSURL *directorySwapRoot = TemporaryRoot();
  AncPrivateVaultRotationEvidenceStore *directorySwapStore =
      [[AncPrivateVaultRotationEvidenceStore alloc]
          initWithStateRootURL:directorySwapRoot];
  CHECK([directorySwapStore readVaultId:vault checkpoint:NULL] ==
        AncPrivateVaultRotationEvidenceStoreStatusNotFound);
  NSURL *directory = EvidenceDirectory(directorySwapRoot);
  NSURL *saved = [[directory URLByDeletingLastPathComponent]
      URLByAppendingPathComponent:@"rotation-evidence.saved"];
  CHECK(rename(directory.fileSystemRepresentation,
               saved.fileSystemRepresentation) == 0);
  CHECK([[NSFileManager defaultManager]
            createDirectoryAtURL:directory
      withIntermediateDirectories:NO
                       attributes:@{NSFilePosixPermissions : @0700}
                            error:nil]);
  CHECK([directorySwapStore readVaultId:vault checkpoint:NULL] ==
        AncPrivateVaultRotationEvidenceStoreStatusStorageFailed);
  RemoveRoot(directorySwapRoot);
  return 0;
}

int main(void) {
  @autoreleasepool {
    int result = 0;
    result |= TestCreateReadBindingsAndBounds();
    result |= TestMaximumLiveRevisionRosterAndRestart();
    result |= TestExactRosterPhaseIdempotencyAndCAS();
    result |= TestCrashAndTornRecovery();
    result |= TestSubstitutionSymlinkAndModes();
    AncPrivateVaultRotationEvidenceStoreSetFaultHookForTesting(nil);
    if (result == 0)
      puts("Private Vault rotation evidence store tests passed");
    return result;
  }
}
