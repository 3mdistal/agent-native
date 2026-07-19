#import <Foundation/Foundation.h>

#import "PrivateVaultAuthorityStore.h"
#import "PrivateVaultAncCanonical.h"
#import "PrivateVaultBootstrapFrame.h"
#import "PrivateVaultBootstrapReplay.h"
#import "PrivateVaultControlLog.h"
#import "PrivateVaultCrypto.h"
#import "PrivateVaultCustodyRepository.h"
#import "PrivateVaultEnrollmentAuthorization.h"
#import "PrivateVaultEnrollmentAuthorizer.h"
#import "PrivateVaultEnrollmentChallenge.h"
#import "PrivateVaultEnrollmentCoordinator.h"
#import "PrivateVaultEnrollmentOfferArtifactStore.h"
#import "PrivateVaultEnrollmentSasReceipt.h"
#import "PrivateVaultEnrollmentSasReceiptStore.h"
#import "PrivateVaultGuardedMemory.h"
#import "PrivateVaultGenesisAccountAdmission.h"
#import "PrivateVaultGenesisBuilder.h"
#import "PrivateVaultKeychain.h"

#include <assert.h>
#include <sys/stat.h>
#include <unistd.h>

/*
 * H4 is deliberately one executable with several process roles. The parent
 * launches a fresh child for every candidate/authorizer step. Durable custody
 * is supplied by a tiny file-backed SecItem adapter whose directory is fixed
 * before a role begins. Candidate and authorizer receive different 0700 roots
 * and different Keychain storageDomain values, just as two installed services
 * receive disjoint secure-storage namespaces. Only files in BridgeAllowlist()
 * are ever exchanged.
 */

static NSString *gKeychainRoot;

static NSString *Hex(NSData *data) {
  const uint8_t *bytes = data.bytes;
  NSMutableString *value = [NSMutableString stringWithCapacity:data.length * 2];
  for (NSUInteger index = 0; index < data.length; index += 1)
    [value appendFormat:@"%02x", bytes[index]];
  return value;
}

static NSData *Repeated(uint8_t byte, NSUInteger length) {
  NSMutableData *data = [NSMutableData dataWithLength:length];
  memset(data.mutableBytes, byte, length);
  return data;
}

static NSString *Safe(NSString *value) {
  NSData *bytes = [value dataUsingEncoding:NSUTF8StringEncoding];
  return Hex(bytes);
}

static NSString *ItemPath(NSDictionary *query) {
  NSString *service = query[(__bridge id)kSecAttrService];
  NSString *account = query[(__bridge id)kSecAttrAccount];
  if (![service isKindOfClass:NSString.class] ||
      ![account isKindOfClass:NSString.class])
    return nil;
  NSData *serviceBytes = [service dataUsingEncoding:NSUTF8StringEncoding];
  NSData *accountBytes = [account dataUsingEncoding:NSUTF8StringEncoding];
  uint8_t digest[32] = {0};
  if (anc_pv_blake2b_256_two_part(digest, serviceBytes.bytes,
                                  serviceBytes.length, accountBytes.bytes,
                                  accountBytes.length) != ANC_PV_CRYPTO_OK)
    return nil;
  NSData *key = [NSData dataWithBytes:digest length:sizeof digest];
  anc_pv_zeroize(digest, sizeof digest);
  return [gKeychainRoot stringByAppendingPathComponent:
      [NSString stringWithFormat:@"%@.item", Hex(key)]];
}

static OSStatus FileCopy(CFDictionaryRef raw, CFTypeRef *result) {
  NSString *path = ItemPath((__bridge NSDictionary *)raw);
  NSData *data = path == nil ? nil : [NSData dataWithContentsOfFile:path];
  if (data == nil)
    return errSecItemNotFound;
  if (result != NULL)
    *result = CFBridgingRetain([data copy]);
  return errSecSuccess;
}

static BOOL AtomicWrite(NSData *data, NSString *path, BOOL exclusive) {
  if (data == nil || path == nil)
    return NO;
  if (exclusive && [NSFileManager.defaultManager fileExistsAtPath:path])
    return NO;
  NSString *temporary = [path stringByAppendingFormat:@".%d.tmp", getpid()];
  if (![data writeToFile:temporary options:NSDataWritingAtomic error:nil])
    return NO;
  chmod(temporary.fileSystemRepresentation, 0600);
  if (exclusive && [NSFileManager.defaultManager fileExistsAtPath:path]) {
    [NSFileManager.defaultManager removeItemAtPath:temporary error:nil];
    return NO;
  }
  if ([NSFileManager.defaultManager fileExistsAtPath:path])
    [NSFileManager.defaultManager removeItemAtPath:path error:nil];
  return [NSFileManager.defaultManager moveItemAtPath:temporary
                                               toPath:path
                                                error:nil];
}

static OSStatus FileAdd(CFDictionaryRef raw, CFTypeRef *result) {
  (void)result;
  NSDictionary *attributes = (__bridge NSDictionary *)raw;
  NSString *path = ItemPath(attributes);
  if ([NSFileManager.defaultManager fileExistsAtPath:path])
    return errSecDuplicateItem;
  NSData *data = attributes[(__bridge id)kSecValueData];
  BOOL okay = AtomicWrite(data, path, YES);
  if (!okay)
    fprintf(stderr, "file keychain add failed path=%s length=%lu\n",
            path.UTF8String, (unsigned long)data.length);
  return okay ? errSecSuccess : errSecIO;
}

static OSStatus FileUpdate(CFDictionaryRef rawQuery,
                           CFDictionaryRef rawAttributes) {
  NSString *path = ItemPath((__bridge NSDictionary *)rawQuery);
  if (![NSFileManager.defaultManager fileExistsAtPath:path])
    return errSecItemNotFound;
  NSData *data = ((__bridge NSDictionary *)rawAttributes)[(__bridge id)kSecValueData];
  BOOL okay = AtomicWrite(data, path, NO);
  if (!okay)
    fprintf(stderr, "file keychain update failed path=%s length=%lu\n",
            path.UTF8String, (unsigned long)data.length);
  return okay ? errSecSuccess : errSecIO;
}

static OSStatus FileDelete(CFDictionaryRef raw) {
  NSString *path = ItemPath((__bridge NSDictionary *)raw);
  if (![NSFileManager.defaultManager fileExistsAtPath:path])
    return errSecItemNotFound;
  return [NSFileManager.defaultManager removeItemAtPath:path error:nil]
             ? errSecSuccess
             : errSecIO;
}

static AncPrivateVaultKeychain *Keychain(NSString *root, NSString *role) {
  gKeychainRoot = [root copy];
  struct stat info = {0};
  assert(stat(root.fileSystemRepresentation, &info) == 0 &&
         S_ISDIR(info.st_mode) && (info.st_mode & 0777) == 0700);
  AncPrivateVaultSecItemFunctions functions = {.copyMatching = FileCopy,
                                               .add = FileAdd,
                                               .update = FileUpdate,
                                               .deleteItem = FileDelete};
  return [[AncPrivateVaultKeychain alloc]
      initWithFunctions:functions
         contextFactory:^LAContext * { return [LAContext new]; }
          storageDomain:[NSString stringWithFormat:@"h4-%@-%@", role,
                                                     Safe(root)]];
}

static BOOL WriteArtifact(NSData *data, NSString *bridge, NSString *name) {
  NSString *path = [bridge stringByAppendingPathComponent:name];
  BOOL okay = data.length > 0 && [data writeToFile:path options:NSDataWritingAtomic error:nil];
  if (okay)
    chmod(path.fileSystemRepresentation, 0600);
  return okay;
}

static NSData *ReadArtifact(NSString *bridge, NSString *name) {
  return [NSData dataWithContentsOfFile:
      [bridge stringByAppendingPathComponent:name]];
}

@interface AncPrivateVaultControlLogMember (H4Harness)
@property(nonatomic, readwrite) NSString *endpointId;
@property(nonatomic, readwrite) NSString *role;
@property(nonatomic, readwrite) BOOL unattended;
@property(nonatomic, readwrite) NSData *signingPublicKey;
@property(nonatomic, readwrite) NSData *keyAgreementPublicKey;
@property(nonatomic, readwrite) NSString *enrollmentRef;
@end

@interface AncPrivateVaultControlLogState (H4Harness)
@property(nonatomic, readwrite) NSString *vaultId;
@property(nonatomic, readwrite) uint64_t sequence;
@property(nonatomic, readwrite) NSData *headHash;
@property(nonatomic, readwrite) NSData *membershipHash;
@property(nonatomic, readwrite) NSString *signedAt;
@property(nonatomic, readwrite) NSArray<AncPrivateVaultControlLogMember *> *activeMembers;
@property(nonatomic, readwrite) NSArray<NSString *> *removedEndpointIds;
@property(nonatomic, readwrite) uint64_t epoch;
@property(nonatomic, readwrite) uint64_t recoveryGeneration;
@property(nonatomic, readwrite) NSString *recoveryId;
@property(nonatomic, readwrite) NSData *recoverySigningPublicKey;
@property(nonatomic, readwrite) NSData *recoveryKeyAgreementPublicKey;
@property(nonatomic, readwrite) NSData *recoveryWrapHash;
@property(nonatomic, readwrite) NSString *freshnessMode;
@end

static const uint8_t kAuthorizerSigningSeed[32] = {
    0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
    0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
    0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
    0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11};
static const uint8_t kAuthorizerBoxSeed[32] = {
    0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
    0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
    0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
    0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22};

static AncPrivateVaultGuardedMemory *Guard(const uint8_t bytes[32]) {
  AncPrivateVaultGuardedMemoryStatus status;
  AncPrivateVaultGuardedMemory *memory =
      [AncPrivateVaultGuardedMemory memoryWithLength:32 status:&status];
  assert(status == AncPrivateVaultGuardedMemoryStatusOK && memory != nil);
  assert([memory borrow:^BOOL(uint8_t *target, size_t length) {
           assert(length == 32);
           memcpy(target, bytes, 32);
           return YES;
         }] == AncPrivateVaultGuardedMemoryStatusOK);
  return memory;
}

static NSData *DomainHash(NSString *domain, NSData *payload) {
  NSMutableData *domainBytes =
      [[domain dataUsingEncoding:NSASCIIStringEncoding] mutableCopy];
  uint8_t zero = 0, digest[32] = {0};
  [domainBytes appendBytes:&zero length:1];
  assert(anc_pv_blake2b_256_two_part(
             digest, domainBytes.bytes, domainBytes.length, payload.bytes,
             payload.length) == ANC_PV_CRYPTO_OK);
  NSData *result = [NSData dataWithBytes:digest length:sizeof digest];
  anc_pv_zeroize(digest, sizeof digest);
  return result;
}

static NSData *GenesisSignedEntry(NSData *authorization) {
  AncPrivateVaultCanonicalStatus status;
  AncPrivateVaultCanonicalValue *root =
      AncPrivateVaultCanonicalDecode(authorization, 256 * 1024, &status);
  AncPrivateVaultCanonicalValue *entry = root.mapValue[@375];
  assert(status == AncPrivateVaultCanonicalStatusOK &&
         entry.type == AncPrivateVaultCanonicalTypeBytes &&
         entry.bytesValue.length > 0);
  return entry.bytesValue;
}

static NSData *EncodeBootstrapFrame(NSData *entry, NSData *recoveryWrap,
                                    NSData *genesisEvidence, NSData *headHash,
                                    NSData *wrapHash) {
  NSDictionary *control = @{
    @"version" : @1, @"suite" : @"anc/v1",
    @"type" : @"vault-bootstrap-response",
    @"vaultId" : Hex(Repeated(0x01, 16)), @"afterSequence" : @-1,
    @"throughSequence" : @0,
    @"head" : @{ @"sequence" : @0, @"hash" : Hex(headHash) },
    @"complete" : @YES, @"entryByteLengths" : @[ @(entry.length) ],
    @"entryRecoveryWrapByteLengths" : @[ @(recoveryWrap.length) ],
    @"entryEvidenceKinds" : @[ @"genesis" ],
    @"entryEvidenceByteLengths" : @[ @(genesisEvidence.length) ],
    @"recoveryWrapHash" : Hex(wrapHash),
    @"recoveryWrapByteLength" : @(recoveryWrap.length),
  };
  NSData *json = [NSJSONSerialization dataWithJSONObject:control options:0 error:nil];
  assert(json.length > 0 && json.length <= 8 * 1024);
  uint32_t length = (uint32_t)json.length;
  uint8_t prefix[4] = {(uint8_t)(length >> 24), (uint8_t)(length >> 16),
                       (uint8_t)(length >> 8), (uint8_t)length};
  NSMutableData *encoded = [NSMutableData dataWithBytes:prefix length:4];
  [encoded appendData:json];
  [encoded appendData:entry];
  [encoded appendData:recoveryWrap];
  [encoded appendData:genesisEvidence];
  [encoded appendData:recoveryWrap];
  AncPrivateVaultBootstrapFrameStatus status;
  assert(AncPrivateVaultBootstrapFrameDecode(encoded, &status) != nil &&
         status == AncPrivateVaultBootstrapFrameStatusOK);
  return encoded;
}

static NSData *BuildBootstrapFrame(uint64_t now) {
  uint8_t entropyBytes[32], eekBytes[32];
  memset(entropyBytes, 0x55, sizeof entropyBytes);
  memset(eekBytes, 0x44, sizeof eekBytes);
  AncPrivateVaultGuardedMemory *entropy = Guard(entropyBytes);
  AncPrivateVaultGuardedMemory *signing = Guard(kAuthorizerSigningSeed);
  AncPrivateVaultGuardedMemory *agreement = Guard(kAuthorizerBoxSeed);
  AncPrivateVaultGuardedMemory *eek = Guard(eekBytes);
  AncPrivateVaultGenesisBuilderStatus builderStatus;
  AncPrivateVaultPreparedGenesisArtifacts *artifacts =
      AncPrivateVaultBuildGenesisArtifacts(
          entropy, signing, agreement, eek, Repeated(0x01, 16),
          Repeated(0x02, 16), Repeated(0x03, 16), Repeated(0x04, 16),
          Repeated(0x05, 16), Repeated(0x06, 16), Repeated(0x07, 16),
          Repeated(0x08, 24), now - 50, now - 40, now - 30, now - 20,
          now - 10, &builderStatus);
  assert(builderStatus == AncPrivateVaultGenesisBuilderStatusOK &&
         artifacts != nil);
  AncPrivateVaultGenesisAdmissionStatus admissionStatus;
  NSData *evidence = AncPrivateVaultGenesisAdmissionCandidateEncode(
      artifacts.bootstrapTranscript, artifacts.recoveryConfirmation,
      artifacts.authorization, &admissionStatus);
  NSData *entry = GenesisSignedEntry(artifacts.authorization);
  NSData *head = DomainHash(@"anc/v1/log-entry", entry);
  NSData *wrapHash = DomainHash(@"anc/v1/recovery-wrap", artifacts.recoveryWrap);
  assert(admissionStatus == AncPrivateVaultGenesisAdmissionStatusOK &&
         evidence != nil);
  NSData *frame = EncodeBootstrapFrame(entry, artifacts.recoveryWrap, evidence,
                                       head, wrapHash);
  assert([entropy close] == AncPrivateVaultGuardedMemoryStatusOK &&
         [signing close] == AncPrivateVaultGuardedMemoryStatusOK &&
         [agreement close] == AncPrivateVaultGuardedMemoryStatusOK &&
         [eek close] == AncPrivateVaultGuardedMemoryStatusOK);
  anc_pv_zeroize(entropyBytes, sizeof entropyBytes);
  anc_pv_zeroize(eekBytes, sizeof eekBytes);
  return frame;
}

static AncPrivateVaultControlLogState *PublicState(NSString *bridge,
                                                   uint64_t now) {
  NSData *encoded = ReadArtifact(bridge, @"bootstrap-frame.bin");
  AncPrivateVaultBootstrapFrameStatus frameStatus;
  AncPrivateVaultBootstrapFrame *frame =
      AncPrivateVaultBootstrapFrameDecode(encoded, &frameStatus);
  AncPrivateVaultBootstrapReplayStatus replayStatus;
  AncPrivateVaultBootstrapReplay *replay =
      [[AncPrivateVaultBootstrapReplay alloc]
          initForPublicEnrollmentWithTrustedNowMilliseconds:now * 1000
                                                   status:&replayStatus];
  assert(frameStatus == AncPrivateVaultBootstrapFrameStatusOK && frame != nil &&
         replayStatus == AncPrivateVaultBootstrapReplayStatusOK && replay != nil &&
         [replay consumeFrame:frame status:&replayStatus] && replay.isComplete &&
         replay.state != nil && replay.verifiedEEK == nil &&
         replay.currentRecoveryAuthority == nil);
  return replay.state;
}

static uint64_t CeremonyTime(NSString *bridge) {
  NSData *data = ReadArtifact(bridge, @"ceremony-time.txt");
  NSString *text = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
  return strtoull(text.UTF8String, NULL, 10);
}

static AncPrivateVaultEnrollmentCoordinator *CandidateCoordinator(
    NSString *root, NSString *authorityRoot) {
  AncPrivateVaultKeychain *keychain = Keychain(root, @"candidate");
  AncPrivateVaultCustodyRepository *repository =
      [[AncPrivateVaultCustodyRepository alloc]
          initWithKeychain:keychain recordId:AncPrivateVaultBrokerCustodyRecordId];
  AncPrivateVaultEnrollmentOfferArtifactStore *offers =
      [[AncPrivateVaultEnrollmentOfferArtifactStore alloc]
          initWithKeychain:keychain recordId:AncPrivateVaultBrokerCustodyRecordId];
  AncPrivateVaultEnrollmentSasReceiptStore *receipts =
      [[AncPrivateVaultEnrollmentSasReceiptStore alloc]
          initWithKeychain:keychain recordId:AncPrivateVaultBrokerCustodyRecordId];
  AncPrivateVaultAuthorityStore *authority = [[AncPrivateVaultAuthorityStore alloc]
      initWithStateRootURL:[NSURL fileURLWithPath:authorityRoot isDirectory:YES]
         custodyRepository:repository];
  return [[AncPrivateVaultEnrollmentCoordinator alloc]
      initWithBrokerCustodyRepository:repository
                        artifactStore:offers
                       sasReceiptStore:receipts
                        authorityStore:authority];
}

static int CandidatePrepare(NSString *root, NSString *authorityRoot,
                            NSString *bridge) {
  AncPrivateVaultEnrollmentCoordinator *coordinator =
      CandidateCoordinator(root, authorityRoot);
  AncPrivateVaultEnrollmentCandidate *candidate = nil;
  AncPrivateVaultEnrollmentCoordinatorStatus prepared =
      [coordinator prepareBrokerVaultId:Repeated(0x01, 16)
                             nowSeconds:CeremonyTime(bridge)
                              candidate:&candidate];
  if (prepared != AncPrivateVaultEnrollmentCoordinatorStatusOK)
    fprintf(stderr, "candidate prepare status=%ld root=%s\n", (long)prepared,
            root.UTF8String);
  assert(prepared == AncPrivateVaultEnrollmentCoordinatorStatusOK &&
         candidate != nil);
  assert(WriteArtifact(candidate.encodedOffer, bridge, @"offer.cbor") &&
         WriteArtifact(candidate.candidateKeyProof, bridge, @"key-proof.bin"));
  fprintf(stdout, "candidate_prepare_pid=%d\n", getpid());
  return 0;
}

static AncPrivateVaultEnrollmentChallengeResult *VerifiedChallenge(
    NSString *bridge, uint64_t now) {
  AncPrivateVaultEnrollmentChallengeStatus status;
  AncPrivateVaultEnrollmentChallengeResult *challenge =
      AncPrivateVaultEnrollmentChallengeVerify(
          ReadArtifact(bridge, @"offer.cbor"),
          ReadArtifact(bridge, @"challenge.cbor"), PublicState(bridge, now),
          now, now + 2,
          &status);
  assert(status == AncPrivateVaultEnrollmentChallengeStatusOK && challenge != nil);
  return challenge;
}

static int CandidateConfirm(NSString *root, NSString *authorityRoot,
                            NSString *bridge) {
  uint64_t now = CeremonyTime(bridge);
  AncPrivateVaultEnrollmentChallengeResult *challenge =
      VerifiedChallenge(bridge, now);
  /* The candidate independently reconstructs the public SAS transcript before
   * making the durable decision. */
  assert(challenge.sasTranscript.length > 0 && challenge.sasCode.length > 0);
  AncPrivateVaultEnrollmentCoordinator *coordinator =
      CandidateCoordinator(root, authorityRoot);
  AncPrivateVaultEnrollmentSasReceipt *receipt = nil;
  assert([coordinator recordSasDecisionForChallenge:challenge
                                          receiptId:Repeated(0x5d, 16)
                                          decidedAt:now + 3
                                           decision:AncPrivateVaultEnrollmentSasDecisionConfirmed
                                            receipt:&receipt] ==
             AncPrivateVaultEnrollmentCoordinatorStatusOK && receipt != nil);
  assert(WriteArtifact(receipt.encodedReceipt, bridge, @"sas-decision.cbor"));
  assert(WriteArtifact([challenge.sasCode dataUsingEncoding:NSUTF8StringEncoding],
                       bridge, @"sas-code.txt"));
  fprintf(stdout, "candidate_confirm_pid=%d\n", getpid());
  return 0;
}

static AncPrivateVaultEnrollmentAuthorizationResult *VerifiedAuthorization(
    NSString *bridge, uint64_t now) {
  AncPrivateVaultEnrollmentAuthorizationStatus status;
  AncPrivateVaultEnrollmentAuthorizationResult *authorization =
      AncPrivateVaultEnrollmentAuthorizationVerify(
          ReadArtifact(bridge, @"offer.cbor"),
          ReadArtifact(bridge, @"challenge.cbor"),
          ReadArtifact(bridge, @"authorization.cbor"), PublicState(bridge, now), now,
          now + 5, [AncPrivateVaultControlLog new], &status);
  return status == AncPrivateVaultEnrollmentAuthorizationStatusOK
             ? authorization
             : nil;
}

static int CandidateActivate(NSString *root, NSString *authorityRoot,
                             NSString *bridge, BOOL expectReject) {
  uint64_t now = CeremonyTime(bridge);
  AncPrivateVaultEnrollmentAuthorizationResult *authorization =
      VerifiedAuthorization(bridge, now);
  if (expectReject) {
    assert(authorization == nil);
    fprintf(stdout, "candidate_rejected_substitution_pid=%d\n", getpid());
    return 0;
  }
  assert(authorization != nil);
  AncPrivateVaultEnrollmentCoordinator *coordinator =
      CandidateCoordinator(root, authorityRoot);
  AncPrivateVaultAuthorityCheckpoint *checkpoint = nil;
  assert([coordinator activateAuthorization:authorization
                                 verifiedAtMs:(now + 5) * 1000
                                   checkpoint:&checkpoint] ==
             AncPrivateVaultEnrollmentCoordinatorStatusOK && checkpoint != nil &&
         checkpoint.snapshot.sequence == 1);
  /* Reread both public authority and secret custody from the candidate root. */
  AncPrivateVaultKeychain *keychain = Keychain(root, @"candidate-reread");
  AncPrivateVaultCustodyRepository *repository =
      [[AncPrivateVaultCustodyRepository alloc]
          initWithKeychain:keychain recordId:AncPrivateVaultBrokerCustodyRecordId];
  AncPrivateVaultCustodySnapshot snapshot = {0};
  AncPrivateVaultCustodyHandle *handle = nil;
  assert([repository readVaultId:Hex(Repeated(0x01, 16))
                         snapshot:&snapshot handle:&handle] ==
             AncPrivateVaultCustodyRepositoryStatusOK && handle != nil &&
         snapshot.lifecycle == ANC_PV_CUSTODY_LIFECYCLE_ACTIVE &&
         snapshot.custody_generation == 3 &&
         [handle close] == AncPrivateVaultCustodyRepositoryStatusOK);
  fprintf(stdout, "candidate_active_pid=%d generation=%llu sequence=%llu\n",
          getpid(), (unsigned long long)snapshot.custody_generation,
          (unsigned long long)checkpoint.snapshot.sequence);
  return 0;
}

static void AssertAuthorizerCannotReadCandidateCustody(NSString *root) {
  AncPrivateVaultKeychain *keychain = Keychain(root, @"authorizer");
  AncPrivateVaultCustodyRepository *repository =
      [[AncPrivateVaultCustodyRepository alloc]
          initWithKeychain:keychain recordId:AncPrivateVaultBrokerCustodyRecordId];
  AncPrivateVaultCustodySnapshot snapshot = {0};
  AncPrivateVaultCustodyHandle *handle = nil;
  assert([repository readVaultId:Hex(Repeated(0x01, 16))
                         snapshot:&snapshot handle:&handle] ==
             AncPrivateVaultCustodyRepositoryStatusNotFound && handle == nil);
}

static int AuthorizerChallenge(NSString *root, NSString *bridge) {
  uint64_t now = CeremonyTime(bridge);
  AssertAuthorizerCannotReadCandidateCustody(root);
  assert(WriteArtifact(BuildBootstrapFrame(now), bridge,
                       @"bootstrap-frame.bin"));
  AncPrivateVaultGuardedMemory *signing = Guard(kAuthorizerSigningSeed);
  AncPrivateVaultGuardedMemory *agreement = Guard(kAuthorizerBoxSeed);
  AncPrivateVaultEnrollmentAuthorizerStatus status;
  AncPrivateVaultPreparedEnrollmentChallenge *challenge =
      AncPrivateVaultBuildEnrollmentChallenge(
          ReadArtifact(bridge, @"offer.cbor"),
          ReadArtifact(bridge, @"key-proof.bin"), PublicState(bridge, now),
          signing, agreement,
          Repeated(0x0f, 16), Repeated(0xa7, 32), now, now + 1, now + 301,
          &status);
  assert(status == AncPrivateVaultEnrollmentAuthorizerStatusOK && challenge != nil);
  assert(WriteArtifact(challenge.encodedChallenge, bridge, @"challenge.cbor"));
  assert([signing close] == AncPrivateVaultGuardedMemoryStatusOK &&
         [agreement close] == AncPrivateVaultGuardedMemoryStatusOK);
  fprintf(stdout, "authorizer_challenge_pid=%d cross_root_lookup=not_found\n", getpid());
  return 0;
}

static int AuthorizerAuthorize(NSString *root, NSString *bridge) {
  uint64_t now = CeremonyTime(bridge);
  AssertAuthorizerCannotReadCandidateCustody(root);
  AncPrivateVaultEnrollmentChallengeResult *challenge =
      VerifiedChallenge(bridge, now);
  AncPrivateVaultEnrollmentSasReceiptStatus receiptStatus;
  AncPrivateVaultEnrollmentSasReceipt *receipt =
      AncPrivateVaultEnrollmentSasReceiptVerify(
          ReadArtifact(bridge, @"sas-decision.cbor"), challenge, &receiptStatus);
  assert(receiptStatus == AncPrivateVaultEnrollmentSasReceiptStatusOK &&
         receipt != nil &&
         receipt.decision == AncPrivateVaultEnrollmentSasDecisionConfirmed);
  AncPrivateVaultGuardedMemory *signing = Guard(kAuthorizerSigningSeed);
  AncPrivateVaultGuardedMemory *agreement = Guard(kAuthorizerBoxSeed);
  uint8_t epochBytes[32]; memset(epochBytes, 0x44, sizeof epochBytes);
  AncPrivateVaultGuardedMemory *epoch = Guard(epochBytes);
  AncPrivateVaultEnrollmentAuthorizerStatus status;
  AncPrivateVaultPreparedEnrollmentAuthorization *authorization =
      AncPrivateVaultBuildEnrollmentAuthorization(
          ReadArtifact(bridge, @"offer.cbor"), challenge, receipt,
          PublicState(bridge, now),
          signing, agreement, epoch, Repeated(0x40, 16), Repeated(0x20, 16),
          Repeated(0x21, 16), Repeated(0x91, 24), Repeated(0x30, 16), now + 4,
          now, now + 4, now + 304, &status);
  assert(status == AncPrivateVaultEnrollmentAuthorizerStatusOK &&
         authorization != nil &&
         WriteArtifact(authorization.encodedAuthorization, bridge,
                       @"authorization.cbor"));
  assert([signing close] == AncPrivateVaultGuardedMemoryStatusOK &&
         [agreement close] == AncPrivateVaultGuardedMemoryStatusOK &&
         [epoch close] == AncPrivateVaultGuardedMemoryStatusOK);
  anc_pv_zeroize(epochBytes, sizeof epochBytes);
  fprintf(stdout, "authorizer_authorize_pid=%d cross_root_lookup=not_found\n", getpid());
  return 0;
}

static NSSet<NSString *> *BridgeAllowlist(void) {
  return [NSSet setWithArray:@[@"ceremony-time.txt", @"offer.cbor",
      @"key-proof.bin", @"challenge.cbor", @"sas-decision.cbor",
      @"sas-code.txt", @"authorization.cbor", @"bootstrap-frame.bin"]];
}

static void Run(NSString *executable, NSArray<NSString *> *arguments) {
  NSTask *task = [NSTask new];
  task.executableURL = [NSURL fileURLWithPath:executable];
  task.arguments = arguments;
  NSError *error = nil;
  assert([task launchAndReturnError:&error]);
  [task waitUntilExit];
  assert(task.terminationReason == NSTaskTerminationReasonExit &&
         task.terminationStatus == 0);
}

static void MakeRoot(NSString *path) {
  assert([NSFileManager.defaultManager createDirectoryAtPath:path
                                withIntermediateDirectories:YES
                                                 attributes:@{NSFilePosixPermissions:@0700}
                                                      error:nil]);
  chmod(path.fileSystemRepresentation, 0700);
}

static int Parent(NSString *executable) {
  NSString *base = [NSTemporaryDirectory() stringByAppendingPathComponent:
      [NSString stringWithFormat:@"private-vault-h4-%@", NSUUID.UUID.UUIDString]];
  NSString *candidateRoot = [base stringByAppendingPathComponent:@"candidate-keychain"];
  NSString *candidateAuthority = [base stringByAppendingPathComponent:@"candidate-authority"];
  NSString *authorizerRoot = [base stringByAppendingPathComponent:@"authorizer-keychain"];
  NSString *bridge = [base stringByAppendingPathComponent:@"public-bridge"];
  for (NSString *path in @[base, candidateRoot, candidateAuthority, authorizerRoot, bridge])
    MakeRoot(path);
  uint64_t now = (uint64_t)NSDate.date.timeIntervalSince1970;
  assert(WriteArtifact([[NSString stringWithFormat:@"%llu", (unsigned long long)now]
                            dataUsingEncoding:NSUTF8StringEncoding],
                       bridge, @"ceremony-time.txt"));
  Run(executable, @[@"candidate-prepare", candidateRoot, candidateAuthority, bridge]);
  Run(executable, @[@"authorizer-challenge", authorizerRoot, bridge]);
  Run(executable, @[@"candidate-confirm", candidateRoot, candidateAuthority, bridge]);
  Run(executable, @[@"authorizer-authorize", authorizerRoot, bridge]);

  NSData *authorization = ReadArtifact(bridge, @"authorization.cbor");
  NSMutableData *substitution = [authorization mutableCopy];
  ((uint8_t *)substitution.mutableBytes)[substitution.length - 1] ^= 1;
  assert(WriteArtifact(substitution, bridge, @"authorization.cbor"));
  Run(executable, @[@"candidate-reject-substitution", candidateRoot,
                    candidateAuthority, bridge]);
  assert(WriteArtifact(authorization, bridge, @"authorization.cbor"));
  Run(executable, @[@"candidate-activate", candidateRoot, candidateAuthority, bridge]);

  NSArray<NSString *> *bridged =
      [NSFileManager.defaultManager contentsOfDirectoryAtPath:bridge error:nil];
  assert(bridged.count == BridgeAllowlist().count);
  for (NSString *name in bridged)
    assert([BridgeAllowlist() containsObject:name]);
  assert(![candidateRoot isEqualToString:authorizerRoot]);
  assert([NSFileManager.defaultManager removeItemAtPath:base error:nil]);
  puts("private-vault H4 genuine two-process isolated-root enrollment passed");
  return 0;
}

int main(int argc, const char *argv[]) {
  @autoreleasepool {
    assert(anc_pv_crypto_init() == ANC_PV_CRYPTO_OK);
    if (argc == 1)
      return Parent(NSProcessInfo.processInfo.arguments.firstObject);
    assert(argc == 5 || argc == 4);
    NSString *mode = @(argv[1]);
    if ([mode isEqualToString:@"candidate-prepare"])
      return CandidatePrepare(@(argv[2]), @(argv[3]), @(argv[4]));
    if ([mode isEqualToString:@"candidate-confirm"])
      return CandidateConfirm(@(argv[2]), @(argv[3]), @(argv[4]));
    if ([mode isEqualToString:@"candidate-activate"])
      return CandidateActivate(@(argv[2]), @(argv[3]), @(argv[4]), NO);
    if ([mode isEqualToString:@"candidate-reject-substitution"])
      return CandidateActivate(@(argv[2]), @(argv[3]), @(argv[4]), YES);
    if ([mode isEqualToString:@"authorizer-challenge"])
      return AuthorizerChallenge(@(argv[2]), @(argv[3]));
    if ([mode isEqualToString:@"authorizer-authorize"])
      return AuthorizerAuthorize(@(argv[2]), @(argv[3]));
    abort();
  }
}
