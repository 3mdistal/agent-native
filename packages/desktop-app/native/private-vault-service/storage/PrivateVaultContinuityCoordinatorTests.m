#import <Foundation/Foundation.h>

#import "PrivateVaultAncCanonical.h"
#import "PrivateVaultAuthoritySnapshotInternal.h"
#import "PrivateVaultAuthorityStore.h"
#import "PrivateVaultContinuityCoordinator.h"
#import "PrivateVaultControlLog.h"
#import "PrivateVaultControlLogInternal.h"
#import "PrivateVaultCrypto.h"
#import "PrivateVaultEndpointRequest.h"
#import "PrivateVaultKeychain.h"

#include <assert.h>

static NSMutableDictionary<NSString *, NSData *> *gKeychain;

static NSData *Bytes(uint8_t value, NSUInteger length) {
  NSMutableData *data = [NSMutableData dataWithLength:length];
  memset(data.mutableBytes, value, length);
  return data;
}

static NSString *Key(NSDictionary *query) {
  return [NSString stringWithFormat:@"%@|%@", query[(__bridge id)kSecAttrService],
                                    query[(__bridge id)kSecAttrAccount]];
}

static OSStatus Copy(CFDictionaryRef raw, CFTypeRef *result) {
  NSData *value = gKeychain[Key((__bridge NSDictionary *)raw)];
  if (value == nil) return errSecItemNotFound;
  if (result != NULL) *result = CFBridgingRetain([value copy]);
  return errSecSuccess;
}

static OSStatus Add(CFDictionaryRef raw, CFTypeRef *result) {
  (void)result;
  NSDictionary *attributes = (__bridge NSDictionary *)raw;
  NSString *key = Key(attributes);
  if (gKeychain[key] != nil) return errSecDuplicateItem;
  NSData *value = attributes[(__bridge id)kSecValueData];
  gKeychain[key] = [value copy];
  return errSecSuccess;
}

static OSStatus Update(CFDictionaryRef rawQuery, CFDictionaryRef rawAttributes) {
  NSString *key = Key((__bridge NSDictionary *)rawQuery);
  if (gKeychain[key] == nil) return errSecItemNotFound;
  gKeychain[key] = [((__bridge NSDictionary *)rawAttributes)
      [(__bridge id)kSecValueData] copy];
  return errSecSuccess;
}

static OSStatus Delete(CFDictionaryRef raw) {
  NSString *key = Key((__bridge NSDictionary *)raw);
  if (gKeychain[key] == nil) return errSecItemNotFound;
  [gKeychain removeObjectForKey:key];
  return errSecSuccess;
}

static AncPrivateVaultKeychain *TestKeychain(void) {
  AncPrivateVaultSecItemFunctions functions = {
      .copyMatching = Copy, .add = Add, .update = Update, .deleteItem = Delete};
  return [[AncPrivateVaultKeychain alloc]
      initWithFunctions:functions
          contextFactory:^LAContext * { return [LAContext new]; }
           storageDomain:@"continuity-coordinator-tests"];
}

@interface AncPrivateVaultAuthorityCheckpoint (ContinuityTests)
@property(nonatomic, readwrite) NSString *vaultId;
@property(nonatomic, readwrite) uint64_t custodyGeneration;
@property(nonatomic, readwrite) NSData *frameDigest;
@property(nonatomic, readwrite) AncPrivateVaultAuthoritySnapshot *snapshot;
@end

@interface AncPrivateVaultControlLogMember (ContinuityTests)
@property(nonatomic, readwrite) NSString *endpointId;
@property(nonatomic, readwrite) NSString *role;
@property(nonatomic, readwrite) BOOL unattended;
@property(nonatomic, readwrite) NSData *signingPublicKey;
@property(nonatomic, readwrite) NSData *keyAgreementPublicKey;
@property(nonatomic, readwrite) NSString *enrollmentRef;
@end

@interface AncPrivateVaultControlLogState (ContinuityTests)
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

@interface TestAuthorityStore : AncPrivateVaultAuthorityStore
@property(nonatomic) AncPrivateVaultAuthorityCheckpoint *checkpoint;
@property(nonatomic) NSUInteger commits;
- (instancetype)initForTesting;
@end

@implementation TestAuthorityStore
- (instancetype)initForTesting {
  return self;
}
- (AncPrivateVaultAuthorityStoreStatus)loadVaultId:(NSString *)vaultId
                                         checkpoint:(AncPrivateVaultAuthorityCheckpoint **)checkpoint
                                              error:(NSError **)error {
  (void)error;
  if (![vaultId isEqualToString:self.checkpoint.vaultId])
    return AncPrivateVaultAuthorityStoreStatusNotFound;
  if (checkpoint != NULL) *checkpoint = self.checkpoint;
  return AncPrivateVaultAuthorityStoreStatusOK;
}
- (AncPrivateVaultAuthorityStoreStatus)
    commitVerifiedReplayResult:(AncPrivateVaultVerifiedReplayResult *)result
                       vaultId:(NSString *)vaultId
                  verifiedAtMs:(uint64_t)verifiedAtMs
                    checkpoint:(AncPrivateVaultAuthorityCheckpoint **)checkpoint
                         error:(NSError **)error {
  (void)verifiedAtMs;
  (void)error;
  if (![vaultId isEqualToString:self.checkpoint.vaultId] || result == nil)
    return AncPrivateVaultAuthorityStoreStatusConflict;
  AncPrivateVaultAuthorityCheckpoint *committed =
      [AncPrivateVaultAuthorityCheckpoint new];
  committed.vaultId = vaultId;
  committed.custodyGeneration = result.nextSnapshot.targetCustodyGeneration;
  committed.frameDigest = Bytes(0x9a, 32);
  committed.snapshot = result.nextSnapshot;
  self.checkpoint = committed;
  self.commits += 1;
  if (checkpoint != NULL) *checkpoint = committed;
  return AncPrivateVaultAuthorityStoreStatusOK;
}
@end

static AncPrivateVaultCanonicalValue *T(NSString *value) {
  return [AncPrivateVaultCanonicalValue text:value];
}
static AncPrivateVaultCanonicalValue *I(int64_t value) {
  return [AncPrivateVaultCanonicalValue integer:value];
}
static AncPrivateVaultCanonicalValue *B(NSData *value) {
  return [AncPrivateVaultCanonicalValue bytes:value];
}

static AncPrivateVaultControlLogState *BaseState(NSString *vaultId,
                                                 NSString *endpointId,
                                                 NSData *publicKey) {
  AncPrivateVaultControlLogMember *member = [AncPrivateVaultControlLogMember new];
  member.endpointId = endpointId;
  member.role = @"endpoint";
  member.unattended = NO;
  member.signingPublicKey = publicKey;
  member.keyAgreementPublicKey = Bytes(0x42, 32);
  member.enrollmentRef = @"enrollment:continuity-tests";
  AncPrivateVaultControlLogState *state = [AncPrivateVaultControlLogState new];
  state.vaultId = vaultId;
  state.sequence = 19;
  state.headHash = Bytes(0x55, 32);
  state.membershipHash = Bytes(0x66, 32);
  state.signedAt = @"2026-07-19T09:00:00.000Z";
  state.activeMembers = @[ member ];
  state.removedEndpointIds = @[];
  state.epoch = 4;
  state.recoveryGeneration = 2;
  state.recoveryId = @"recovery:continuity-tests";
  state.recoverySigningPublicKey = Bytes(0x51, 32);
  state.recoveryKeyAgreementPublicKey = Bytes(0x52, 32);
  state.recoveryWrapHash = Bytes(0x53, 32);
  state.freshnessMode = @"endpoint_witnessed";
  return state;
}

static TestAuthorityStore *Authority(AncPrivateVaultControlLogState *state) {
  AncPrivateVaultAuthoritySnapshot *snapshot =
      AncPrivateVaultAuthoritySnapshotCreateFromVerifiedControlState(
          state, 2, 1, @18, Bytes(0x54, 32), 1784451601000ULL);
  assert(snapshot != nil);
  TestAuthorityStore *store = [[TestAuthorityStore alloc] initForTesting];
  store.checkpoint = [AncPrivateVaultAuthorityCheckpoint new];
  store.checkpoint.vaultId = state.vaultId;
  store.checkpoint.custodyGeneration = 2;
  store.checkpoint.frameDigest = Bytes(0x71, 32);
  store.checkpoint.snapshot = snapshot;
  return store;
}

static NSData *Receipt(NSString *vaultId, NSString *entryId, uint64_t sequence,
                       NSData *headHash) {
  AncPrivateVaultCanonicalStatus status;
  NSData *encoded = AncPrivateVaultCanonicalEncode([AncPrivateVaultCanonicalValue map:@{
    @1:T(@"anc/v1"), @2:I(1), @3:T(@"control-log-continuity-append-receipt"),
    @4:T(vaultId), @5:T(entryId), @6:I((int64_t)sequence), @7:B(headHash)}], &status);
  assert(encoded != nil && status == AncPrivateVaultCanonicalStatusOK &&
         AncPrivateVaultControlLogContinuityAppendReceiptDecode(encoded) != nil);
  return encoded;
}

static AncPrivateVaultContinuityCoordinator *Coordinator(TestAuthorityStore *authority,
                                                          AncPrivateVaultKeychain *keychain) {
  return [[AncPrivateVaultContinuityCoordinator alloc]
      initWithAuthorityStore:authority keychain:keychain controlLog:[AncPrivateVaultControlLog new]];
}

static AncPrivateVaultPreparedContinuity *Prepare(AncPrivateVaultContinuityCoordinator *coordinator,
                                                   NSString *vaultId, const uint8_t seed[32],
                                                   NSData *publicKey, NSString *nonce) {
  AncPrivateVaultPreparedContinuity *prepared = nil;
  AncPrivateVaultContinuityCoordinatorStatus status =
      [coordinator prepareVaultId:vaultId
                     logEnvelopeId:@"log-entry:continuity-tests"
                    entryCreatedAt:@"2026-07-19T09:10:00.000Z"
                     proofIssuedAt:@"2026-07-19T09:10:01.000Z"
                              nonce:nonce endpointId:@"endpoint:continuity-tests"
                        signingSeed:seed expectedSigningPublicKey:publicKey result:&prepared];
  assert(status == AncPrivateVaultContinuityCoordinatorStatusOK);
  assert(prepared != nil);
  return prepared;
}

int main(void) {
  @autoreleasepool {
    assert(anc_pv_crypto_init() == ANC_PV_CRYPTO_OK);
    uint8_t seed[32]; memset(seed, 0x31, sizeof seed);
    uint8_t publicBytes[32] = {0}, privateKey[64] = {0};
    assert(anc_pv_ed25519_seed_keypair(publicBytes, privateKey, seed) == ANC_PV_CRYPTO_OK);
    NSData *publicKey = [NSData dataWithBytes:publicBytes length:sizeof publicBytes];
    NSString *vaultId = @"vault:continuity-tests";
    AncPrivateVaultControlLogState *state =
        BaseState(vaultId, @"endpoint:continuity-tests", publicKey);
    anc_pv_zeroize(privateKey, sizeof privateKey);
    anc_pv_zeroize(publicBytes, sizeof publicBytes);

    // Crash before network: the exact signed edge is already durable.
    gKeychain = [NSMutableDictionary dictionary];
    AncPrivateVaultKeychain *keychain = TestKeychain();
    TestAuthorityStore *authority = Authority(state);
    AncPrivateVaultContinuityCoordinator *coordinator = Coordinator(authority, keychain);
    AncPrivateVaultPreparedContinuity *first = Prepare(
        coordinator, vaultId, seed, publicKey, @"11111111111111111111111111111111");
    NSData *pending = nil;
    assert([keychain copyDataForService:AncPrivateVaultContinuityPendingService vaultId:vaultId
                               recordId:@"continuity-pending-v1" data:&pending] == AncPrivateVaultKeychainStatusOK &&
           [pending isEqualToData:first.signedEntry]);

    // Retry reuses that edge while deriving a fresh request proof from its nonce.
    AncPrivateVaultPreparedContinuity *retry = Prepare(
        coordinator, vaultId, seed, publicKey, @"22222222222222222222222222222222");
    assert([retry.signedEntry isEqualToData:first.signedEntry] &&
           [retry.requestBody isEqualToData:first.requestBody] &&
           ![retry.proofHeader isEqualToString:first.proofHeader]);

    // Simulated response loss: a later verified local commit clears the durable edge.
    assert([coordinator finalizeVaultId:vaultId
                                receipt:Receipt(vaultId, retry.entryId,
                                                retry.sequence, retry.headHash)
                           verifiedAtMs:1784452201000ULL] ==
           AncPrivateVaultContinuityCoordinatorStatusOK);
    NSData *cleared = nil;
    assert(authority.commits == 1 &&
           [keychain copyDataForService:AncPrivateVaultContinuityPendingService vaultId:vaultId
                                recordId:@"continuity-pending-v1" data:&cleared] == AncPrivateVaultKeychainStatusNotFound &&
           cleared == nil);

    // A receipt for another edge must not erase the locally durable edge.
    gKeychain = [NSMutableDictionary dictionary];
    keychain = TestKeychain(); authority = Authority(state); coordinator = Coordinator(authority, keychain);
    first = Prepare(coordinator, vaultId, seed, publicKey, @"33333333333333333333333333333333");
    assert([coordinator finalizeVaultId:vaultId
                                receipt:Receipt(vaultId, @"log-entry:wrong-receipt", first.sequence, first.headHash)
                           verifiedAtMs:1784452201000ULL] == AncPrivateVaultContinuityCoordinatorStatusReceiptRejected);
    pending = nil;
    assert([keychain copyDataForService:AncPrivateVaultContinuityPendingService vaultId:vaultId
                               recordId:@"continuity-pending-v1" data:&pending] == AncPrivateVaultKeychainStatusOK &&
           [pending isEqualToData:first.signedEntry]);

    // Corrupt and oversized pending records fail closed rather than generating a replacement.
    gKeychain = [NSMutableDictionary dictionary]; keychain = TestKeychain(); authority = Authority(state);
    coordinator = Coordinator(authority, keychain);
    assert([keychain addData:[NSData dataWithBytes:"bad" length:3]
                  forService:AncPrivateVaultContinuityPendingService vaultId:vaultId
                   recordId:@"continuity-pending-v1"] == AncPrivateVaultKeychainStatusOK);
    AncPrivateVaultPreparedContinuity *rejected = nil;
    assert([coordinator prepareVaultId:vaultId logEnvelopeId:@"log-entry:continuity-tests"
                         entryCreatedAt:@"2026-07-19T09:10:00.000Z"
                          proofIssuedAt:@"2026-07-19T09:10:01.000Z" nonce:@"44444444444444444444444444444444"
                            endpointId:@"endpoint:continuity-tests" signingSeed:seed
             expectedSigningPublicKey:publicKey result:&rejected] ==
           AncPrivateVaultContinuityCoordinatorStatusConflict && rejected == nil);
    gKeychain = [NSMutableDictionary dictionary]; keychain = TestKeychain(); coordinator = Coordinator(Authority(state), keychain);
    assert([keychain addData:Bytes(0x55, 1) forService:AncPrivateVaultContinuityPendingService
                     vaultId:vaultId recordId:@"continuity-pending-v1"] == AncPrivateVaultKeychainStatusOK);
    gKeychain[gKeychain.allKeys.firstObject] = Bytes(0x55, 2049);
    assert([coordinator prepareVaultId:vaultId logEnvelopeId:@"log-entry:continuity-tests"
                         entryCreatedAt:@"2026-07-19T09:10:00.000Z"
                          proofIssuedAt:@"2026-07-19T09:10:01.000Z" nonce:@"55555555555555555555555555555555"
                            endpointId:@"endpoint:continuity-tests" signingSeed:seed
             expectedSigningPublicKey:publicKey result:&rejected] ==
           AncPrivateVaultContinuityCoordinatorStatusStorageFailed);
    anc_pv_zeroize(seed, sizeof seed);
    puts("private-vault continuity coordinator tests passed");
  }
  return 0;
}
