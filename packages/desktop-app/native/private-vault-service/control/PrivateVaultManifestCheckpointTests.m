#import <Foundation/Foundation.h>

#import "PrivateVaultAncCanonical.h"
#import "PrivateVaultManifestCheckpoint.h"

#include <assert.h>

/* This target is intentionally standalone like the other native control
 * codec tests. Build wiring is owned by the service build script. The hostile
 * case pins the verifier's fail-closed behavior when a once-valid-looking
 * checkpoint/binding is replayed after the authenticated authority state no
 * longer supplies an active attended signer. */
@interface AncPrivateVaultControlLogState (ManifestCheckpointTests)
@property(nonatomic, readwrite) NSString *vaultId;
@property(nonatomic, readwrite)
    NSArray<AncPrivateVaultControlLogMember *> *activeMembers;
@end

static NSData *Repeated(uint8_t byte, NSUInteger length) {
  NSMutableData *data = [NSMutableData dataWithLength:length];
  memset(data.mutableBytes, byte, length);
  return data;
}

static NSData *CanonicalCheckpointVector(void) {
  NSDictionary *map = @{
    @1 : [AncPrivateVaultCanonicalValue text:@"anc/enrollment-manifest/v1"],
    @2 : [AncPrivateVaultCanonicalValue bytes:Repeated(1, 16)],
    @3 : [AncPrivateVaultCanonicalValue text:@"private-vault-manifest-checkpoint"],
    @4 : [AncPrivateVaultCanonicalValue integer:1721111175],
    @5 : [AncPrivateVaultCanonicalValue bytes:Repeated(0x30, 16)],
    @10 : [AncPrivateVaultCanonicalValue bytes:Repeated(0x31, 16)],
    @11 : [AncPrivateVaultCanonicalValue bytes:Repeated(0x32, 32)],
    @12 : [AncPrivateVaultCanonicalValue integer:7],
    @13 : [AncPrivateVaultCanonicalValue bytes:Repeated(0x33, 32)],
    @14 : [AncPrivateVaultCanonicalValue bytes:Repeated(2, 16)],
    @15 : [AncPrivateVaultCanonicalValue bytes:Repeated(0, 64)],
  };
  AncPrivateVaultCanonicalStatus status;
  NSData *encoded = AncPrivateVaultCanonicalEncode(
      [AncPrivateVaultCanonicalValue map:map], &status);
  assert(status == AncPrivateVaultCanonicalStatusOK && encoded != nil);
  return encoded;
}

int main(void) {
  @autoreleasepool {
    AncPrivateVaultControlLogState *revoked = [AncPrivateVaultControlLogState new];
    revoked.vaultId = @"01010101010101010101010101010101";
    revoked.activeMembers = @[];
    AncPrivateVaultManifestCheckpointStatus status;
    NSData *checkpoint = CanonicalCheckpointVector();
    /* A syntactically canonical stale bundle cannot become authority merely
     * because its bytes were retained after its authorizer was revoked. */
    assert(AncPrivateVaultVerifyManifestCheckpoint(
               Repeated(0, 1), checkpoint, Repeated(0, 1), revoked,
               Repeated(0x31, 16), Repeated(0x32, 32), 7,
               Repeated(0x33, 32), 1721111200, &status) == nil);
    assert(status == AncPrivateVaultManifestCheckpointStatusUnauthorized ||
           status == AncPrivateVaultManifestCheckpointStatusInvalid);
    puts("private-vault manifest checkpoint hostile replay passed");
  }
  return 0;
}
