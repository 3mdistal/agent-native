#import "PrivateVaultManifestCheckpoint.h"

#import "PrivateVaultAncCanonical.h"
#import "PrivateVaultCrypto.h"
#import "PrivateVaultEnrollmentAuthorizationInternal.h"

static const uint8_t kCheckpointDomain[] =
    "anc/enrollment-manifest/v1/private-vault-manifest-checkpoint\0";
static const uint8_t kBindingDomain[] =
    "anc/enrollment-manifest/v1/enrollment-manifest-authorization\0";
static const uint8_t kEnrollmentDomain[] = "anc/v1/enrollment-authorization";
static const uint64_t kMaxSafe = UINT64_C(9007199254740991);

@interface AncPrivateVaultManifestCheckpointBundle ()
- (instancetype)initWithCheckpoint:(NSData *)checkpoint binding:(NSData *)binding
                            digest:(NSData *)digest;
@end
@implementation AncPrivateVaultManifestCheckpointBundle
@synthesize encodedCheckpoint = _encodedCheckpoint;
@synthesize encodedAuthorization = _encodedAuthorization;
@synthesize checkpointDigest = _checkpointDigest;
- (instancetype)initWithCheckpoint:(NSData *)checkpoint binding:(NSData *)binding
                            digest:(NSData *)digest {
  if ((self = [super init])) { _encodedCheckpoint = [checkpoint copy]; _encodedAuthorization = [binding copy]; _checkpointDigest = [digest copy]; }
  return self;
}
@end

static void Set(AncPrivateVaultManifestCheckpointStatus *s, AncPrivateVaultManifestCheckpointStatus v) { if (s) *s = v; }
static BOOL Exact(NSData *v, NSUInteger n) { return [v isKindOfClass:NSData.class] && v.length == n; }
static BOOL Same(NSData *a, NSData *b) { return Exact(a, b.length) && b.length > 0 && anc_pv_memcmp(a.bytes,b.bytes,b.length) == ANC_PV_CRYPTO_OK; }
static AncPrivateVaultCanonicalValue *BV(NSData *v) { return [AncPrivateVaultCanonicalValue bytes:v]; }
static AncPrivateVaultCanonicalValue *TV(NSString *v) { return [AncPrivateVaultCanonicalValue text:v]; }
static AncPrivateVaultCanonicalValue *IV(uint64_t v) { return v && v <= INT64_MAX ? [AncPrivateVaultCanonicalValue integer:(int64_t)v] : nil; }
static NSData *Encode(NSDictionary *m) { AncPrivateVaultCanonicalStatus s; NSData *r=AncPrivateVaultCanonicalEncode([AncPrivateVaultCanonicalValue map:m],&s); return s==AncPrivateVaultCanonicalStatusOK?r:nil; }
static NSData *HexData(NSString *v) { if (![v isKindOfClass:NSString.class] || v.length != 32) return nil; NSMutableData *r=[NSMutableData dataWithLength:16]; for(NSUInteger i=0;i<16;i++){ unichar a=[v characterAtIndex:i*2],b=[v characterAtIndex:i*2+1]; int x=a>='0'&&a<='9'?a-'0':a>='a'&&a<='f'?a-'a'+10:-1, y=b>='0'&&b<='9'?b-'0':b>='a'&&b<='f'?b-'a'+10:-1; if(x<0||y<0)return nil; ((uint8_t*)r.mutableBytes)[i]=(uint8_t)((x<<4)|y); } return r; }
static NSString *Hex(NSData *v) { if (!Exact(v,16)) return nil; NSMutableString *r=[NSMutableString stringWithCapacity:32]; for(NSUInteger i=0;i<16;i++) [r appendFormat:@"%02x",((const uint8_t*)v.bytes)[i]]; return r; }
static NSData *Hash(const uint8_t *d,size_t n,NSData *p) { uint8_t out[32]={0}; BOOL ok=p&&anc_pv_blake2b_256_two_part(out,d,n,p.bytes,p.length)==ANC_PV_CRYPTO_OK; NSData *r=ok?[NSData dataWithBytes:out length:32]:nil; anc_pv_zeroize(out,sizeof out); return r; }
static NSData *Sign(const uint8_t *d,size_t n,NSData *p,const uint8_t seed[32],NSData **pub) { uint8_t pk[32]={0},sk[64]={0},sig[64]={0}; NSMutableData *m=p?[NSMutableData dataWithBytes:d length:n]:nil; [m appendData:p]; BOOL ok=m&&anc_pv_ed25519_seed_keypair(pk,sk,seed)==ANC_PV_CRYPTO_OK&&anc_pv_ed25519_sign(sig,m.bytes,m.length,sk)==ANC_PV_CRYPTO_OK; NSData *r=ok?[NSData dataWithBytes:sig length:64]:nil; if(pub)*pub=ok?[NSData dataWithBytes:pk length:32]:nil; anc_pv_zeroize(m.mutableBytes,m.length);anc_pv_zeroize(pk,sizeof pk);anc_pv_zeroize(sk,sizeof sk);anc_pv_zeroize(sig,sizeof sig);return r; }
static BOOL Verify(NSDictionary *m,NSNumber *key,const uint8_t*d,size_t n,NSData *pk) { AncPrivateVaultCanonicalValue *sig=m[key]; if(sig.type!=AncPrivateVaultCanonicalTypeBytes||!Exact(sig.bytesValue,64)||!Exact(pk,32))return NO; NSMutableDictionary *u=[m mutableCopy];[u removeObjectForKey:key];NSData *raw=Encode(u);NSMutableData *msg=raw?[NSMutableData dataWithBytes:d length:n]:nil;[msg appendData:raw];BOOL ok=msg&&anc_pv_ed25519_verify(sig.bytesValue.bytes,msg.bytes,msg.length,pk.bytes)==ANC_PV_CRYPTO_OK;anc_pv_zeroize(msg.mutableBytes,msg.length);return ok; }
static NSDictionary *Map(NSData *v,NSUInteger max) { AncPrivateVaultCanonicalStatus s; AncPrivateVaultCanonicalValue *r=AncPrivateVaultCanonicalDecode(v,max,&s);return s==AncPrivateVaultCanonicalStatusOK&&r.type==AncPrivateVaultCanonicalTypeMap?r.mapValue:nil; }
static AncPrivateVaultCanonicalValue *F(NSDictionary*m,NSNumber*k,AncPrivateVaultCanonicalType t){AncPrivateVaultCanonicalValue*v=m[k];return v.type==t?v:nil;}
static BOOL Keys(NSDictionary*m,NSArray*k){return m.count==k.count&&[[NSSet setWithArray:m.allKeys]isEqualToSet:[NSSet setWithArray:k]];}
static AncPrivateVaultControlLogMember *Active(AncPrivateVaultControlLogState *s,NSData *id){NSString *h=Hex(id);for(AncPrivateVaultControlLogMember*m in s.activeMembers)if([m.endpointId isEqual:h]&&[m.role isEqual:@"endpoint"]&&!m.unattended&&Exact(m.signingPublicKey,32))return m;return nil;}

static BOOL EnrollmentAuthority(NSData *encoded, AncPrivateVaultControlLogState *state, uint64_t now, NSData **idOut, NSData **keyOut, uint64_t *createdOut, uint64_t *expiresOut) {
  NSDictionary *m=Map(encoded,1024); NSArray *keys=@[@1,@2,@3,@4,@5,@300,@301,@302,@303,@304,@305,@306,@307,@308,@309,@310,@311];
  NSData *vault=HexData(state.vaultId); AncPrivateVaultCanonicalValue *suite=F(m,@1,AncPrivateVaultCanonicalTypeText),*type=F(m,@3,AncPrivateVaultCanonicalTypeText),*created=F(m,@4,AncPrivateVaultCanonicalTypeInteger),*authorizer=F(m,@302,AncPrivateVaultCanonicalTypeBytes),*expires=F(m,@310,AncPrivateVaultCanonicalTypeInteger);
  if(!Keys(m,keys)||!vault||![suite.textValue isEqual:@"anc/v1"]||![type.textValue isEqual:@"enrollment-authorization"]||!Exact(F(m,@2,AncPrivateVaultCanonicalTypeBytes).bytesValue,16)||!Same(F(m,@2,AncPrivateVaultCanonicalTypeBytes).bytesValue,vault)||!Exact(authorizer.bytesValue,16)||created.integerValue<1||expires.integerValue<created.integerValue||expires.integerValue-created.integerValue>600||(uint64_t)expires.integerValue<now)return NO;
  AncPrivateVaultControlLogMember *member=Active(state,authorizer.bytesValue); if(!member||!Verify(m,@311,kEnrollmentDomain,sizeof kEnrollmentDomain,member.signingPublicKey))return NO;
  if(idOut)*idOut=[authorizer.bytesValue copy];if(keyOut)*keyOut=[member.signingPublicKey copy];if(createdOut)*createdOut=(uint64_t)created.integerValue;if(expiresOut)*expiresOut=(uint64_t)expires.integerValue;return YES;
}

AncPrivateVaultManifestCheckpointBundle *AncPrivateVaultBuildManifestCheckpoint(AncPrivateVaultEnrollmentAuthorizationResult *enrollment, AncPrivateVaultControlLogState *state, NSData *object, NSData *revision, uint64_t generation, NSData *ciphertext, NSData *checkpointId, NSData *bindingId, uint64_t checkpointAt, uint64_t bindingAt, uint64_t bindingExpires, const uint8_t seed[32], AncPrivateVaultManifestCheckpointStatus *status) {
  Set(status,AncPrivateVaultManifestCheckpointStatusInvalid);
  NSData *vault=nil,*digest=nil,*envelope=nil,*ceremony=nil,*candidate=nil,*offer=nil,*challenge=nil,*sas=nil,*prior=nil,*signedCommit=nil;NSString *role=nil;BOOL unattended=NO;NSData *candidateSign=nil,*candidateAgree=nil;uint64_t cc=0,ce=0;AncPrivateVaultControlLogReplayResult *replay=nil;
  if(!enrollment||!state||!Exact(object,16)||!Exact(revision,32)||!generation||!Exact(ciphertext,32)||!Exact(checkpointId,16)||!Exact(bindingId,16)||!seed||checkpointAt>kMaxSafe||bindingAt>kMaxSafe||bindingExpires>kMaxSafe||bindingExpires<bindingAt||!AncPrivateVaultEnrollmentAuthorizationCopyEvidence(enrollment,&vault,&digest,&envelope,&ceremony,&candidate,&role,&unattended,&candidateSign,&candidateAgree,&offer,&challenge,&sas,&cc,&ce,&prior,&signedCommit,&replay)||!Exact(vault,16)||!Exact(digest,32)||!Same(vault,HexData(state.vaultId))||!EnrollmentAuthority(enrollment.encodedAuthorization,state,bindingAt,NULL,NULL,NULL,NULL)) return nil;
  NSData *authorizer=nil,*public=nil;uint64_t authCreated=0,authExpires=0; if(!EnrollmentAuthority(enrollment.encodedAuthorization,state,bindingAt,&authorizer,&public,&authCreated,&authExpires)||bindingAt<authCreated||bindingExpires>authExpires||checkpointAt<authCreated||checkpointAt>bindingAt){Set(status,AncPrivateVaultManifestCheckpointStatusUnauthorized);return nil;}
  NSData *derived=nil; Sign(kCheckpointDomain,sizeof kCheckpointDomain,[NSData data],seed,&derived); if(!Same(derived,public)){Set(status,AncPrivateVaultManifestCheckpointStatusUnauthorized);return nil;}
  NSMutableDictionary *c=[@{@1:TV(@"anc/enrollment-manifest/v1"),@2:BV(vault),@3:TV(@"private-vault-manifest-checkpoint"),@4:IV(checkpointAt),@5:BV(checkpointId),@10:BV(object),@11:BV(revision),@12:IV(generation),@13:BV(ciphertext),@14:BV(authorizer)} mutableCopy]; NSData *unsignedCheckpoint=Encode(c); c[@15]=BV(Sign(kCheckpointDomain,sizeof kCheckpointDomain,unsignedCheckpoint,seed,NULL)); NSData *encodedCheckpoint=Encode(c); NSData *checkpointHash=Hash(kCheckpointDomain,sizeof kCheckpointDomain,encodedCheckpoint);
  NSMutableDictionary *b=[@{@1:TV(@"anc/enrollment-manifest/v1"),@2:BV(vault),@3:TV(@"enrollment-manifest-authorization"),@4:IV(bindingAt),@5:BV(bindingId),@20:BV(digest),@21:BV(checkpointHash),@22:BV(authorizer),@23:IV(bindingExpires)} mutableCopy]; NSData *unsignedBinding=Encode(b); b[@24]=BV(Sign(kBindingDomain,sizeof kBindingDomain,unsignedBinding,seed,NULL));NSData *encodedBinding=Encode(b);
  AncPrivateVaultManifestCheckpointBundle *result=AncPrivateVaultVerifyManifestCheckpoint(enrollment.encodedAuthorization,encodedCheckpoint,encodedBinding,state,object,revision,generation,ciphertext,bindingAt,status);return result;
}

AncPrivateVaultManifestCheckpointBundle *AncPrivateVaultVerifyManifestCheckpoint(NSData *authorization,NSData *checkpoint,NSData *binding,AncPrivateVaultControlLogState *state,NSData *object,NSData *revision,uint64_t generation,NSData *ciphertext,uint64_t now,AncPrivateVaultManifestCheckpointStatus *status) {
  Set(status,AncPrivateVaultManifestCheckpointStatusInvalid); if(!state||!Exact(object,16)||!Exact(revision,32)||!generation||!Exact(ciphertext,32)||!now||now>kMaxSafe)return nil;
  NSData *authorizer=nil,*public=nil;uint64_t authCreated=0,authExpires=0; if(!EnrollmentAuthority(authorization,state,now,&authorizer,&public,&authCreated,&authExpires)){Set(status,AncPrivateVaultManifestCheckpointStatusUnauthorized);return nil;}
  NSDictionary *c=Map(checkpoint,1024),*b=Map(binding,1024);NSArray *ck=@[@1,@2,@3,@4,@5,@10,@11,@12,@13,@14,@15],*bk=@[@1,@2,@3,@4,@5,@20,@21,@22,@23,@24];NSData *vault=HexData(state.vaultId); if(!Keys(c,ck)||!Keys(b,bk)||!vault||![F(c,@1,AncPrivateVaultCanonicalTypeText).textValue isEqual:@"anc/enrollment-manifest/v1"]||![F(c,@3,AncPrivateVaultCanonicalTypeText).textValue isEqual:@"private-vault-manifest-checkpoint"]||![F(b,@3,AncPrivateVaultCanonicalTypeText).textValue isEqual:@"enrollment-manifest-authorization"]||!Same(F(c,@2,AncPrivateVaultCanonicalTypeBytes).bytesValue,vault)||!Same(F(b,@2,AncPrivateVaultCanonicalTypeBytes).bytesValue,vault)||!Same(F(c,@10,AncPrivateVaultCanonicalTypeBytes).bytesValue,object)||!Same(F(c,@11,AncPrivateVaultCanonicalTypeBytes).bytesValue,revision)||F(c,@12,AncPrivateVaultCanonicalTypeInteger).integerValue!=(int64_t)generation||!Same(F(c,@13,AncPrivateVaultCanonicalTypeBytes).bytesValue,ciphertext)||!Same(F(c,@14,AncPrivateVaultCanonicalTypeBytes).bytesValue,authorizer)||!Verify(c,@15,kCheckpointDomain,sizeof kCheckpointDomain,public)||!Verify(b,@24,kBindingDomain,sizeof kBindingDomain,public)){Set(status,AncPrivateVaultManifestCheckpointStatusSignature);return nil;}
  NSData *authHash=Hash(kEnrollmentDomain,sizeof kEnrollmentDomain,authorization),*checkpointHash=Hash(kCheckpointDomain,sizeof kCheckpointDomain,checkpoint);int64_t cc=F(c,@4,AncPrivateVaultCanonicalTypeInteger).integerValue,bc=F(b,@4,AncPrivateVaultCanonicalTypeInteger).integerValue,be=F(b,@23,AncPrivateVaultCanonicalTypeInteger).integerValue;if(!Exact(F(c,@5,AncPrivateVaultCanonicalTypeBytes).bytesValue,16)||!Exact(F(b,@5,AncPrivateVaultCanonicalTypeBytes).bytesValue,16)||cc<1||bc<1||be<bc||!Same(F(b,@20,AncPrivateVaultCanonicalTypeBytes).bytesValue,authHash)||!Same(F(b,@21,AncPrivateVaultCanonicalTypeBytes).bytesValue,checkpointHash)||!Same(F(b,@22,AncPrivateVaultCanonicalTypeBytes).bytesValue,authorizer)||(uint64_t)bc<authCreated||(uint64_t)be>authExpires||(uint64_t)cc<authCreated||cc>bc||now<(uint64_t)bc||now>(uint64_t)be){Set(status,AncPrivateVaultManifestCheckpointStatusBinding);return nil;} Set(status,AncPrivateVaultManifestCheckpointStatusOK);return [[AncPrivateVaultManifestCheckpointBundle alloc]initWithCheckpoint:checkpoint binding:binding digest:checkpointHash];
}
