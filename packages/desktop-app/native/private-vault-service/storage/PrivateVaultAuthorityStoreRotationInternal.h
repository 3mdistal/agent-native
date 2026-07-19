#import "PrivateVaultAuthorityStore.h"
#import "PrivateVaultCustodyRepositoryRotationInternal.h"

@class AncPrivateVaultControlLogReplayResult;

NS_ASSUME_NONNULL_BEGIN

/* Rotation commits are deliberately separate from the generic replay
 * constructor. The custody checkpoint is an opaque repository-issued proof of
 * the exact g -> g+1 pending-key staging operation; freezing it here prevents a
 * valid control edge from being paired with substituted pending custody. */
FOUNDATION_EXPORT AncPrivateVaultVerifiedReplayResult
    *_Nullable AncPrivateVaultVerifiedRotationReplayResultCreate(
        AncPrivateVaultControlLogReplayResult *replayResult,
        AncPrivateVaultAuthorityCheckpoint *expectedCheckpoint,
        AncPrivateVaultPreparedRotationCustodyCheckpoint
            *preparedRotationCheckpoint,
        uint64_t verifiedAtMs);

NS_ASSUME_NONNULL_END
