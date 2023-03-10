cmichel

high

# Withdrawal transactions can get stuck if output root is reproposed

## Summary
Withdrawal transactions may never be executed if the L2 output root for the block, for which the withdrawal was proven, is challenged and reproposed.

## Vulnerability Detail

Withdrawal transactions can be reproven in the case that the output root for their previously proven output index has been updated.
This can happen if the L2 output root was removed by the challenger.
However, to circumvent malicious users from reproving messages all the time and resetting the withdrawal countdown, reproving can only be done on the same L2 block number (and if the output root changed).

If the challenger deletes the block with the withdrawal transaction and the proposer proposes a different block that does _not_ have the withdrawal transaction, the withdrawal transaction can never be finalized - even if a future block includes the legitimate withdrawal transaction again, as reproving it is bound to the old `provenWithdrawals[withdrawalHash].l2OutputIndex`.

## Impact
Legitimate withdrawal transactions will never be finalized if the proposed block was challenged and replaced with a different one not having the withdrawal transaction. As this call fails on the "lowest level", the `OptimismPortal`, these transactions also cannot be replayed or be issued refunds. In case the withdrawal transaction was a token bridge transfer, the tokens are stuck on the other chain and cannot be recovered by the user.

## Code Snippet
https://github.com/ethereum-optimism/optimism/blob/3f4b3c328153a8aa03611158b6984d624b17c1d9/packages/contracts-bedrock/contracts/L1/OptimismPortal.sol#L196-L197
https://github.com/ethereum-optimism/optimism/blob/3f4b3c328153a8aa03611158b6984d624b17c1d9/packages/contracts-bedrock/contracts/L1/L2OutputOracle.sol#L128

## Tool used

Manual Review

## Recommendation
Loosen the restriction of reproving: Allow reproving _under a new L2 output index_ whenever the output root of the proven output index changes. This still balances the other concern of malicious users reproving transactions to reset the withdrawal countdown well as in the case where the output root changed, the withdrawal needs to be proved again anyway to be finalized.

```diff
- require(
-     provenWithdrawal.timestamp == 0 ||
-         (_l2OutputIndex == provenWithdrawal.l2OutputIndex &&
-             outputRoot != provenWithdrawal.outputRoot),
-     "OptimismPortal: withdrawal hash has already been proven"
- );
+ require(
+   provenWithdrawal.timestamp == 0 || 
+     L2_ORACLE.getL2Output(provenWithdrawal.l2OutputIndex) != provenWithdrawal.outputRoot,
+   "OptimismPortal: withdrawal hash has already been proven"
+ );
```