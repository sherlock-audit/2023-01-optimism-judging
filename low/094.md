cmichel

low

# Spec: Wrong description of withdrawal process

## Summary
Wrong description of the withdrawal process in the spec.

## Vulnerability Detail

The [`withdrawals.md`](https://github.com/ethereum-optimism/optimism/blob/3f4b3c328153a8aa03611158b6984d624b17c1d9/specs/withdrawals.md?plain=1#L67) describes the second step of the withdrawal process as:

> 2. The `OptimismPortal` contract retrieves the output root for the given block number from the `L2OutputOracle`'s
   `getL2OutputAfter()` function, and performs the remainder of the verification process internally.

The `getL2OutputAfter` call is never performed. This function does not even exist, most likely, it was referring to `getL2OutputIndexAfter`. However, even this function is not called. What happens in the withdrawal process is that `getL2Output` is called to retrieve the output root for the given block number (index).

## Impact

The withdrawal process should be clearly documented in the spec. Currently, it's referring to a non-existant function.

## Code Snippet
https://github.com/ethereum-optimism/optimism/blob/3f4b3c328153a8aa03611158b6984d624b17c1d9/specs/withdrawals.md?plain=1#L67

## Tool used

Manual Review

## Recommendation
Fix the spec by referring to `getL2Output(l2OutputIndex)` instead.