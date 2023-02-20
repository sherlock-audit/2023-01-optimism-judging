lemonmon

low

# deposits: the `sourceHash` of L1 attributes deposited

## Summary

The calculation of `sourceHash` for L1 attributes deposited is incorrect.

Although, it is a very small difference, because of the misplaced blacket, it means a different thing with a different result from the actual calculation.

## Vulnerability Detail

According to the specs, the `sourceHash` of L1 attributes deposited is calculated based on:

https://github.com/sherlock-audit/2023-01-optimism/blob/main/optimism/specs/deposits.md?plain=1#L92

It means the `l1BlockHash` will be hashed alone, before it is hashed with other values. However, `l1BlockHash` and `seqNumber` should be hashed together, as the actual calculation in the `deposit_source.go`:


https://github.com/sherlock-audit/2023-01-optimism/blob/main/optimism/op-node/rollup/derive/deposit_source.go#L35-L46


Therefore, the line should be corrected as following:

```md
-  `keccak256(bytes32(uint256(1)), keccak256(l1BlockHash), bytes32(uint256(seqNumber)))`.
+  `keccak256(bytes32(uint256(1)), keccak256(l1BlockHash, bytes32(uint256(seqNumber))))`.
```

## Impact

factually incorrect information

The calculation of `sourceHash` in the specs will give a different result from the actual code.

## Code Snippet

https://github.com/sherlock-audit/2023-01-optimism/blob/main/optimism/specs/deposits.md?plain=1#L92
https://github.com/sherlock-audit/2023-01-optimism/blob/main/optimism/op-node/rollup/derive/deposit_source.go#L35-L46

## Tool used

Manual Review

## Recommendation

correct the calculation
