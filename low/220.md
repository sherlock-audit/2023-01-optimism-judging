lemonmon

informational

# contract with only `IOptimismMintableERC20` interface is not compatible with `StandardBridge`



## Summary

If a custom contract implements only the `IOptimismMintableERC20`, but no the `ILegacyMintableERC20`, the contract is not compatible with the `StandardBridge`, as the bridge uses the `l1Token` function from the legacy interface

## Vulnerability Detail

The comment in the `IOptimismMintableERC20` suggests that one can make a custom implementation of `OptimismMintableERC20` using the interface `IOptimismMintableERC20`.

https://github.com/sherlock-audit/2023-01-optimism/blob/main/optimism/packages/contracts-bedrock/contracts/universal/IOptimismMintableERC20.sol#L8-L10

Also, the `StandardBridge`, which uses the `OptimismMintableERC20` has `_isOptimismMintableERC20` function, which checks whether the given token address is implementing `OptimismMintableERC20`. The function will be true if either of `ILegacyMintableERC20` or `IOptimismMintableERC20` is implemented. it means that if a token implements only one of the interfaces, it will return true.

https://github.com/sherlock-audit/2023-01-optimism/blob/main/optimism/packages/contracts-bedrock/contracts/universal/StandardBridge.sol#L446-L450

However, if the given token passes the `_isOptimismMintableERC20`, the legacy function `l1Token` will be called on the token. If the token does not implement the legacy interface, the call will fail.

https://github.com/sherlock-audit/2023-01-optimism/blob/main/optimism/packages/contracts-bedrock/contracts/L2/L2StandardBridge.sol#L170

Therefore, the token which only implements `IOptimismMintableERC20`, but not the `ILegacyMintableERC20`, is not compatible with `StandardBridge`.


## Impact

Any custom contract without `l1Token` function will not be compatible with `StandardBridge`


## Code Snippet


https://github.com/sherlock-audit/2023-01-optimism/blob/main/optimism/packages/contracts-bedrock/contracts/universal/IOptimismMintableERC20.sol#L8-L10


https://github.com/sherlock-audit/2023-01-optimism/blob/main/optimism/packages/contracts-bedrock/contracts/universal/StandardBridge.sol#L446-L450


https://github.com/sherlock-audit/2023-01-optimism/blob/main/optimism/packages/contracts-bedrock/contracts/L2/L2StandardBridge.sol#L170


## Tool used

Manual Review

## Recommendation

It is unclear it is intended behavior.
If the `_isOptimismMintableERC20` function returns true only when the both of interfaces are implemented, the token with only the `IOptimismMintableERC20` will be treated as if they are not the optimism mintable function, without failing.

