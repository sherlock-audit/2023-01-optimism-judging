shw

low

# Incorrect code comments in the `StandardBridge.sol` contract

## Summary

Incorrect code comments in the `StandardBridge.sol` contract.

## Vulnerability Detail

The code comments for the `bridgeERC20` and `bridgeERC20To` functions in the `universal/StandardBridge.sol` contract do not match the actual code. The comments say the bridge returns tokens to the sender if the bridging fails, but the refund logic has been removed since [PR#3535](https://github.com/ethereum-optimism/optimism/pull/3535).

## Impact

Specfication error only.

## Code Snippet

https://github.com/ethereum-optimism/optimism/blob/3f4b3c328153a8aa03611158b6984d624b17c1d9/packages/contracts-bedrock/contracts/universal/StandardBridge.sol#L219-L222
https://github.com/ethereum-optimism/optimism/blob/3f4b3c328153a8aa03611158b6984d624b17c1d9/packages/contracts-bedrock/contracts/universal/StandardBridge.sol#L251-L254

## Tool used

Manual Review

## Recommendation

Remove the outdated code comments.