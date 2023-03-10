obront

medium

# Censorship resistance is undermined and bridging of assets can be DOSed at low cost

## Summary

All L1->L2 transactions go through OptimismPortal's `depositTransaction` function. It is wrapped through the `metered` modifier. The goal is to create a gas market for L1->L2 transactions and not allow L1 TXs to fill up L2 batches (as the gas for deposit TX in L2 is payed for by the system), but the mechanism used makes it too inexpensive for a malicious user to DOS and censor deposits.

## Vulnerability Detail

It is possible for a malicious actor to snipe arbitrary L1->L2 transactions in the mempool for far too cheaply. This introduces two impacts:
1. Undermines censorship resistance guarantees by Optimism
2. Griefs users who simply want to bridge assets to L2

The core issue is the check in ResourceMetering.sol:
```solidity
// Make sure we can actually buy the resource amount requested by the user.
params.prevBoughtGas += _amount;
require(
    int256(uint256(params.prevBoughtGas)) <= MAX_RESOURCE_LIMIT,
    "ResourceMetering: cannot buy more gas than available gas limit"
);
```
Note that `params.prevBoughtGas` is reset per block. This means attacker can view a TX in the mempool and wrap up the following flashbot bundle:
1. Attacker TX to `depositTransaction`, with gasLimit = 8M (MAX_RESOURCE_LIMIT)
2. Victim TX to `depositTransaction`

The result is that attacker's transaction will execute and victim's TX would revert. It is unknown how this affects the UI and whether victim would be able to resubmit this TX again easily, but regardless it's clearly griefing user's attempt to bridge an asset. Note that a reverted TX is different from an uncompleted TX from a UX point of view.

From a censorship resistance perspective, there is nothing inherently preventing attack to continually use this technique to block out all TXs, albert gas metering price will rise as will be discussed.

Now we can demonstrate the cost of the attack to be low. Gas burned by the modifier is calculated as:
```solidity
// Determine the amount of ETH to be paid.
uint256 resourceCost = _amount * params.prevBaseFee;
...
uint256 gasCost = resourceCost / Math.max(block.basefee, 1000000000);
```
`params.prevBaseFee` is initialized at 1e9 and goes up per block by a factor of 1.375 when gas market is drained, while going down by 0.875 when gas market wasn't used at all. 

If we take the initial value, `resourceCost = 8e6 * 1e9 = 8e15`. If we assume tip is negligible to `block.basefee`, L1 gas cost in ETH equals `resourceCost` (divide by basefee and multiply by basefee). Therefore, cost of this snipe TX is:

`8e15 / 1e18 (ETH decimals) * 1600 (curr ETH price) = $12.80`

The result is an extremely low price to pay, and even taking into account extra tips for frontrunning, is easily achievable. 

In practice `prevBaseFee` will represent the market price for L2 gas. If it goes lower than initial value, DOSing will become cheaper, while if it goes higher it will become more expensive. The key problem is that the attacker's cost is too similar to the victim's cost. If victim is trying to pass a 400k TX, attacker needs to buy a 7.6M of gas. This gap is too small and the resulting situation is that for DOS to be too expensive for attacker, TX would have to be far too expensive for the average user. 

## Impact

Censorship resistance is undermined and bridging of assets can be DOSed at low cost.

## Code Snippet

https://github.com/ethereum-optimism/optimism/blob/407f97b9d13448b766624995ec824d3059d4d4f6/packages/contracts-bedrock/contracts/L1/ResourceMetering.sol#L133

## Tool used

Manual Review

## Recommendation

It is admittedly difficult to balance the need for censorship resistance with the prevention of L2 flooding via L1 TXs. However, the current solution which will make a victim's TX revert at hacker's will is inadequate and will lead to severe UX issues for users. 

Recommendation would be to not require gas spending to be under `MAX_RESOURCE_LIMIT` and solve it in L2 sequencing. It's already close enough to the L1 gas limit so that it can't be really abused. 