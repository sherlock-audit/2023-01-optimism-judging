rvierdiiev

high

# Deposits from L1 to L2 using L1CrossDomainMessenger will fail and will not be replayable when L2CrossDomainMessenger is paused

## Summary
Deposits from L1 to L2 using L1CrossDomainMessenger will fail and will not be replayable when L2CrossDomainMessenger is paused.
## Vulnerability Detail
Both `L1CrossDomainMessenger` and `L2CrossDomainMessenger` extend `CrossDomainMessenger` contract that [can be paused](https://github.com/sherlock-audit/2023-01-optimism/blob/main/optimism/packages/contracts-bedrock/contracts/universal/CrossDomainMessenger.sol#L46).

When `CrossDomainMessenger` is paused then only `relayMessage` function [will revert](relayMessage) as it uses `whenNotPaused` modifier. It's still possible to call `sendMessage` when contract is paused.

In known issues section you can find following:
> 3.If the L1CrossDomainMessenger is paused, withdrawals sent to it will fail and not be replayable.

However there is another problem with pausing.
In case if `L2CrossDomainMessenger` is paused and no matter if `L1CrossDomainMessenger` is pause or not(as `sendMessage` function is callable when contract is paused), then all deposits that are coming from L1 to L2 through the `L1CrossDomainMessenger` will fail on L2 side, as `relayMessage` will revert, because is paused.
As result, it will be not possible for depositor to replay that deposit anymore as no information about the call is saved.
All sent value will be minted to aliased `L2CrossDomainMessenger` address.

Example.
1.User wants to send himself some eth from L1 to L2 through `L1CrossDomainMessenger`.
2.When new `TransactionDeposited` event was fired by `OptimismPortal`, `L2CrossDomainMessenger` on L2 was paused for some reasons.
3.`TransactionDeposited` was explored by special service that sent tx to L2 node.
4.Sent value amount is minted to aliased `L2CrossDomainMessenger` address and `L2CrossDomainMessenger.relayMessage` is called which reverts.
5.Depositor lost his eth as he is not able to replay tx.
## Impact
Lose of funds for depositor.
## Code Snippet
https://github.com/sherlock-audit/2023-01-optimism/blob/main/optimism/packages/contracts-bedrock/contracts/universal/CrossDomainMessenger.sol#L212-L343
## Tool used

Manual Review

## Recommendation
Pause `CrossDomainMessenger` on both sides at same time(L1 and L2) and restrict call of `sendMessage` function when contract is paused.