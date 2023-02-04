obront

low

# The CrossDomainMessenger process is explained incorrectly in the spec

## Summary

The process for using the L1CrossDomainMessenger has not been updated in the spec, and it still explains the pre-Bedrock process rather than the updated process.

## Vulnerability Detail

The spec explains:

> When going from L2 into L1, the user must call relayMessage on the L1CrossDomainMessenger to finalize the withdrawal. This function can only be called after the finalization window has passed.

This is no longer the process. In Bedrock:
- the user proves their withdrawal right away
- the user proves their withdrawal on OptimismPortal, not CrossDomainMessenger
- the user executes their withdrawal on OptimismPortal, not by calling `relayMessage` (or any other function) on CrossDomainMessenger

## Impact

The spec is still showing the old withdrawal process, and doesn't accurately reflect the new process that will exist in Bedrock.

## Code Snippet

https://github.com/ethereum-optimism/optimism/blob/develop/specs/messengers.md#message-passing

https://github.com/sherlock-audit/2023-01-optimism/blob/main/optimism/packages/contracts-bedrock/contracts/L1/OptimismPortal.sol#L160-L344

## Tool used

Manual Review

## Recommendation

Update the explanation of the CrossDomainMessenger in the spec to explain the new withdrawal process.