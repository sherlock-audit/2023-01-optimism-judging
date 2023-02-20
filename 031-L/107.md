obront

low

# Withdrawing process in spec does not include two-step withdrawals

## Summary

The withdrawal process in the Introduction of the spec displays the old, single-step withdrawal process, not the new, two-step one.

## Vulnerability Detail

The Introduction section of the spec explains withdrawals with the following image:

https://github.com/ethereum-optimism/optimism/blob/develop/specs/assets/user-withdrawing-to-l1.svg

This image seems to have been drawn for the old withdrawal system, including steps:
```text
4. Wait for block hash to finalize
5. Send execute withdrawal transaction
```
In the new system, the user submits the proof right away, then waits at least 7 days for the proof (regardless of when block hash finalizes), and then makes an additional call to execute the transaction.

## Impact

The spec is still showing the old withdrawal process, and doesn't accurately reflect the new process that will exist in Bedrock.

## Code Snippet

https://github.com/ethereum-optimism/optimism/blob/develop/specs/introduction.md#withdrawing

https://github.com/sherlock-audit/2023-01-optimism/blob/main/optimism/packages/contracts-bedrock/contracts/L1/OptimismPortal.sol#L160-L344

## Tool used

Manual Review

## Recommendation

Update the diagram in the spec Introduction to explain the new two-step withdrawal process.