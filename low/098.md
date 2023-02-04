obront

low

# L2OutputOracle outputs are removed by challenger, not proposer

## Summary

There is an inconsistency between the spec and reality regarding which user is able to delete the L2 outputs to roll back the chain.

## Vulnerability Detail

In the spec, it states:

> The proposer may also delete multiple output roots by calling the deleteL2Outputs() function and specifying the index of the first output to delete, this will also delete all subsequent outputs.

It goes on to explicitly state that this will be the same role as the sequencer:

> Note regarding future work: In the initial version of the system, the proposer will be the same entity as the sequencer, which is a trusted role. In the future proposers will need to submit a bond in order to post L2 output roots, and some or all of this bond may be taken in the event of a faulty proposal.

However, the code specifies a different user, called `CHALLENGER`, who has this permission:

```solidity
require(
    msg.sender == CHALLENGER,
    "L2OutputOracle: only the challenger address can delete outputs"
);
```
Looking at the `CHALLENGER` address, it appears that it is actually a multisig, separate from both the sequencer and proposer.

## Impact

The spec is incorrect in defining which user has the ability to roll back the chain.

## Code Snippet

https://github.com/ethereum-optimism/optimism/blob/f30376825c82f62b846590487fe46b7435213d37/specs/proposals.md#proposing-l2-output-commitments

https://github.com/sherlock-audit/2023-01-optimism/blob/main/optimism/packages/contracts-bedrock/contracts/L1/L2OutputOracle.sol#L129-L132

## Tool used

Manual Review

## Recommendation

Adjust the language in the spec to make clear that the `CHALLENGER` is a separate role controlled by a multisig.