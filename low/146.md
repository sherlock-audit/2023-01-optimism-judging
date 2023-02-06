supernova

low

# Confusion in gap size

## Summary
According to the comments 

```solidity
Reserve extra slots in the storage layout for future upgrades.
     *         A gap size of 41 was chosen here, so that the first slot used in a child contract
     *         would be a multiple of 50.
```


## Vulnerability Detail
But actually gap is provided for 42 instead of 41 mentioned above . This can lead to presumptions on the minds of the dev that the first slot of the child contract is a multiple of 50 , when it is not . 
## Impact

## Code Snippet
https://github.com/sherlock-audit/2023-01-optimism/blob/main/optimism/packages/contracts-bedrock/contracts/universal/CrossDomainMessenger.sol#L132-L137
## Tool used

Manual Review

## Recommendation
Clear the collision in the comments and the actual code . 