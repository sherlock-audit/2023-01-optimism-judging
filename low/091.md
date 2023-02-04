cmichel

low

# Spec: Wrong `L2OutputOracle` interface

## Summary
Wrong `L2OutputOracle` interface in the specs.

## Vulnerability Detail

The [`proposals.md`](https://github.com/ethereum-optimism/optimism/blob/3f4b3c328153a8aa03611158b6984d624b17c1d9/specs/proposals.md?plain=1#L142) specification file shows a wrong `L2OutputOracle` interface:

- `function getNextBlockNumber() public view returns (uint256)` does not exist. It should be `function nextBlockNumber() public view returns (uint256)`

```solidity
/**
 * @notice The number of the first L2 block recorded in this contract.
 */
uint256 public startingBlockNumber;

/**
 * @notice The timestamp of the first L2 block recorded in this contract.
 */
uint256 public startingTimestamp;

/**
 * @notice Accepts an L2 outputRoot and the timestamp of the corresponding L2 block. The
 * timestamp must be equal to the current value returned by `nextTimestamp()` in order to be
 * accepted.
 * This function may only be called by the Proposer.
 *
 * @param _l2Output      The L2 output of the checkpoint block.
 * @param _l2BlockNumber The L2 block number that resulted in _l2Output.
 * @param _l1Blockhash   A block hash which must be included in the current chain.
 * @param _l1BlockNumber The block number with the specified block hash.
*/
  function proposeL2Output(
      bytes32 _l2Output,
      uint256 _l2BlockNumber,
      bytes32 _l1Blockhash,
      uint256 _l1BlockNumber
  )

/**
 * @notice Deletes all output proposals after and including the proposal that corresponds to
 *         the given output index. Only the challenger address can delete outputs.
 *
 * @param _l2OutputIndex Index of the first L2 output to be deleted. All outputs after this
 *                       output will also be deleted.
 */
function deleteL2Outputs(uint256 _l2OutputIndex) external

/**
 * @notice Computes the block number of the next L2 block that needs to be checkpointed.
 */
 // @audit is called `function nextBlockNumber() public view returns (uint256)`
function getNextBlockNumber() public view returns (uint256)
```

## Impact

Users usually go to the docs & specification to see how to integrate a project. Integrating Optimisim's L2OutputOracle based on the specification will lead to errors.

## Code Snippet
https://github.com/ethereum-optimism/optimism/blob/3f4b3c328153a8aa03611158b6984d624b17c1d9/specs/proposals.md?plain=1#L142

## Tool used

Manual Review

## Recommendation
Use the correct interface by fixing the mentioned issues.