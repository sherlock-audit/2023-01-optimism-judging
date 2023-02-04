cmichel

low

# Spec: Wrong `OptimismPortal` interface

## Summary
Wrong `OptimismPortal` interface in the specs.

## Vulnerability Detail

The [`withdrawals.md`](https://github.com/ethereum-optimism/optimism/blob/3f4b3c328153a8aa03611158b6984d624b17c1d9/specs/withdrawals.md?plain=1#L149) specification file shows a wrong `L2ToL1MessagePasser` interface:

- `function proveWithdrawalTransaction(Types.WithdrawalTransaction memory _tx, uint256 _l2BlockNumber, Types.OutputRootProof calldata _outputRootProof, bytes[] calldata _withdrawalProof) external` uses the wrong `_l2BlockNumber` parameter. The parameter should be named `_l2OutputIndex` like in the `OptimismPortal` code.  The difference is that the `L2OutputOracle` pushes the blocks to an array, and the `startingBlockNumber` is its first element, so there's a shift from a L2 output _index_ to its L2 _block number_. Using the block number as described in the spec will make any `proveWithdrawalTransaction` calls fail.

```solidity
interface OptimismPortal {

    event WithdrawalFinalized(bytes32 indexed);

    function l2Sender() returns(address) external;

    function proveWithdrawalTransaction(
        Types.WithdrawalTransaction memory _tx,
        uint256 _l2BlockNumber, // @audit this is NOT the block number, it's the `_l2OutputIndex`.
        Types.OutputRootProof calldata _outputRootProof,
        bytes[] calldata _withdrawalProof
    ) external;

    function finalizeWithdrawalTransaction(
        Types.WithdrawalTransaction memory _tx
    ) external;
}
```

## Impact

Users usually go to the docs & specification to see how to integrate a project. Integrating Optimisim's `OptimismPortal` based on the specification will lead to errors as it uses the block number, different from the required block index in `L2OutputOracle`'s array.

## Code Snippet
https://github.com/ethereum-optimism/optimism/blob/3f4b3c328153a8aa03611158b6984d624b17c1d9/specs/withdrawals.md?plain=1#L149

## Tool used

Manual Review

## Recommendation
Use the correct interface by fixing the mentioned issues.