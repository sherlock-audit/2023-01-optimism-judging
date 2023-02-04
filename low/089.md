cmichel

low

# Spec: Wrong Deposited Transaction Type encoding

## Summary
Wrong Deposited Transaction Type encoding in the specs.

## Vulnerability Details

The [`deposits.md`](https://github.com/ethereum-optimism/optimism/blob/3f4b3c328153a8aa03611158b6984d624b17c1d9/specs/deposits.md?plain=1#L55-L68) specification file says that the deposited transaction type is encoded with "the following fields (rlp encoded in the order they appear here)":

However, they are missing the `isSystemTransaction` bool from the encoding and the order is also different (`data` after `gasLimit`), see:

```solidity
/**
 * @notice RLP encodes the L2 transaction that would be generated when a given deposit is sent
 *         to the L2 system. Useful for searching for a deposit in the L2 system. The
 *         transaction is prefixed with 0x7e to identify its EIP-2718 type.
 *
 * @param _tx User deposit transaction to encode.
 *
 * @return RLP encoded L2 deposit transaction.
 */
function encodeDepositTransaction(Types.UserDepositTransaction memory _tx)
    internal
    pure
    returns (bytes memory)
{
    bytes32 source = Hashing.hashDepositSource(_tx.l1BlockHash, _tx.logIndex);
    bytes[] memory raw = new bytes[](8);
    raw[0] = RLPWriter.writeBytes(abi.encodePacked(source));
    raw[1] = RLPWriter.writeAddress(_tx.from);
    raw[2] = _tx.isCreation ? RLPWriter.writeBytes("") : RLPWriter.writeAddress(_tx.to);
    raw[3] = RLPWriter.writeUint(_tx.mint);
    raw[4] = RLPWriter.writeUint(_tx.value);
    raw[5] = RLPWriter.writeUint(uint256(_tx.gasLimit));
    raw[6] = RLPWriter.writeBool(false);
    raw[7] = RLPWriter.writeBytes(_tx.data);
    return abi.encodePacked(uint8(0x7e), RLPWriter.writeList(raw));
}
```

## Impact

Users go to the specification to see how to integrate a project. Integrating according to this spec will be wrong.

## Code Snippet
https://github.com/ethereum-optimism/optimism/blob/3f4b3c328153a8aa03611158b6984d624b17c1d9/specs/deposits.md?plain=1#L55-L68
https://github.com/ethereum-optimism/optimism/blob/3f4b3c328153a8aa03611158b6984d624b17c1d9/packages/contracts-bedrock/contracts/libraries/Encoding.sol#L22

## Tool used

Manual Review

## Recommendation
Use the correct encoding from the `encodeDepositTransaction` function above.