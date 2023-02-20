cmichel

low

# Spec: Wrong `L2ToL1MessagePasser` interface

## Summary
Wrong `L2ToL1MessagePasser` interface in the specs.

## Vulnerability Detail

The [`withdrawals.md`](https://github.com/ethereum-optimism/optimism/blob/3f4b3c328153a8aa03611158b6984d624b17c1d9/specs/withdrawals.md?plain=1#L106) specification file shows a wrong `L2ToL1MessagePasser` interface:

- `function nonce() view external returns (uint256);` does not exist. It should be `function messageNonce() view external returns (uint256);`

```solidity
interface L2ToL1MessagePasser {
    event MessagePassed(
        uint256 indexed nonce, // this is a global nonce value for all withdrawal messages
        address indexed sender,
        address indexed target,
        uint256 value,
        uint256 gasLimit,
        bytes data,
        bytes32 withdrawalHash
    );

    event WithdrawerBalanceBurnt(uint256 indexed amount);

    function burn() external;

    function initiateWithdrawal(address _target, uint256 _gasLimit, bytes memory _data) payable external;
   // @audit it's called messageNonce
    function nonce() view external returns (uint256);

    function sentMessages(bytes32) view external returns (bool);
}
```

## Impact

Users usually go to the docs & specification to see how to integrate a project. Integrating Optimisim's L2ToL1MessagePasser based on the specification will lead to errors.

## Code Snippet
https://github.com/ethereum-optimism/optimism/blob/3f4b3c328153a8aa03611158b6984d624b17c1d9/specs/withdrawals.md?plain=1#L106

## Tool used

Manual Review

## Recommendation
Use the correct interface by fixing the mentioned issues.