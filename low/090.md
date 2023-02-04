cmichel

low

# Spec: Wrong `CrossDomainMessenger` interface

## Summary
Wrong `CrossDomainMessenger` interface in the specs.

## Vulnerability Details

The [`messengers.md`](https://github.com/ethereum-optimism/optimism/blob/3f4b3c328153a8aa03611158b6984d624b17c1d9/specs/messengers.md?plain=1#L38) specification file shows a wrong `CrossDomainMessenger` interface:

- `function otherMessenger() view external returns (address);` does not exist. It should be `function OTHER_MESSENGER() view external returns (address);`

```solidity
interface CrossDomainMessenger {
    event FailedRelayedMessage(bytes32 indexed msgHash);
    event RelayedMessage(bytes32 indexed msgHash);
    event SentMessage(address indexed target, address sender, bytes message, uint256 messageNonce, uint256 gasLimit);

    function MESSAGE_VERSION() view external returns (uint16);
    function messageNonce() view external returns (uint256);
    // @audit is OTHER_MESSENGER
    function otherMessenger() view external returns (address);
    function failedMessages(bytes32) view external returns (bool);
    function relayMessage(uint256 _nonce, address _sender, address _target, uint256 _value, uint256 _minGasLimit, bytes memory _message) payable external;
    function sendMessage(address _target, bytes memory _message, uint32 _minGasLimit) payable external;
    function successfulMessages(bytes32) view external returns (bool);
    function xDomainMessageSender() view external returns (address);
}
```

## Impact

Users usually go to the docs & specification to see how to integrate a project. Integrating Optimisim's CrossDomainMessenger based on the specification will lead to errors.

## Code Snippet
https://github.com/ethereum-optimism/optimism/blob/3f4b3c328153a8aa03611158b6984d624b17c1d9/specs/messengers.md?plain=1#L38

## Tool used

Manual Review

## Recommendation
Use the correct interface by fixing the mentioned issues.