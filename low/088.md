cmichel

low

# Spec: Wrong `StandardBridge` interface

## Summary
Wrong `StandardBridge` interface in the specs.

## Vulnerability Details

The [`bridges.md`](https://github.com/ethereum-optimism/optimism/blob/3f4b3c328153a8aa03611158b6984d624b17c1d9/specs/bridges.md?plain=1#L24) specification file shows a wrong `StandardBridge` interface:

- `ERC20BridgeFinalized` event is defined twice, this is an invalid interface as compilation will fail with "DeclarationError: Event with same name and parameter types defined twice."
- The function parameter `_extraData` is defined as `bytes memory _extraData` but the `StandardBridge` uses call-data. The encodings are incompatible.

```solidity
interface StandardBridge {
    // @audit ERC20BridgeFinalized event defined twice, this is an invalid interface as compilation will fail with "DeclarationError: Event with same name and parameter types defined twice."
    event ERC20BridgeFinalized(address indexed localToken, address indexed remoteToken, address indexed from, address to, uint256 amount, bytes extraData);
    event ERC20BridgeFinalized(address indexed localToken, address indexed remoteToken, address indexed from, address to, uint256 amount, bytes extraData);
    event ERC20BridgeInitiated(address indexed localToken, address indexed remoteToken, address indexed from, address to, uint256 amount, bytes extraData);
    event ETHBridgeFinalized(address indexed from, address indexed to, uint256 amount, bytes extraData);
    event ETHBridgeInitiated(address indexed from, address indexed to, uint256 amount, bytes extraData);
    // @audit everywhere it is `bytes calldata _extraData`, like 5 times
    function bridgeERC20(address _localToken, address _remoteToken, uint256 _amount, uint32 _minGasLimit, bytes memory _extraData) external;
    function bridgeERC20To(address _localToken, address _remoteToken, address _to, uint256 _amount, uint32 _minGasLimit, bytes memory _extraData) external;
    function bridgeETH(uint32 _minGasLimit, bytes memory _extraData) payable external;
    function bridgeETHTo(address _to, uint32 _minGasLimit, bytes memory _extraData) payable external;
    function deposits(address, address) view external returns (uint256);
    function finalizeBridgeERC20(address _localToken, address _remoteToken, address _from, address _to, uint256 _amount, bytes memory _extraData) external;
    function finalizeBridgeETH(address _from, address _to, uint256 _amount, bytes memory _extraData) payable external;
    function messenger() view external returns (address);
    function otherBridge() view external returns (address);
}
```

## Impact

Users usually go to the docs & specification to see how to integrate a project. Integrating Optimisim's bridge based on the specification will lead to errors.

## Code Snippet
https://github.com/ethereum-optimism/optimism/blob/3f4b3c328153a8aa03611158b6984d624b17c1d9/specs/bridges.md?plain=1#L24

## Tool used

Manual Review

## Recommendation
Use the correct interface by fixing the mentioned issues.