lemonmon

low

# overview, withdrawals: DepositFeed does not exist


## Summary

There is no `DepositFeed` contract. The implementation of Deposit contract would be `OptimismPortal`.
There are some multiple occasions of incorrect information, for example, stating that Optimism Portal inherits from `DepositFeed` contract.

Also, using "Deposit Contract" and `DepositFeed` contract interchangeably may confuse the reader.

## Vulnerability Detail

https://github.com/sherlock-audit/2023-01-optimism/blob/main/optimism/specs/overview.md?plain=1#L52

There is no `DepositFeed` contract. It should be `OptimismPortal` contract.

```md
 - The `OptimismPortal` contract emits `TransactionDeposited` events, which the rollup driver reads in order to process 
```

https://github.com/sherlock-audit/2023-01-optimism/blob/main/optimism/specs/overview.md?plain=1#L109

Here as well, the `DepositFeed` contract should be `OptimismPortal` contract.

```md
call the `depositTransaction` method on the `OptimismPortal` contract. This in turn emits `TransactionDeposited` events, 
```

https://github.com/sherlock-audit/2023-01-optimism/blob/main/optimism/specs/overview.md?plain=1#L144

Here as well, the `DepositFeed` contract should be `OptimismPortal` contract.

```md
deposits initiated via the `OptimismPortal` contract on L1. All L2 blocks can also contain _sequenced transactions_, i.e.
```

https://github.com/sherlock-audit/2023-01-optimism/blob/main/optimism/specs/withdrawals.md?plain=1#L133-L135

The `OptimismPortal` inherits `Initializable`, `ResourceMetering` and `Semver` and there is no `DepositFeed` contract in the inheritance tree.


## Impact

Factually wrong specs

## Code Snippet

https://github.com/sherlock-audit/2023-01-optimism/blob/main/optimism/specs/overview.md?plain=1#L52
https://github.com/sherlock-audit/2023-01-optimism/blob/main/optimism/specs/overview.md?plain=1#L109
https://github.com/sherlock-audit/2023-01-optimism/blob/main/optimism/specs/overview.md?plain=1#L144
https://github.com/sherlock-audit/2023-01-optimism/blob/main/optimism/specs/withdrawals.md?plain=1#L133-L135

## Tool used

Manual Review

## Recommendation

Use "Deposit Contract" or `OptimismPortal` depending on the context, instead of `DepositFeed` contract.
