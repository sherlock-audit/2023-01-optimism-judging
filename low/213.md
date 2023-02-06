lemonmon

low

# `system_config`: incorrect variable name and missing config update type


## Summary

The specs for system config contains incorrect information and incorrect names for its contents.

1) The names for `overhead` and `scalar` are falsely stated as `l1FeeOverhead` and `l1FeeScalar` in multiple occasions.
2) The list of the configuration update types is missing the **unsafe block signer update**


## Vulnerability Detail

In the `SystemConfig` contract, there are public variables `overhead` and `scalar`:

https://github.com/sherlock-audit/2023-01-optimism/blob/main/optimism/packages/contracts-bedrock/contracts/L1/SystemConfig.sol#L51-L59

Below the variables `overhead` and `scalar` are incorrectly named as `l1FeeOverhead` and `l1FeeScalar` in multiple occasions:

https://github.com/sherlock-audit/2023-01-optimism/blob/main/optimism/specs/system_config.md?plain=1#L34
https://github.com/sherlock-audit/2023-01-optimism/blob/main/optimism/specs/system_config.md?plain=1#L73
https://github.com/sherlock-audit/2023-01-optimism/blob/main/optimism/specs/system_config.md?plain=1#L86-L90

In the above snippet:
Line 89: the names of `overhead` and `scalar`
It also is missing the type 3:

> - type `3`: `unsafeBlockSigner` overwrite, as `address` payload.

The corresponding update code snippets from `SystemConfig` are below:

https://github.com/sherlock-audit/2023-01-optimism/blob/main/optimism/packages/contracts-bedrock/contracts/L1/SystemConfig.sol#L25-L30
https://github.com/sherlock-audit/2023-01-optimism/blob/main/optimism/packages/contracts-bedrock/contracts/L1/SystemConfig.sol#L169-L175


## Impact

factually incorrect information
  - incorrect name of variables
  - missing config update type

As the name of variables double as interface to fetch the value, anybody uses the incorrect name in the specs to fetch the values will fail.
Also the specs do not list the possible config update types, so the users may not know that the `unsafeBlockSigner` can be updated.


## Code Snippet
https://github.com/sherlock-audit/2023-01-optimism/blob/main/optimism/packages/contracts-bedrock/contracts/L1/SystemConfig.sol#L51-L59
https://github.com/sherlock-audit/2023-01-optimism/blob/main/optimism/specs/system_config.md?plain=1#L34
https://github.com/sherlock-audit/2023-01-optimism/blob/main/optimism/specs/system_config.md?plain=1#L73
https://github.com/sherlock-audit/2023-01-optimism/blob/main/optimism/specs/system_config.md?plain=1#L86-L90
https://github.com/sherlock-audit/2023-01-optimism/blob/main/optimism/packages/contracts-bedrock/contracts/L1/SystemConfig.sol#L25-L30
https://github.com/sherlock-audit/2023-01-optimism/blob/main/optimism/packages/contracts-bedrock/contracts/L1/SystemConfig.sol#L169-L175

## Tool used

Manual Review

## Recommendation

Correct the names of the variables and add the missing config update type

