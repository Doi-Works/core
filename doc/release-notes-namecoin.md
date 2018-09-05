# Release Notes for Doichain

- Previously, `createrawtransaction` supported a separate argument for creating
  name operations.  This has been removed, so that `createrawtransaction` now
  has the same interface as the upstream version in Bitcoin.  Instead, a new
  RPC method `namerawtransaction` has been added, which takes an already created
  transaction and changes its output to be a name operation.

  For more details, see: https://github.com/doichain/doichain-core/issues/181
