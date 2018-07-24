# Release Notes for Namecoin

- Previously, `createrawtransaction` supported a separate argument for creating
  name operations.  This has been removed, so that `createrawtransaction` now
  has the same interface as the upstream version in Bitcoin.  Instead, a new
  RPC method `namerawtransaction` has been added, which takes an already created
  transaction and changes its output to be a name operation.
  For more details, see
  [#181](https://github.com/namecoin/namecoin-core/issues/181).

- The optional "destination address" argument to `name_update` and
  `name_firstupdate` has been removed.  Instead, those methods as well
  as `name_new` now accept an optional `options` argument.  The destination
  address can now be specified by setting `destAddress` in these options.
  In addition, one can now also specify to send namecoins to addresses
  (similar to `sendmany`) in the same transaction by using the new `sendTo`
  option.
  See also the
  [basic proposal](https://github.com/namecoin/namecoin-core/issues/194), which
  is not yet completely implemented, and the concrete changes done in
  [#220](https://github.com/namecoin/namecoin-core/pull/220) and
  [#222](https://github.com/namecoin/namecoin-core/pull/222).

- `listunspent` now explicitly handles name outputs.  In particular, the coins
  associated to expired names are now always excluded.  Coins tied to active
  names are included only if the `includeNames` option is set, and they
  are marked as name operations in this case.
  More details can be found in
  [#192](https://github.com/namecoin/namecoin-core/issues/192).

- The `transferred` field in the output of `name_list` has been changed
  to `ismine` (with the negated value).  This makes it consistent with
  `name_pending`.  In addition, `ismine` has also been added to the other
  name RPCs like `name_show` or `name_scan`.
  See the [proposal](https://github.com/namecoin/namecoin-core/issues/219) and
  the [implementation](https://github.com/namecoin/namecoin-core/pull/236).

- `name_new` now checks whether a name exists already and by default rejects
  to register an already existing name.  To override this check and get back
  the old behaviour (where a `NAME_NEW` transaction can be sent for existing
  names), set the new `allowExisting` option to true.
  For more context, see the
  [corresponding issue](https://github.com/namecoin/namecoin-core/issues/54).

- The `namecoin-tx` utility has now support for creating name operations based
  on the new commands `namenew`, ` namefirstupdate` and `nameupdate`.  For the
  exact usage, see the
  [proposal](https://github.com/namecoin/namecoin-core/issues/147#issuecomment-402429258).
