# Transaction and crash recovery

Install and repair operations persist a small, versioned journal below the
instance runtime directory. Its states are `created`, `downloading`,
`validating`, `committing`, `committed`, `cancelled`, and `failed`.

At startup CentralCore examines instances left in `Installing`. It first tries
the instance OS lock: failure means another process still owns the operation
and the state is left untouched. If the lock is available, a complete managed
index is verified and can be promoted to `Installed`; otherwise the instance
is marked recoverable. A later install or repair reuses every valid cache
object and downloads only what remains.

Native staging directories carry the transaction identifier. A new operation
never silently overwrites another transaction's staging area. Abandoned
staging and `.part` files remain visible to cache verification/prune rather
than being mistaken for committed data.

