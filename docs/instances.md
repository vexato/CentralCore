# Instances

An `InstanceSpec` is the portable definition of a Minecraft installation. An
`Instance` combines that definition with a trusted local directory. This keeps
remote data separate from local filesystem authority.

Instance IDs accept only ASCII letters, digits, hyphens, and underscores.
`InstanceService` creates `.minecraft`, `mods`, `config`, and `logs` below the
instance root and persists a versioned `instance.json`. Creation is staged and
renamed into place. Reads and recursive deletion reject symbolic-link roots.

