# Minecraft Vanilla engine

CentralCore reads Mojang's official version catalog and strongly typed version
metadata. Unknown JSON fields are ignored for forward compatibility. Modern
`arguments.game`/`arguments.jvm` and legacy `minecraftArguments` are supported.
Rules are evaluated centrally from normalized OS, architecture, OS version,
and explicit launcher features.

Libraries resolve from Mojang artifact metadata or legacy Maven coordinates.
Applicable normal artifacts enter the classpath; native classifiers are kept
out of it and extracted separately. Assets use the standard content-addressed
`<sha1-prefix>/<sha1>` layout and support legacy virtual/resource mappings.

Metadata inheritance is represented by the model but is currently rejected
with `MinecraftError::UnsupportedInheritance`. Official standalone Vanilla
versions do not require inheritance; loader composition will address merging
in a later phase.

