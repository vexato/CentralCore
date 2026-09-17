# Offline guarantee

Offline means that the selected operation performs no network request.
CentralCore reads only committed provider snapshots, detached signatures,
trusted public keys, Minecraft/loader metadata, managed Java archives and file
objects already present in the data directory.

Supported offline paths include provider catalog/list, provider-backed install
when every base and provider object is cached, update planning/application,
verification, repair, launch and process status. Missing cache content fails
closed; it never switches to online mode. A cached signed provider snapshot is
revalidated from its stored document/signature metadata when required, while a
304 response retains the previously verified state.

Provider sync, initial metadata resolution, interactive online authentication
and downloading a missing managed Java runtime remain online operations. Hosts
should expose that distinction in their UI instead of treating all failures as
connectivity failures.
