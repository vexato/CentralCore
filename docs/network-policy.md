# Network policy

`DownloadManager` is the shared transport boundary. Configuration centralizes
concurrency, retries, connect/request timeouts, maximum metadata/file sizes and
the user agent. Downloads accept HTTP and HTTPS for explicit compatibility;
provider and authentication policies can require HTTPS, and URLs containing
credentials are rejected.

Remote static providers additionally apply redirect and private-address
controls. Loopback, link-local, private and metadata-service destinations are
rejected unless the locally constructed provider configuration explicitly
allows private networks. Redirect targets are revalidated. Remote provider
registration requires an explicit signature policy; the production setting is
`SignaturePolicy::Required` with a locally trusted key.

Offline operations call cache/snapshot-specific code paths and do not fall back
to transport after a miss. A miss is an error explaining the unavailable local
artifact. Authentication refresh and provider sync are inherently online and
are not silently invoked by offline install/update/repair.
