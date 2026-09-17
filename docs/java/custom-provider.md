# Custom Java distribution provider

Applications can add a trusted distribution source at compile time:

```rust,ignore
use centralcore::{download::CancellationToken, java::{JavaDistribution,
    JavaDistributionProvider, JavaDistributionRequest}};

struct CompanyMirror;

#[async_trait::async_trait]
impl JavaDistributionProvider for CompanyMirror {
    fn id(&self) -> &str { "company-mirror" }

    async fn resolve(&self, request: JavaDistributionRequest,
        cancellation: &CancellationToken)
        -> centralcore::Result<JavaDistribution> {
        // Return metadata from the company's authenticated/trusted mirror.
        let _ = (request, cancellation);
        Err(centralcore::Error::InvalidConfig("mirror lookup omitted".into()))
    }
}
```

The provider returns metadata only; extraction, hash verification, executable
validation and launch selection remain CentralCore responsibilities. A remote
instance manifest cannot register a provider or supply an executable path.

Register it with
`core.java().register_distribution_provider(Arc::new(CompanyMirror)).await?`.
The complete compilable example is `examples/custom-java-provider.rs`.
