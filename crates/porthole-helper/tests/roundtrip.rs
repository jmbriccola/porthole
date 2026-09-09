//! Proves the zbus shapes the rest of this milestone is built on: a service
//! that owns a name, a proxy that calls it, and access to the caller's
//! credentials from the message header — which is what polkit will need.
//!
//! The bus is this binary's own ([`common::private_bus`]), never the
//! developer's. `com.jacopobriccola.PortholeProbe` is a singleton name like
//! any other, so on a shared bus a second `cargo test` finds it taken and
//! fails on `.expect("the name is free")` — which is a fact about who else is
//! on the machine, not about the shapes this file is here to prove.

mod common;

use zbus::{interface, proxy};

struct Probe;

#[interface(name = "com.jacopobriccola.PortholeProbe1")]
impl Probe {
    async fn echo(&self, text: String) -> String {
        format!("echo: {text}")
    }

    /// The caller's unique bus name, read from the message header. The polkit
    /// authorizer needs exactly this to build its Subject.
    async fn caller(&self, #[zbus(header)] header: zbus::message::Header<'_>) -> String {
        header
            .sender()
            .map(|s| s.to_string())
            .unwrap_or_else(|| "<none>".to_string())
    }
}

#[proxy(
    interface = "com.jacopobriccola.PortholeProbe1",
    default_service = "com.jacopobriccola.PortholeProbe",
    default_path = "/com/jacopobriccola/PortholeProbe"
)]
trait Probe {
    async fn echo(&self, text: &str) -> zbus::Result<String>;
    async fn caller(&self) -> zbus::Result<String>;
}

#[tokio::test]
async fn a_service_and_its_proxy_agree_on_the_session_bus() {
    // A session bus, not the system bus: this test must run unprivileged.
    // The helper uses the same shapes on the system bus in production.
    let _server = common::builder()
        .name("com.jacopobriccola.PortholeProbe")
        .expect("the name is free")
        .serve_at("/com/jacopobriccola/PortholeProbe", Probe)
        .expect("the path is free")
        .build()
        .await
        .expect("the service starts");

    let client = common::connect().await;
    let proxy = ProbeProxy::new(&client).await.expect("proxy binds");

    assert_eq!(proxy.echo("hello").await.unwrap(), "echo: hello");

    let caller = proxy.caller().await.unwrap();
    assert!(
        caller.starts_with(':'),
        "the header must carry the caller's unique name, got: {caller}"
    );
}
