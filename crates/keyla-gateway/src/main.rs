//! Process bootstrap for the standalone gateway binary.

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    keyla_gateway::server::run().await
}
