use std::sync::Arc;
use tonic::transport::Server;
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;

mod api;
mod crypto;
mod service;

use api::FheServiceServer;
use crypto::{KeyStore, CiphertextStore};
use service::FheServiceImpl;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    // Initialize FHE service stores
    let key_store = Arc::new(KeyStore::new());
    let ciphertext_store = Arc::new(CiphertextStore::new());
    
    // Create service implementation
    let service = FheServiceImpl::new(key_store, ciphertext_store);
    
    // Define server address
    let addr = "[::1]:50051".parse()?;
    
    info!("FHE Service listening on {}", addr);
    
    // Start gRPC server
    Server::builder()
        .add_service(FheServiceServer::new(service))
        .serve(addr)
        .await?;
    
    Ok(())
}
