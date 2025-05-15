use hermetic_fhe::api::{
    EncryptBooleanRequest, EvaluationRequest,
    KeyGenerationRequest, OperationType, DecryptBooleanRequest,
};
use hermetic_fhe::api::hermetic_fhe::fhe_service_client::FheServiceClient;
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    info!("Connecting to FHE Service...");
    
    // Connect to the server
    let mut client = FheServiceClient::connect("http://[::1]:50051").await?;
    
    // Generate encryption keys
    info!("Generating encryption keys...");
    let key_response = client
        .generate_keys(KeyGenerationRequest {
            parameter_set: 0, // DEFAULT
        })
        .await?;
    
    let client_key_id = key_response.get_ref().client_key_id.clone();
    let server_key_id = key_response.get_ref().server_key_id.clone();
    
    info!("Generated client key: {}", client_key_id);
    info!("Generated server key: {}", server_key_id);
    
    // Encrypt boolean values
    info!("Encrypting boolean values...");
    let encrypt_true = client
        .encrypt_boolean(EncryptBooleanRequest {
            client_key_id: client_key_id.clone(),
            value: true,
        })
        .await?;
    
    let encrypt_false = client
        .encrypt_boolean(EncryptBooleanRequest {
            client_key_id: client_key_id.clone(),
            value: false,
        })
        .await?;
    
    let true_id = encrypt_true.get_ref().encrypted_data_id.clone();
    let false_id = encrypt_false.get_ref().encrypted_data_id.clone();
    
    info!("Encrypted true value with ID: {}", true_id);
    info!("Encrypted false value with ID: {}", false_id);
    
    // Perform homomorphic AND operation
    info!("Performing homomorphic AND operation...");
    let eval_response = client
        .evaluate_operation(EvaluationRequest {
            server_key_id: server_key_id.clone(),
            operation: OperationType::And as i32,
            operand_ids: vec![true_id.clone(), false_id.clone()],
        })
        .await?;
    
    let result_id = eval_response.get_ref().result_id.clone();
    info!("AND operation result ID: {}", result_id);
    
    // Decrypt the result
    info!("Decrypting the result...");
    let decrypt_response = client
        .decrypt_boolean(DecryptBooleanRequest {
            client_key_id: client_key_id.clone(),
            encrypted_data_id: result_id,
            serialized_data: vec![],
        })
        .await?;
    
    let result = decrypt_response.get_ref().value;
    info!("Decrypted result: true AND false = {}", result);
    
    Ok(())
} 