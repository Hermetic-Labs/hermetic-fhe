use std::sync::Arc;
use tonic::Request;

use hermetic_fhe::api::{
    DecryptBooleanRequest, EncryptBooleanRequest, 
    EncryptIntegerRequest, EvaluationRequest, FheService, 
    KeyGenerationRequest, OperationType,
};
use hermetic_fhe::crypto::{CiphertextStore, KeyStore};
use hermetic_fhe::service::FheServiceImpl;

async fn setup_service() -> impl FheService {
    let key_store = Arc::new(KeyStore::new());
    let ciphertext_store = Arc::new(CiphertextStore::new());
    FheServiceImpl::new(key_store, ciphertext_store)
}

#[tokio::test]
async fn test_invalid_parameter_set() {
    let service = setup_service().await;
    
    // Try to generate keys with an invalid parameter set
    let request = Request::new(KeyGenerationRequest {
        parameter_set: 99, // Invalid parameter set
    });
    
    let response = service.generate_keys(request).await;
    assert!(response.is_err(), "Should return an error for invalid parameter set");
    
    if let Err(status) = response {
        assert_eq!(status.code(), tonic::Code::InvalidArgument);
        assert!(status.message().contains("Invalid parameter set"));
    }
}

#[tokio::test]
async fn test_client_key_not_found() {
    let service = setup_service().await;
    
    // Try to encrypt with a non-existent client key
    let encrypt_request = Request::new(EncryptBooleanRequest {
        client_key_id: "non-existent-key".to_string(),
        value: true,
    });
    
    let response = service.encrypt_boolean(encrypt_request).await;
    assert!(response.is_err(), "Should return an error for non-existent client key");
    
    if let Err(status) = response {
        assert_eq!(status.code(), tonic::Code::NotFound);
        assert!(status.message().contains("Client key not found"));
    }
}

#[tokio::test]
async fn test_server_key_not_found() {
    let service = setup_service().await;
    
    // Generate client key
    let key_gen_request = Request::new(KeyGenerationRequest {
        parameter_set: 0, // DEFAULT
    });
    
    let key_gen_response = service.generate_keys(key_gen_request).await.unwrap();
    let client_key_id = key_gen_response.get_ref().client_key_id.clone();
    
    // Encrypt a value
    let encrypt_request = Request::new(EncryptBooleanRequest {
        client_key_id: client_key_id.clone(),
        value: true,
    });
    
    let encrypt_response = service.encrypt_boolean(encrypt_request).await.unwrap();
    let encrypted_id = encrypt_response.get_ref().encrypted_data_id.clone();
    
    // Try to evaluate with a non-existent server key
    let eval_request = Request::new(EvaluationRequest {
        server_key_id: "non-existent-key".to_string(),
        operation: OperationType::Not as i32,
        operand_ids: vec![encrypted_id],
    });
    
    let response = service.evaluate_operation(eval_request).await;
    assert!(response.is_err(), "Should return an error for non-existent server key");
    
    if let Err(status) = response {
        assert_eq!(status.code(), tonic::Code::NotFound);
        assert!(status.message().contains("Server key not found"));
    }
}

#[tokio::test]
async fn test_encrypted_data_not_found() {
    let service = setup_service().await;
    
    // Generate keys
    let key_gen_request = Request::new(KeyGenerationRequest {
        parameter_set: 0, // DEFAULT
    });
    
    let key_gen_response = service.generate_keys(key_gen_request).await.unwrap();
    let client_key_id = key_gen_response.get_ref().client_key_id.clone();
    
    // Try to decrypt non-existent data
    let decrypt_request = Request::new(DecryptBooleanRequest {
        client_key_id: client_key_id.clone(),
        encrypted_data_id: "non-existent-data".to_string(),
        serialized_data: vec![],
    });
    
    let response = service.decrypt_boolean(decrypt_request).await;
    assert!(response.is_err(), "Should return an error for non-existent encrypted data");
    
    if let Err(status) = response {
        assert_eq!(status.code(), tonic::Code::NotFound);
        assert!(status.message().contains("Encrypted data not found"));
    }
}

#[tokio::test]
async fn test_integer_out_of_range() {
    let service = setup_service().await;
    
    // Generate keys
    let key_gen_request = Request::new(KeyGenerationRequest {
        parameter_set: 0, // DEFAULT
    });
    
    let key_gen_response = service.generate_keys(key_gen_request).await.unwrap();
    let client_key_id = key_gen_response.get_ref().client_key_id.clone();
    
    // Try to encrypt an integer that's out of range for uint8
    let encrypt_request = Request::new(EncryptIntegerRequest {
        client_key_id: client_key_id.clone(),
        value: 256, // Out of range for uint8 (0-255)
        num_bits: 8,
    });
    
    let response = service.encrypt_integer(encrypt_request).await;
    assert!(response.is_err(), "Should return an error for integer out of range");
    
    if let Err(status) = response {
        assert_eq!(status.code(), tonic::Code::InvalidArgument);
        assert!(status.message().contains("Value out of range"));
    }
}

#[tokio::test]
async fn test_invalid_operation_operands() {
    let service = setup_service().await;
    
    // Generate keys
    let key_gen_request = Request::new(KeyGenerationRequest {
        parameter_set: 0, // DEFAULT
    });
    
    let key_gen_response = service.generate_keys(key_gen_request).await.unwrap();
    let client_key_id = key_gen_response.get_ref().client_key_id.clone();
    let server_key_id = key_gen_response.get_ref().server_key_id.clone();
    
    // Encrypt a boolean value
    let encrypt_request = Request::new(EncryptBooleanRequest {
        client_key_id: client_key_id.clone(),
        value: true,
    });
    
    let encrypt_response = service.encrypt_boolean(encrypt_request).await.unwrap();
    let encrypted_id = encrypt_response.get_ref().encrypted_data_id.clone();
    
    // Try to use a binary operation with only one operand
    let eval_request = Request::new(EvaluationRequest {
        server_key_id: server_key_id.clone(),
        operation: OperationType::And as i32, // AND requires 2 operands
        operand_ids: vec![encrypted_id], // But we only provide 1
    });
    
    let response = service.evaluate_operation(eval_request).await;
    assert!(response.is_err(), "Should return an error for invalid number of operands");
    
    if let Err(status) = response {
        assert_eq!(status.code(), tonic::Code::InvalidArgument);
        assert!(status.message().contains("Binary operation requires 2 operands"));
    }
} 