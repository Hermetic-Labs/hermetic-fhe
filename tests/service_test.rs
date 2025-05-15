use std::sync::Arc;
use tonic::Request;

use hermetic_fhe::api::{
    DecryptBooleanRequest, EncryptBooleanRequest, EvaluationRequest,
    FheService, KeyGenerationRequest, OperationType,
};
use hermetic_fhe::crypto::{CiphertextStore, KeyStore};
use hermetic_fhe::service::FheServiceImpl;

async fn setup_service() -> impl FheService {
    let key_store = Arc::new(KeyStore::new());
    let ciphertext_store = Arc::new(CiphertextStore::new());
    FheServiceImpl::new(key_store, ciphertext_store)
}

#[tokio::test]
async fn test_key_generation() {
    let service = setup_service().await;
    
    let request = Request::new(KeyGenerationRequest {
        parameter_set: 0, // DEFAULT
    });
    
    let response = service.generate_keys(request).await.unwrap();
    let response_body = response.get_ref();
    
    assert!(!response_body.client_key_id.is_empty(), "Client key ID should not be empty");
    assert!(!response_body.server_key_id.is_empty(), "Server key ID should not be empty");
}

#[tokio::test]
async fn test_encrypt_decrypt_boolean() {
    let service = setup_service().await;
    
    // Generate keys
    let key_gen_request = Request::new(KeyGenerationRequest {
        parameter_set: 0, // DEFAULT
    });
    
    let key_gen_response = service.generate_keys(key_gen_request).await.unwrap();
    let client_key_id = key_gen_response.get_ref().client_key_id.clone();
    
    // Encrypt a boolean value
    let encrypt_request = Request::new(EncryptBooleanRequest {
        client_key_id: client_key_id.clone(),
        value: true,
    });
    
    let encrypt_response = service.encrypt_boolean(encrypt_request).await.unwrap();
    let encrypted_data_id = encrypt_response.get_ref().encrypted_data_id.clone();
    
    // Decrypt the boolean value
    let decrypt_request = Request::new(DecryptBooleanRequest {
        client_key_id: client_key_id.clone(),
        encrypted_data_id,
        serialized_data: vec![],
    });
    
    let decrypt_response = service.decrypt_boolean(decrypt_request).await.unwrap();
    let decrypted_value = decrypt_response.get_ref().value;
    
    assert_eq!(decrypted_value, true, "Decrypted value should match the original");
}

#[tokio::test]
async fn test_boolean_and_operation() {
    let service = setup_service().await;
    
    // Generate keys
    let key_gen_request = Request::new(KeyGenerationRequest {
        parameter_set: 0, // DEFAULT
    });
    
    let key_gen_response = service.generate_keys(key_gen_request).await.unwrap();
    let client_key_id = key_gen_response.get_ref().client_key_id.clone();
    let server_key_id = key_gen_response.get_ref().server_key_id.clone();
    
    // Encrypt true
    let encrypt_true_request = Request::new(EncryptBooleanRequest {
        client_key_id: client_key_id.clone(),
        value: true,
    });
    
    let encrypt_true_response = service.encrypt_boolean(encrypt_true_request).await.unwrap();
    let true_id = encrypt_true_response.get_ref().encrypted_data_id.clone();
    
    // Encrypt false
    let encrypt_false_request = Request::new(EncryptBooleanRequest {
        client_key_id: client_key_id.clone(),
        value: false,
    });
    
    let encrypt_false_response = service.encrypt_boolean(encrypt_false_request).await.unwrap();
    let false_id = encrypt_false_response.get_ref().encrypted_data_id.clone();
    
    // Perform AND operation
    let eval_request = Request::new(EvaluationRequest {
        server_key_id: server_key_id.clone(),
        operation: OperationType::And as i32,
        operand_ids: vec![true_id, false_id],
    });
    
    let eval_response = service.evaluate_operation(eval_request).await.unwrap();
    let result_id = eval_response.get_ref().result_id.clone();
    
    // Decrypt the result
    let decrypt_request = Request::new(DecryptBooleanRequest {
        client_key_id: client_key_id.clone(),
        encrypted_data_id: result_id,
        serialized_data: vec![],
    });
    
    let decrypt_response = service.decrypt_boolean(decrypt_request).await.unwrap();
    let result = decrypt_response.get_ref().value;
    
    assert_eq!(result, false, "true AND false should be false");
}

#[tokio::test]
async fn test_boolean_or_operation() {
    let service = setup_service().await;
    
    // Generate keys
    let key_gen_request = Request::new(KeyGenerationRequest {
        parameter_set: 0, // DEFAULT
    });
    
    let key_gen_response = service.generate_keys(key_gen_request).await.unwrap();
    let client_key_id = key_gen_response.get_ref().client_key_id.clone();
    let server_key_id = key_gen_response.get_ref().server_key_id.clone();
    
    // Encrypt true
    let encrypt_true_request = Request::new(EncryptBooleanRequest {
        client_key_id: client_key_id.clone(),
        value: true,
    });
    
    let encrypt_true_response = service.encrypt_boolean(encrypt_true_request).await.unwrap();
    let true_id = encrypt_true_response.get_ref().encrypted_data_id.clone();
    
    // Encrypt false
    let encrypt_false_request = Request::new(EncryptBooleanRequest {
        client_key_id: client_key_id.clone(),
        value: false,
    });
    
    let encrypt_false_response = service.encrypt_boolean(encrypt_false_request).await.unwrap();
    let false_id = encrypt_false_response.get_ref().encrypted_data_id.clone();
    
    // Perform OR operation
    let eval_request = Request::new(EvaluationRequest {
        server_key_id: server_key_id.clone(),
        operation: OperationType::Or as i32,
        operand_ids: vec![true_id, false_id],
    });
    
    let eval_response = service.evaluate_operation(eval_request).await.unwrap();
    let result_id = eval_response.get_ref().result_id.clone();
    
    // Decrypt the result
    let decrypt_request = Request::new(DecryptBooleanRequest {
        client_key_id: client_key_id.clone(),
        encrypted_data_id: result_id,
        serialized_data: vec![],
    });
    
    let decrypt_response = service.decrypt_boolean(decrypt_request).await.unwrap();
    let result = decrypt_response.get_ref().value;
    
    assert_eq!(result, true, "true OR false should be true");
}

#[tokio::test]
async fn test_boolean_not_operation() {
    let service = setup_service().await;
    
    // Generate keys
    let key_gen_request = Request::new(KeyGenerationRequest {
        parameter_set: 0, // DEFAULT
    });
    
    let key_gen_response = service.generate_keys(key_gen_request).await.unwrap();
    let client_key_id = key_gen_response.get_ref().client_key_id.clone();
    let server_key_id = key_gen_response.get_ref().server_key_id.clone();
    
    // Encrypt true
    let encrypt_request = Request::new(EncryptBooleanRequest {
        client_key_id: client_key_id.clone(),
        value: true,
    });
    
    let encrypt_response = service.encrypt_boolean(encrypt_request).await.unwrap();
    let id = encrypt_response.get_ref().encrypted_data_id.clone();
    
    // Perform NOT operation
    let eval_request = Request::new(EvaluationRequest {
        server_key_id: server_key_id.clone(),
        operation: OperationType::Not as i32,
        operand_ids: vec![id],
    });
    
    let eval_response = service.evaluate_operation(eval_request).await.unwrap();
    let result_id = eval_response.get_ref().result_id.clone();
    
    // Decrypt the result
    let decrypt_request = Request::new(DecryptBooleanRequest {
        client_key_id: client_key_id.clone(),
        encrypted_data_id: result_id,
        serialized_data: vec![],
    });
    
    let decrypt_response = service.decrypt_boolean(decrypt_request).await.unwrap();
    let result = decrypt_response.get_ref().value;
    
    assert_eq!(result, false, "NOT true should be false");
} 