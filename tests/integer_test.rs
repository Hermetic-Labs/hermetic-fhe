use std::sync::Arc;
use tonic::Request;

use hermetic_fhe::api::{
    DecryptIntegerRequest, EncryptIntegerRequest, EvaluationRequest,
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
async fn test_encrypt_decrypt_integer() {
    let service = setup_service().await;
    
    // Generate keys
    let key_gen_request = Request::new(KeyGenerationRequest {
        parameter_set: 0, // DEFAULT
    });
    
    let key_gen_response = service.generate_keys(key_gen_request).await.unwrap();
    let client_key_id = key_gen_response.get_ref().client_key_id.clone();
    
    // Encrypt an integer value
    let value = 42;
    let encrypt_request = Request::new(EncryptIntegerRequest {
        client_key_id: client_key_id.clone(),
        value,
        num_bits: 8, // 8-bit integer
    });
    
    let encrypt_response = service.encrypt_integer(encrypt_request).await.unwrap();
    let encrypted_data_id = encrypt_response.get_ref().encrypted_data_id.clone();
    
    // Decrypt the integer value
    let decrypt_request = Request::new(DecryptIntegerRequest {
        client_key_id: client_key_id.clone(),
        encrypted_data_id,
        serialized_data: vec![],
    });
    
    let decrypt_response = service.decrypt_integer(decrypt_request).await.unwrap();
    let decrypted_value = decrypt_response.get_ref().value;
    
    assert_eq!(decrypted_value, value, "Decrypted integer should match the original");
}

#[tokio::test]
async fn test_integer_addition() {
    let service = setup_service().await;
    
    // Generate keys
    let key_gen_request = Request::new(KeyGenerationRequest {
        parameter_set: 0, // DEFAULT
    });
    
    let key_gen_response = service.generate_keys(key_gen_request).await.unwrap();
    let client_key_id = key_gen_response.get_ref().client_key_id.clone();
    let server_key_id = key_gen_response.get_ref().server_key_id.clone();
    
    // Encrypt first integer
    let value_a = 25;
    let encrypt_a_request = Request::new(EncryptIntegerRequest {
        client_key_id: client_key_id.clone(),
        value: value_a,
        num_bits: 8,
    });
    
    let encrypt_a_response = service.encrypt_integer(encrypt_a_request).await.unwrap();
    let a_id = encrypt_a_response.get_ref().encrypted_data_id.clone();
    
    // Encrypt second integer
    let value_b = 17;
    let encrypt_b_request = Request::new(EncryptIntegerRequest {
        client_key_id: client_key_id.clone(),
        value: value_b,
        num_bits: 8,
    });
    
    let encrypt_b_response = service.encrypt_integer(encrypt_b_request).await.unwrap();
    let b_id = encrypt_b_response.get_ref().encrypted_data_id.clone();
    
    // Perform addition
    let eval_request = Request::new(EvaluationRequest {
        server_key_id: server_key_id.clone(),
        operation: OperationType::Add as i32,
        operand_ids: vec![a_id, b_id],
    });
    
    let eval_response = service.evaluate_operation(eval_request).await.unwrap();
    let result_id = eval_response.get_ref().result_id.clone();
    
    // Decrypt the result
    let decrypt_request = Request::new(DecryptIntegerRequest {
        client_key_id: client_key_id.clone(),
        encrypted_data_id: result_id,
        serialized_data: vec![],
    });
    
    let decrypt_response = service.decrypt_integer(decrypt_request).await.unwrap();
    let result = decrypt_response.get_ref().value;
    
    assert_eq!(result, value_a + value_b, "25 + 17 should be 42");
}

#[tokio::test]
async fn test_integer_subtraction() {
    let service = setup_service().await;
    
    // Generate keys
    let key_gen_request = Request::new(KeyGenerationRequest {
        parameter_set: 0, // DEFAULT
    });
    
    let key_gen_response = service.generate_keys(key_gen_request).await.unwrap();
    let client_key_id = key_gen_response.get_ref().client_key_id.clone();
    let server_key_id = key_gen_response.get_ref().server_key_id.clone();
    
    // Encrypt first integer
    let value_a = 30;
    let encrypt_a_request = Request::new(EncryptIntegerRequest {
        client_key_id: client_key_id.clone(),
        value: value_a,
        num_bits: 8,
    });
    
    let encrypt_a_response = service.encrypt_integer(encrypt_a_request).await.unwrap();
    let a_id = encrypt_a_response.get_ref().encrypted_data_id.clone();
    
    // Encrypt second integer
    let value_b = 12;
    let encrypt_b_request = Request::new(EncryptIntegerRequest {
        client_key_id: client_key_id.clone(),
        value: value_b,
        num_bits: 8,
    });
    
    let encrypt_b_response = service.encrypt_integer(encrypt_b_request).await.unwrap();
    let b_id = encrypt_b_response.get_ref().encrypted_data_id.clone();
    
    // Perform subtraction
    let eval_request = Request::new(EvaluationRequest {
        server_key_id: server_key_id.clone(),
        operation: OperationType::Subtract as i32,
        operand_ids: vec![a_id, b_id],
    });
    
    let eval_response = service.evaluate_operation(eval_request).await.unwrap();
    let result_id = eval_response.get_ref().result_id.clone();
    
    // Decrypt the result
    let decrypt_request = Request::new(DecryptIntegerRequest {
        client_key_id: client_key_id.clone(),
        encrypted_data_id: result_id,
        serialized_data: vec![],
    });
    
    let decrypt_response = service.decrypt_integer(decrypt_request).await.unwrap();
    let result = decrypt_response.get_ref().value;
    
    assert_eq!(result, value_a - value_b, "30 - 12 should be 18");
}

#[tokio::test]
async fn test_integer_multiplication() {
    let service = setup_service().await;
    
    // Generate keys
    let key_gen_request = Request::new(KeyGenerationRequest {
        parameter_set: 0, // DEFAULT
    });
    
    let key_gen_response = service.generate_keys(key_gen_request).await.unwrap();
    let client_key_id = key_gen_response.get_ref().client_key_id.clone();
    let server_key_id = key_gen_response.get_ref().server_key_id.clone();
    
    // Encrypt first integer
    let value_a = 6;
    let encrypt_a_request = Request::new(EncryptIntegerRequest {
        client_key_id: client_key_id.clone(),
        value: value_a,
        num_bits: 8,
    });
    
    let encrypt_a_response = service.encrypt_integer(encrypt_a_request).await.unwrap();
    let a_id = encrypt_a_response.get_ref().encrypted_data_id.clone();
    
    // Encrypt second integer
    let value_b = 7;
    let encrypt_b_request = Request::new(EncryptIntegerRequest {
        client_key_id: client_key_id.clone(),
        value: value_b,
        num_bits: 8,
    });
    
    let encrypt_b_response = service.encrypt_integer(encrypt_b_request).await.unwrap();
    let b_id = encrypt_b_response.get_ref().encrypted_data_id.clone();
    
    // Perform multiplication
    let eval_request = Request::new(EvaluationRequest {
        server_key_id: server_key_id.clone(),
        operation: OperationType::Multiply as i32,
        operand_ids: vec![a_id, b_id],
    });
    
    let eval_response = service.evaluate_operation(eval_request).await.unwrap();
    let result_id = eval_response.get_ref().result_id.clone();
    
    // Decrypt the result
    let decrypt_request = Request::new(DecryptIntegerRequest {
        client_key_id: client_key_id.clone(),
        encrypted_data_id: result_id,
        serialized_data: vec![],
    });
    
    let decrypt_response = service.decrypt_integer(decrypt_request).await.unwrap();
    let result = decrypt_response.get_ref().value;
    
    assert_eq!(result, value_a * value_b, "6 * 7 should be 42");
} 