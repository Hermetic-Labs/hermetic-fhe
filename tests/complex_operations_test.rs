use std::sync::Arc;
use tonic::Request;

use hermetic_fhe::api::{
    DecryptBooleanRequest, DecryptIntegerRequest, EncryptBooleanRequest, EncryptIntegerRequest,
    EvaluationRequest, FheService, KeyGenerationRequest, OperationType,
};
use hermetic_fhe::crypto::{CiphertextStore, KeyStore};
use hermetic_fhe::service::FheServiceImpl;

async fn setup_service() -> impl FheService {
    let key_store = Arc::new(KeyStore::new());
    let ciphertext_store = Arc::new(CiphertextStore::new());
    FheServiceImpl::new(key_store, ciphertext_store)
}

#[tokio::test]
async fn test_chained_boolean_operations() {
    let service = setup_service().await;
    
    // Generate keys
    let key_gen_request = Request::new(KeyGenerationRequest {
        parameter_set: 0, // DEFAULT
    });
    
    let key_gen_response = service.generate_keys(key_gen_request).await.unwrap();
    let client_key_id = key_gen_response.get_ref().client_key_id.clone();
    let server_key_id = key_gen_response.get_ref().server_key_id.clone();
    
    // Encrypt three boolean values: true, false, true
    let encrypt_true1_request = Request::new(EncryptBooleanRequest {
        client_key_id: client_key_id.clone(),
        value: true,
    });
    let encrypt_true1_response = service.encrypt_boolean(encrypt_true1_request).await.unwrap();
    let true1_id = encrypt_true1_response.get_ref().encrypted_data_id.clone();
    
    let encrypt_false_request = Request::new(EncryptBooleanRequest {
        client_key_id: client_key_id.clone(),
        value: false,
    });
    let encrypt_false_response = service.encrypt_boolean(encrypt_false_request).await.unwrap();
    let false_id = encrypt_false_response.get_ref().encrypted_data_id.clone();
    
    let encrypt_true2_request = Request::new(EncryptBooleanRequest {
        client_key_id: client_key_id.clone(),
        value: true,
    });
    let encrypt_true2_response = service.encrypt_boolean(encrypt_true2_request).await.unwrap();
    let true2_id = encrypt_true2_response.get_ref().encrypted_data_id.clone();
    
    // Perform first operation: true1 AND false = false
    let eval_request1 = Request::new(EvaluationRequest {
        server_key_id: server_key_id.clone(),
        operation: OperationType::And as i32,
        operand_ids: vec![true1_id, false_id],
    });
    let eval_response1 = service.evaluate_operation(eval_request1).await.unwrap();
    let intermediate_result_id = eval_response1.get_ref().result_id.clone();
    
    // Perform second operation: (true1 AND false) OR true2 = true
    let eval_request2 = Request::new(EvaluationRequest {
        server_key_id: server_key_id.clone(),
        operation: OperationType::Or as i32,
        operand_ids: vec![intermediate_result_id, true2_id],
    });
    let eval_response2 = service.evaluate_operation(eval_request2).await.unwrap();
    let final_result_id = eval_response2.get_ref().result_id.clone();
    
    // Decrypt and verify the result
    let decrypt_request = Request::new(DecryptBooleanRequest {
        client_key_id: client_key_id.clone(),
        encrypted_data_id: final_result_id,
        serialized_data: vec![],
    });
    let decrypt_response = service.decrypt_boolean(decrypt_request).await.unwrap();
    let result = decrypt_response.get_ref().value;
    
    // We expect (true AND false) OR true = (false) OR true = true
    assert_eq!(result, true, "Chained boolean operation result should be true");
}

#[tokio::test]
async fn test_complex_integer_operations() {
    let service = setup_service().await;
    
    // Generate keys
    let key_gen_request = Request::new(KeyGenerationRequest {
        parameter_set: 0, // DEFAULT
    });
    
    let key_gen_response = service.generate_keys(key_gen_request).await.unwrap();
    let client_key_id = key_gen_response.get_ref().client_key_id.clone();
    let server_key_id = key_gen_response.get_ref().server_key_id.clone();
    
    // Encrypt three integer values: 5, 3, 2
    let encrypt_a_request = Request::new(EncryptIntegerRequest {
        client_key_id: client_key_id.clone(),
        value: 5,
        num_bits: 8,
    });
    let encrypt_a_response = service.encrypt_integer(encrypt_a_request).await.unwrap();
    let a_id = encrypt_a_response.get_ref().encrypted_data_id.clone();
    
    let encrypt_b_request = Request::new(EncryptIntegerRequest {
        client_key_id: client_key_id.clone(),
        value: 3,
        num_bits: 8,
    });
    let encrypt_b_response = service.encrypt_integer(encrypt_b_request).await.unwrap();
    let b_id = encrypt_b_response.get_ref().encrypted_data_id.clone();
    
    let encrypt_c_request = Request::new(EncryptIntegerRequest {
        client_key_id: client_key_id.clone(),
        value: 2,
        num_bits: 8,
    });
    let encrypt_c_response = service.encrypt_integer(encrypt_c_request).await.unwrap();
    let c_id = encrypt_c_response.get_ref().encrypted_data_id.clone();
    
    // Perform first operation: a * b = 5 * 3 = 15
    let eval_request1 = Request::new(EvaluationRequest {
        server_key_id: server_key_id.clone(),
        operation: OperationType::Multiply as i32,
        operand_ids: vec![a_id, b_id],
    });
    let eval_response1 = service.evaluate_operation(eval_request1).await.unwrap();
    let intermediate_result_id = eval_response1.get_ref().result_id.clone();
    
    // Perform second operation: (a * b) - c = 15 - 2 = 13
    let eval_request2 = Request::new(EvaluationRequest {
        server_key_id: server_key_id.clone(),
        operation: OperationType::Subtract as i32,
        operand_ids: vec![intermediate_result_id, c_id],
    });
    let eval_response2 = service.evaluate_operation(eval_request2).await.unwrap();
    let final_result_id = eval_response2.get_ref().result_id.clone();
    
    // Decrypt and verify the result
    let decrypt_request = Request::new(DecryptIntegerRequest {
        client_key_id: client_key_id.clone(),
        encrypted_data_id: final_result_id,
        serialized_data: vec![],
    });
    let decrypt_response = service.decrypt_integer(decrypt_request).await.unwrap();
    let result = decrypt_response.get_ref().value;
    
    // We expect (5 * 3) - 2 = 15 - 2 = 13
    assert_eq!(result, 13, "Complex integer operation result should be 13");
}

#[tokio::test]
async fn test_larger_integers() {
    let service = setup_service().await;
    
    // Generate keys
    let key_gen_request = Request::new(KeyGenerationRequest {
        parameter_set: 0, // DEFAULT
    });
    
    let key_gen_response = service.generate_keys(key_gen_request).await.unwrap();
    let client_key_id = key_gen_response.get_ref().client_key_id.clone();
    
    // Test with larger integer values (within 8-bit range)
    let value_a = 200;
    let encrypt_a_request = Request::new(EncryptIntegerRequest {
        client_key_id: client_key_id.clone(),
        value: value_a,
        num_bits: 8,
    });
    
    let encrypt_a_response = service.encrypt_integer(encrypt_a_request).await.unwrap();
    let encrypted_data_id = encrypt_a_response.get_ref().encrypted_data_id.clone();
    
    // Decrypt and verify
    let decrypt_request = Request::new(DecryptIntegerRequest {
        client_key_id: client_key_id.clone(),
        encrypted_data_id,
        serialized_data: vec![],
    });
    
    let decrypt_response = service.decrypt_integer(decrypt_request).await.unwrap();
    let decrypted_value = decrypt_response.get_ref().value;
    
    assert_eq!(decrypted_value, value_a, "Larger integer encryption/decryption should work correctly");
}

#[tokio::test]
async fn test_multiple_parameter_sets() {
    // Test DEFAULT parameter set
    test_with_parameter_set(0).await;
    
    // Test FAST parameter set
    test_with_parameter_set(1).await;
    
    // Test SECURE parameter set
    test_with_parameter_set(2).await;
}

async fn test_with_parameter_set(parameter_set: i32) {
    let service = setup_service().await;
    
    // Generate keys with the specified parameter set
    let key_gen_request = Request::new(KeyGenerationRequest {
        parameter_set,
    });
    
    let key_gen_response = service.generate_keys(key_gen_request).await.unwrap();
    let client_key_id = key_gen_response.get_ref().client_key_id.clone();
    let server_key_id = key_gen_response.get_ref().server_key_id.clone();
    
    // Encrypt integers
    let value_a = 10;
    let value_b = 5;
    
    let encrypt_a_request = Request::new(EncryptIntegerRequest {
        client_key_id: client_key_id.clone(),
        value: value_a,
        num_bits: 8,
    });
    let encrypt_a_response = service.encrypt_integer(encrypt_a_request).await.unwrap();
    let a_id = encrypt_a_response.get_ref().encrypted_data_id.clone();
    
    let encrypt_b_request = Request::new(EncryptIntegerRequest {
        client_key_id: client_key_id.clone(),
        value: value_b,
        num_bits: 8,
    });
    let encrypt_b_response = service.encrypt_integer(encrypt_b_request).await.unwrap();
    let b_id = encrypt_b_response.get_ref().encrypted_data_id.clone();
    
    // Test addition with this parameter set
    let eval_request = Request::new(EvaluationRequest {
        server_key_id: server_key_id.clone(),
        operation: OperationType::Add as i32,
        operand_ids: vec![a_id, b_id],
    });
    let eval_response = service.evaluate_operation(eval_request).await.unwrap();
    let result_id = eval_response.get_ref().result_id.clone();
    
    // Decrypt and verify
    let decrypt_request = Request::new(DecryptIntegerRequest {
        client_key_id: client_key_id.clone(),
        encrypted_data_id: result_id,
        serialized_data: vec![],
    });
    let decrypt_response = service.decrypt_integer(decrypt_request).await.unwrap();
    let result = decrypt_response.get_ref().value;
    
    assert_eq!(result, value_a + value_b, "Addition should work correctly with parameter set {}", parameter_set);
}

#[tokio::test]
async fn test_xor_operation() {
    let service = setup_service().await;
    
    // Generate keys
    let key_gen_request = Request::new(KeyGenerationRequest {
        parameter_set: 0, // DEFAULT
    });
    
    let key_gen_response = service.generate_keys(key_gen_request).await.unwrap();
    let client_key_id = key_gen_response.get_ref().client_key_id.clone();
    let server_key_id = key_gen_response.get_ref().server_key_id.clone();
    
    // Test cases for XOR
    let test_cases = [
        (true, true, false),   // true XOR true = false
        (true, false, true),   // true XOR false = true
        (false, true, true),   // false XOR true = true
        (false, false, false), // false XOR false = false
    ];
    
    for (a_val, b_val, expected) in test_cases {
        // Encrypt first boolean
        let encrypt_a_request = Request::new(EncryptBooleanRequest {
            client_key_id: client_key_id.clone(),
            value: a_val,
        });
        let encrypt_a_response = service.encrypt_boolean(encrypt_a_request).await.unwrap();
        let a_id = encrypt_a_response.get_ref().encrypted_data_id.clone();
        
        // Encrypt second boolean
        let encrypt_b_request = Request::new(EncryptBooleanRequest {
            client_key_id: client_key_id.clone(),
            value: b_val,
        });
        let encrypt_b_response = service.encrypt_boolean(encrypt_b_request).await.unwrap();
        let b_id = encrypt_b_response.get_ref().encrypted_data_id.clone();
        
        // Perform XOR operation
        let eval_request = Request::new(EvaluationRequest {
            server_key_id: server_key_id.clone(),
            operation: OperationType::Xor as i32,
            operand_ids: vec![a_id, b_id],
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
        
        assert_eq!(result, expected, "{} XOR {} should be {}", a_val, b_val, expected);
    }
} 