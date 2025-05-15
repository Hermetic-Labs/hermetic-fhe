use hermetic_fhe::crypto::{KeyStore, CiphertextStore, operations};
use tfhe::{FheBool, FheUint8, prelude::FheTryEncrypt, prelude::FheDecrypt};

#[test]
fn test_key_generation() {
    let key_store = KeyStore::new();
    
    // Test key generation with valid parameter set
    let result = key_store.generate_keys("DEFAULT");
    assert!(result.is_ok(), "Key generation should succeed with valid parameter set");
    
    let (client_key_id, server_key_id) = result.unwrap();
    assert!(!client_key_id.is_empty(), "Client key ID should not be empty");
    assert!(!server_key_id.is_empty(), "Server key ID should not be empty");
    
    // Verify that keys are retrievable
    let client_key = key_store.get_client_key(&client_key_id);
    assert!(client_key.is_some(), "Client key should be retrievable");
    
    let server_key = key_store.get_server_key(&server_key_id);
    assert!(server_key.is_some(), "Server key should be retrievable");
}

#[test]
fn test_invalid_parameter_set() {
    let key_store = KeyStore::new();
    
    // Test key generation with invalid parameter set
    let result = key_store.generate_keys("INVALID_PARAMETER_SET");
    assert!(result.is_err(), "Key generation should fail with invalid parameter set");
}

#[test]
fn test_ciphertext_store() {
    let key_store = KeyStore::new();
    let ciphertext_store = CiphertextStore::new();
    
    // Generate keys
    let (client_key_id, _) = key_store.generate_keys("DEFAULT").unwrap();
    let client_key = key_store.get_client_key(&client_key_id).unwrap();
    
    // Create and store a boolean ciphertext
    let client_key_ref = &*client_key;
    let true_value = FheBool::try_encrypt(true, client_key_ref).unwrap();
    let id = ciphertext_store.store_boolean(true_value);
    
    // Retrieve and verify the ciphertext
    let retrieved = ciphertext_store.get_boolean(&id);
    assert!(retrieved.is_some(), "Stored ciphertext should be retrievable");
    
    let decrypted_value = retrieved.unwrap().decrypt(client_key_ref);
    assert_eq!(decrypted_value, true, "Decrypted value should match the original");
    
    // Test with nonexistent ID
    let not_found = ciphertext_store.get_boolean("nonexistent-id");
    assert!(not_found.is_none(), "Nonexistent ciphertext ID should return None");
}

#[test]
fn test_boolean_operations() {
    let key_store = KeyStore::new();
    
    // Generate keys
    let (client_key_id, server_key_id) = key_store.generate_keys("DEFAULT").unwrap();
    let client_key = key_store.get_client_key(&client_key_id).unwrap();
    let server_key = key_store.get_server_key(&server_key_id).unwrap();
    
    // Set the server key for the thread
    tfhe::set_server_key((*server_key).clone());
    
    // Create boolean ciphertexts
    let client_key_ref = &*client_key;
    let true_cipher = FheBool::try_encrypt(true, client_key_ref).unwrap();
    let false_cipher = FheBool::try_encrypt(false, client_key_ref).unwrap();
    
    // Test AND operation
    let and_result = operations::boolean_and(&server_key, &true_cipher, &false_cipher);
    let decrypted_and = and_result.decrypt(client_key_ref);
    assert_eq!(decrypted_and, false, "true AND false should be false");
    
    // Test OR operation
    let or_result = operations::boolean_or(&server_key, &true_cipher, &false_cipher);
    let decrypted_or = or_result.decrypt(client_key_ref);
    assert_eq!(decrypted_or, true, "true OR false should be true");
    
    // Test XOR operation
    let xor_result = operations::boolean_xor(&server_key, &true_cipher, &false_cipher);
    let decrypted_xor = xor_result.decrypt(client_key_ref);
    assert_eq!(decrypted_xor, true, "true XOR false should be true");
    
    // Test NOT operation
    let not_result = operations::boolean_not(&server_key, &true_cipher);
    let decrypted_not = not_result.decrypt(client_key_ref);
    assert_eq!(decrypted_not, false, "NOT true should be false");
}

#[test]
fn test_integer_operations() {
    let key_store = KeyStore::new();
    
    // Generate keys
    let (client_key_id, server_key_id) = key_store.generate_keys("DEFAULT").unwrap();
    let client_key = key_store.get_client_key(&client_key_id).unwrap();
    let server_key = key_store.get_server_key(&server_key_id).unwrap();
    
    // Set the server key for the thread
    tfhe::set_server_key((*server_key).clone());
    
    // Create integer ciphertexts (using 8-bit integers for the test)
    let client_key_ref = &*client_key;
    let a = FheUint8::try_encrypt(5u8, client_key_ref).unwrap();
    let b = FheUint8::try_encrypt(3u8, client_key_ref).unwrap();
    
    // Test addition
    let add_result = operations::integer_add(&a, &b);
    let decrypted_add = <FheUint8 as FheDecrypt<u8>>::decrypt(&add_result, client_key_ref);
    assert_eq!(decrypted_add, 8u8, "5 + 3 should be 8");
    
    // Test subtraction
    let sub_result = operations::integer_subtract(&a, &b);
    let decrypted_sub = <FheUint8 as FheDecrypt<u8>>::decrypt(&sub_result, client_key_ref);
    assert_eq!(decrypted_sub, 2u8, "5 - 3 should be 2");
    
    // Test multiplication
    let mul_result = operations::integer_multiply(&a, &b);
    let decrypted_mul = <FheUint8 as FheDecrypt<u8>>::decrypt(&mul_result, client_key_ref);
    assert_eq!(decrypted_mul, 15u8, "5 * 3 should be 15");
} 