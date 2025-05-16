use std::error::Error;

use hermetic_fhe::api::{
    fhe_service_client::FheServiceClient, DecryptBooleanRequest, DecryptIntegerRequest,
    EncryptBooleanRequest, EncryptIntegerRequest, EvaluationRequest, KeyGenerationRequest, OperationType,
};
use tonic::Request;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Connect to the FHE service
    let mut client = FheServiceClient::connect("http://[::1]:50051").await?;
    println!("Connected to FHE service");
    
    // Demo 1: Boolean operations
    println!("\n===== Boolean Circuit Evaluation =====");
    boolean_circuit_demo(&mut client).await?;
    
    // Demo 2: Integer arithmetic
    println!("\n===== Integer Arithmetic =====");
    integer_arithmetic_demo(&mut client).await?;
    
    // Demo 3: Using different parameter sets
    println!("\n===== Parameter Sets Demo =====");
    parameter_sets_demo(&mut client).await?;
    
    Ok(())
}

async fn boolean_circuit_demo(client: &mut FheServiceClient<tonic::transport::Channel>) -> Result<(), Box<dyn Error>> {
    // Generate keys with default parameter set
    let key_gen_request = Request::new(KeyGenerationRequest {
        parameter_set: 0, // DEFAULT
    });
    
    let key_gen_response = client.generate_keys(key_gen_request).await?;
    let key_gen_result = key_gen_response.into_inner();
    let client_key_id = key_gen_result.client_key_id;
    let server_key_id = key_gen_result.server_key_id;
    
    println!("Generated keys: client_key_id={}, server_key_id={}", client_key_id, server_key_id);
    
    // Encrypt boolean values: A, B, C, D
    let input_values = [
        ("A", true),
        ("B", false),
        ("C", true),
        ("D", false),
    ];
    
    let mut encrypted_ids = Vec::new();
    
    for (name, value) in input_values.iter() {
        let encrypt_request = Request::new(EncryptBooleanRequest {
            client_key_id: client_key_id.clone(),
            value: *value,
        });
        
        let encrypt_response = client.encrypt_boolean(encrypt_request).await?;
        let encrypted_id = encrypt_response.into_inner().encrypted_data_id;
        encrypted_ids.push(encrypted_id.clone());
        
        println!("Encrypted {} = {} (id: {})", name, value, encrypted_id);
    }
    
    // Demonstrate a more complex boolean circuit:
    // Result = (A AND B) OR (C AND NOT D)
    
    // Step 1: Compute NOT D
    let not_d_request = Request::new(EvaluationRequest {
        server_key_id: server_key_id.clone(),
        operation: OperationType::Not as i32,
        operand_ids: vec![encrypted_ids[3].clone()], // D
    });
    
    let not_d_response = client.evaluate_operation(not_d_request).await?;
    let not_d_id = not_d_response.into_inner().result_id;
    println!("Computed NOT D (id: {})", not_d_id);
    
    // Step 2: Compute A AND B
    let a_and_b_request = Request::new(EvaluationRequest {
        server_key_id: server_key_id.clone(),
        operation: OperationType::And as i32,
        operand_ids: vec![encrypted_ids[0].clone(), encrypted_ids[1].clone()], // A, B
    });
    
    let a_and_b_response = client.evaluate_operation(a_and_b_request).await?;
    let a_and_b_id = a_and_b_response.into_inner().result_id;
    println!("Computed A AND B (id: {})", a_and_b_id);
    
    // Step 3: Compute C AND NOT D
    let c_and_not_d_request = Request::new(EvaluationRequest {
        server_key_id: server_key_id.clone(),
        operation: OperationType::And as i32,
        operand_ids: vec![encrypted_ids[2].clone(), not_d_id.clone()], // C, NOT D
    });
    
    let c_and_not_d_response = client.evaluate_operation(c_and_not_d_request).await?;
    let c_and_not_d_id = c_and_not_d_response.into_inner().result_id;
    println!("Computed C AND NOT D (id: {})", c_and_not_d_id);
    
    // Step 4: Compute (A AND B) OR (C AND NOT D)
    let final_request = Request::new(EvaluationRequest {
        server_key_id: server_key_id.clone(),
        operation: OperationType::Or as i32,
        operand_ids: vec![a_and_b_id.clone(), c_and_not_d_id.clone()],
    });
    
    let final_response = client.evaluate_operation(final_request).await?;
    let final_result_id = final_response.into_inner().result_id;
    println!("Computed (A AND B) OR (C AND NOT D) (id: {})", final_result_id);
    
    // Decrypt the final result
    let decrypt_request = Request::new(DecryptBooleanRequest {
        client_key_id: client_key_id.clone(),
        encrypted_data_id: final_result_id,
        serialized_data: vec![],
    });
    
    let decrypt_response = client.decrypt_boolean(decrypt_request).await?;
    let result = decrypt_response.into_inner().value;
    
    println!("Final result: (A AND B) OR (C AND NOT D) = {}", result);
    println!("Expected: (true AND false) OR (true AND NOT false) = false OR (true AND true) = false OR true = true");
    
    if result == true {
        println!("✅ Result matches expected output");
    } else {
        println!("❌ Result does not match expected output");
    }
    
    Ok(())
}

async fn integer_arithmetic_demo(client: &mut FheServiceClient<tonic::transport::Channel>) -> Result<(), Box<dyn Error>> {
    // Generate keys with default parameter set
    let key_gen_request = Request::new(KeyGenerationRequest {
        parameter_set: 0, // DEFAULT
    });
    
    let key_gen_response = client.generate_keys(key_gen_request).await?;
    let key_gen_result = key_gen_response.into_inner();
    let client_key_id = key_gen_result.client_key_id;
    let server_key_id = key_gen_result.server_key_id;
    
    println!("Generated keys: client_key_id={}, server_key_id={}", client_key_id, server_key_id);
    
    // Encrypt integer values
    let a = 15;
    let b = 7;
    let c = 3;
    
    let encrypt_a_request = Request::new(EncryptIntegerRequest {
        client_key_id: client_key_id.clone(),
        value: a,
        num_bits: 8,
    });
    let encrypt_a_response = client.encrypt_integer(encrypt_a_request).await?;
    let a_id = encrypt_a_response.into_inner().encrypted_data_id;
    println!("Encrypted A = {} (id: {})", a, a_id);
    
    let encrypt_b_request = Request::new(EncryptIntegerRequest {
        client_key_id: client_key_id.clone(),
        value: b,
        num_bits: 8,
    });
    let encrypt_b_response = client.encrypt_integer(encrypt_b_request).await?;
    let b_id = encrypt_b_response.into_inner().encrypted_data_id;
    println!("Encrypted B = {} (id: {})", b, b_id);
    
    let encrypt_c_request = Request::new(EncryptIntegerRequest {
        client_key_id: client_key_id.clone(),
        value: c,
        num_bits: 8,
    });
    let encrypt_c_response = client.encrypt_integer(encrypt_c_request).await?;
    let c_id = encrypt_c_response.into_inner().encrypted_data_id;
    println!("Encrypted C = {} (id: {})", c, c_id);
    
    // Compute a complex arithmetic expression: (A - B) * C
    
    // Step 1: Compute A - B
    let a_minus_b_request = Request::new(EvaluationRequest {
        server_key_id: server_key_id.clone(),
        operation: OperationType::Subtract as i32,
        operand_ids: vec![a_id.clone(), b_id.clone()],
    });
    let a_minus_b_response = client.evaluate_operation(a_minus_b_request).await?;
    let a_minus_b_id = a_minus_b_response.into_inner().result_id;
    println!("Computed A - B (id: {})", a_minus_b_id);
    
    // Step 2: Compute (A - B) * C
    let final_request = Request::new(EvaluationRequest {
        server_key_id: server_key_id.clone(),
        operation: OperationType::Multiply as i32,
        operand_ids: vec![a_minus_b_id.clone(), c_id.clone()],
    });
    let final_response = client.evaluate_operation(final_request).await?;
    let final_result_id = final_response.into_inner().result_id;
    println!("Computed (A - B) * C (id: {})", final_result_id);
    
    // Decrypt the final result
    let decrypt_request = Request::new(DecryptIntegerRequest {
        client_key_id: client_key_id.clone(),
        encrypted_data_id: final_result_id,
        serialized_data: vec![],
    });
    let decrypt_response = client.decrypt_integer(decrypt_request).await?;
    let result = decrypt_response.into_inner().value;
    
    println!("Final result: (A - B) * C = ({} - {}) * {} = {} * {} = {}", a, b, c, a - b, c, (a - b) * c);
    println!("Decrypted result: {}", result);
    
    if result == (a - b) * c {
        println!("✅ Result matches expected output");
    } else {
        println!("❌ Result does not match expected output");
    }
    
    Ok(())
}

async fn parameter_sets_demo(client: &mut FheServiceClient<tonic::transport::Channel>) -> Result<(), Box<dyn Error>> {
    // Demonstrate the different parameter sets
    let parameter_sets = [
        (0, "DEFAULT"),
        (1, "FAST"),
        (2, "SECURE"),
    ];
    
    for (param_set, name) in parameter_sets.iter() {
        println!("\nTesting {} parameter set:", name);
        
        // Generate keys with this parameter set
        let key_gen_request = Request::new(KeyGenerationRequest {
            parameter_set: *param_set,
        });
        
        let key_gen_response = client.generate_keys(key_gen_request).await?;
        let key_gen_result = key_gen_response.into_inner();
        let client_key_id = key_gen_result.client_key_id;
        let server_key_id = key_gen_result.server_key_id;
        
        println!("Generated keys with {} parameter set", name);
        
        // Encrypt and perform a simple operation
        let a = 42;
        let b = 27;
        
        let encrypt_a_request = Request::new(EncryptIntegerRequest {
            client_key_id: client_key_id.clone(),
            value: a,
            num_bits: 8,
        });
        let encrypt_a_response = client.encrypt_integer(encrypt_a_request).await?;
        let a_id = encrypt_a_response.into_inner().encrypted_data_id;
        
        let encrypt_b_request = Request::new(EncryptIntegerRequest {
            client_key_id: client_key_id.clone(),
            value: b,
            num_bits: 8,
        });
        let encrypt_b_response = client.encrypt_integer(encrypt_b_request).await?;
        let b_id = encrypt_b_response.into_inner().encrypted_data_id;
        
        // Perform addition
        let add_request = Request::new(EvaluationRequest {
            server_key_id: server_key_id.clone(),
            operation: OperationType::Add as i32,
            operand_ids: vec![a_id.clone(), b_id.clone()],
        });
        let add_response = client.evaluate_operation(add_request).await?;
        let add_result_id = add_response.into_inner().result_id;
        
        // Decrypt and verify
        let decrypt_request = Request::new(DecryptIntegerRequest {
            client_key_id: client_key_id.clone(),
            encrypted_data_id: add_result_id,
            serialized_data: vec![],
        });
        let decrypt_response = client.decrypt_integer(decrypt_request).await?;
        let result = decrypt_response.into_inner().value;
        
        println!("Using {} parameter set: {} + {} = {}", name, a, b, result);
        
        if result == a + b {
            println!("✅ Correct result with {} parameter set", name);
        } else {
            println!("❌ Incorrect result with {} parameter set", name);
        }
    }
    
    Ok(())
} 