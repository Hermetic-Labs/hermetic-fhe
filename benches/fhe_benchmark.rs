#[macro_use]
extern crate criterion;

use criterion::{black_box, Criterion, BenchmarkId};
use std::sync::Arc;
use tonic::Request;

use hermetic_fhe::api::{
    DecryptBooleanRequest, DecryptIntegerRequest, EncryptBooleanRequest, EncryptIntegerRequest,
    EvaluationRequest, FheService, KeyGenerationRequest, OperationType,
};
use hermetic_fhe::crypto::{CiphertextStore, KeyStore};
use hermetic_fhe::service::FheServiceImpl;

// Helper function to create a new service instance
fn setup_service() -> impl FheService {
    let key_store = Arc::new(KeyStore::new());
    let ciphertext_store = Arc::new(CiphertextStore::new());
    FheServiceImpl::new(key_store, ciphertext_store)
}

// Helper function to generate keys
async fn generate_keys(service: &impl FheService, parameter_set: i32) -> (String, String) {
    let key_gen_request = Request::new(KeyGenerationRequest {
        parameter_set,
    });
    
    let key_gen_response = service.generate_keys(key_gen_request).await.unwrap();
    let response = key_gen_response.get_ref();
    
    (response.client_key_id.clone(), response.server_key_id.clone())
}

// Helper function to encrypt a boolean value
async fn encrypt_boolean(service: &impl FheService, client_key_id: &str, value: bool) -> String {
    let encrypt_request = Request::new(EncryptBooleanRequest {
        client_key_id: client_key_id.to_string(),
        value,
    });
    
    let encrypt_response = service.encrypt_boolean(encrypt_request).await.unwrap();
    encrypt_response.get_ref().encrypted_data_id.clone()
}

// Helper function to encrypt an integer value
async fn encrypt_integer(service: &impl FheService, client_key_id: &str, value: i64, num_bits: u32) -> String {
    let encrypt_request = Request::new(EncryptIntegerRequest {
        client_key_id: client_key_id.to_string(),
        value,
        num_bits,
    });
    
    let encrypt_response = service.encrypt_integer(encrypt_request).await.unwrap();
    encrypt_response.get_ref().encrypted_data_id.clone()
}

fn bench_key_generation(c: &mut Criterion) {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    
    let mut group = c.benchmark_group("key_generation");
    
    // Benchmark key generation with different parameter sets
    for param_set in [0, 1, 2] {
        group.bench_with_input(BenchmarkId::from_parameter(param_set), &param_set, |b, &param_set| {
            b.iter(|| {
                runtime.block_on(async {
                    let service = setup_service();
                    generate_keys(&service, param_set).await
                })
            });
        });
    }
    
    group.finish();
}

fn bench_boolean_operations(c: &mut Criterion) {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    
    let mut group = c.benchmark_group("boolean_operations");
    
    // Benchmark different boolean operations
    let operations = [
        (OperationType::And as i32, "AND"),
        (OperationType::Or as i32, "OR"),
        (OperationType::Xor as i32, "XOR"),
        (OperationType::Not as i32, "NOT"),
    ];
    
    for (op_type, op_name) in operations.iter() {
        group.bench_with_input(BenchmarkId::from_parameter(op_name), op_type, |b, &op_type| {
            b.iter(|| {
                runtime.block_on(async {
                    let service = setup_service();
                    let (client_key_id, server_key_id) = generate_keys(&service, 0).await;
                    
                    let a_id = encrypt_boolean(&service, &client_key_id, true).await;
                    
                    // For NOT, we only need one operand
                    if op_type == &(OperationType::Not as i32) {
                        let eval_request = Request::new(EvaluationRequest {
                            server_key_id: server_key_id.clone(),
                            operation: *op_type,
                            operand_ids: vec![a_id.clone()],
                        });
                        
                        service.evaluate_operation(eval_request).await.unwrap();
                    } else {
                        let b_id = encrypt_boolean(&service, &client_key_id, false).await;
                        
                        let eval_request = Request::new(EvaluationRequest {
                            server_key_id: server_key_id.clone(),
                            operation: *op_type,
                            operand_ids: vec![a_id.clone(), b_id.clone()],
                        });
                        
                        service.evaluate_operation(eval_request).await.unwrap();
                    }
                })
            });
        });
    }
    
    group.finish();
}

fn bench_integer_operations(c: &mut Criterion) {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    
    let mut group = c.benchmark_group("integer_operations");
    
    // Benchmark different integer operations
    let operations = [
        (OperationType::Add as i32, "ADD"),
        (OperationType::Subtract as i32, "SUBTRACT"),
        (OperationType::Multiply as i32, "MULTIPLY"),
    ];
    
    for (op_type, op_name) in operations.iter() {
        group.bench_with_input(BenchmarkId::from_parameter(op_name), op_type, |b, &op_type| {
            b.iter(|| {
                runtime.block_on(async {
                    let service = setup_service();
                    let (client_key_id, server_key_id) = generate_keys(&service, 0).await;
                    
                    let a_id = encrypt_integer(&service, &client_key_id, 15, 8).await;
                    let b_id = encrypt_integer(&service, &client_key_id, 7, 8).await;
                    
                    let eval_request = Request::new(EvaluationRequest {
                        server_key_id: server_key_id.clone(),
                        operation: *op_type,
                        operand_ids: vec![a_id.clone(), b_id.clone()],
                    });
                    
                    service.evaluate_operation(eval_request).await.unwrap();
                })
            });
        });
    }
    
    group.finish();
}

fn bench_parameter_sets(c: &mut Criterion) {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    
    let mut group = c.benchmark_group("parameter_sets");
    
    // Benchmark integer addition with different parameter sets
    for param_set in [0, 1, 2] {
        group.bench_with_input(BenchmarkId::from_parameter(param_set), &param_set, |b, &param_set| {
            b.iter(|| {
                runtime.block_on(async {
                    let service = setup_service();
                    let (client_key_id, server_key_id) = generate_keys(&service, param_set).await;
                    
                    let a_id = encrypt_integer(&service, &client_key_id, 15, 8).await;
                    let b_id = encrypt_integer(&service, &client_key_id, 7, 8).await;
                    
                    let eval_request = Request::new(EvaluationRequest {
                        server_key_id: server_key_id.clone(),
                        operation: OperationType::Add as i32,
                        operand_ids: vec![a_id.clone(), b_id.clone()],
                    });
                    
                    service.evaluate_operation(eval_request).await.unwrap();
                })
            });
        });
    }
    
    group.finish();
}

criterion_group!(
    benches,
    bench_key_generation,
    bench_boolean_operations,
    bench_integer_operations,
    bench_parameter_sets
);
criterion_main!(benches); 