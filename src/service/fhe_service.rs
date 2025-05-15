use std::sync::Arc;
use tonic::{Request, Response, Status};
use tracing::info;
use tfhe::{FheBool, FheUint8, prelude::FheTryEncrypt, prelude::FheDecrypt};

use crate::api::{
    BooleanResponse, DecryptBooleanRequest, DecryptIntegerRequest, EncryptBooleanRequest,
    EncryptIntegerRequest, EncryptedDataResponse, EvaluationRequest, EvaluationResponse,
    FheService, IntegerResponse, KeyGenerationRequest, KeyGenerationResponse, OperationType,
};
use crate::crypto::{KeyStore, CiphertextStore, operations};

pub struct FheServiceImpl {
    key_store: Arc<KeyStore>,
    ciphertext_store: Arc<CiphertextStore>,
}

impl FheServiceImpl {
    pub fn new(key_store: Arc<KeyStore>, ciphertext_store: Arc<CiphertextStore>) -> Self {
        Self {
            key_store,
            ciphertext_store,
        }
    }
}

#[tonic::async_trait]
impl FheService for FheServiceImpl {
    async fn generate_keys(
        &self,
        request: Request<KeyGenerationRequest>,
    ) -> Result<Response<KeyGenerationResponse>, Status> {
        let parameter_set = match request.get_ref().parameter_set {
            0 => "DEFAULT",
            1 => "FAST",
            2 => "SECURE",
            _ => return Err(Status::invalid_argument("Invalid parameter set")),
        };

        info!("Generating keys with parameter set: {}", parameter_set);
        
        let (client_key_id, server_key_id) = self
            .key_store
            .generate_keys(parameter_set)
            .map_err(|e| Status::internal(format!("Failed to generate keys: {}", e)))?;

        Ok(Response::new(KeyGenerationResponse {
            client_key_id,
            server_key_id,
        }))
    }

    async fn encrypt_boolean(
        &self,
        request: Request<EncryptBooleanRequest>,
    ) -> Result<Response<EncryptedDataResponse>, Status> {
        let req = request.into_inner();
        
        // Get the client key
        let client_key = self
            .key_store
            .get_client_key(&req.client_key_id)
            .ok_or_else(|| Status::not_found("Client key not found"))?;

        // Need to dereference Arc to get the ClientKey reference
        let client_key_ref = &*client_key;
        
        // Encrypt the boolean value
        let encrypted = FheBool::try_encrypt(req.value, client_key_ref)
            .map_err(|e| Status::internal(format!("Encryption failed: {}", e)))?;
        
        // Store the encrypted value
        let encrypted_data_id = self.ciphertext_store.store_boolean(encrypted);
        
        Ok(Response::new(EncryptedDataResponse {
            encrypted_data_id,
            serialized_data: vec![], // For simplicity, not serializing the data
        }))
    }

    async fn encrypt_integer(
        &self,
        request: Request<EncryptIntegerRequest>,
    ) -> Result<Response<EncryptedDataResponse>, Status> {
        let req = request.into_inner();
        
        // Get the client key
        let client_key = self
            .key_store
            .get_client_key(&req.client_key_id)
            .ok_or_else(|| Status::not_found("Client key not found"))?;

        // Need to dereference Arc to get the ClientKey reference
        let client_key_ref = &*client_key;
        
        // Simplifying to always use uint8 for the example
        // In a real implementation, you'd choose the integer type based on the num_bits
        if req.value < 0 || req.value > 255 {
            return Err(Status::invalid_argument("Value out of range for uint8"));
        }

        // Encrypt the integer value
        let encrypted = FheUint8::try_encrypt(req.value as u8, client_key_ref)
            .map_err(|e| Status::internal(format!("Encryption failed: {}", e)))?;
        
        // Store the encrypted value
        let encrypted_data_id = self.ciphertext_store.store_integer(encrypted);
        
        Ok(Response::new(EncryptedDataResponse {
            encrypted_data_id,
            serialized_data: vec![], // For simplicity, not serializing the data
        }))
    }

    async fn evaluate_operation(
        &self,
        request: Request<EvaluationRequest>,
    ) -> Result<Response<EvaluationResponse>, Status> {
        let req = request.into_inner();
        
        // Get the server key
        let server_key = self
            .key_store
            .get_server_key(&req.server_key_id)
            .ok_or_else(|| Status::not_found("Server key not found"))?;

        // Validate the operands
        if req.operand_ids.is_empty() {
            return Err(Status::invalid_argument("No operands provided"));
        }

        match req.operation() {
            // Boolean operations
            OperationType::And | OperationType::Or | OperationType::Xor => {
                if req.operand_ids.len() != 2 {
                    return Err(Status::invalid_argument("Binary operation requires 2 operands"));
                }

                let a = self
                    .ciphertext_store
                    .get_boolean(&req.operand_ids[0])
                    .ok_or_else(|| Status::not_found("First operand not found"))?;

                let b = self
                    .ciphertext_store
                    .get_boolean(&req.operand_ids[1])
                    .ok_or_else(|| Status::not_found("Second operand not found"))?;

                let result = match req.operation() {
                    OperationType::And => operations::boolean_and(&server_key, &a, &b),
                    OperationType::Or => operations::boolean_or(&server_key, &a, &b),
                    OperationType::Xor => operations::boolean_xor(&server_key, &a, &b),
                    _ => unreachable!(),
                };

                let result_id = self.ciphertext_store.store_boolean(result);
                
                Ok(Response::new(EvaluationResponse {
                    result_id,
                    serialized_result: vec![],
                }))
            }
            
            // Unary boolean operation
            OperationType::Not => {
                if req.operand_ids.len() != 1 {
                    return Err(Status::invalid_argument("Unary operation requires 1 operand"));
                }

                let a = self
                    .ciphertext_store
                    .get_boolean(&req.operand_ids[0])
                    .ok_or_else(|| Status::not_found("Operand not found"))?;

                let result = operations::boolean_not(&server_key, &a);
                let result_id = self.ciphertext_store.store_boolean(result);
                
                Ok(Response::new(EvaluationResponse {
                    result_id,
                    serialized_result: vec![],
                }))
            }
            
            // Integer operations
            OperationType::Add | OperationType::Subtract | OperationType::Multiply => {
                if req.operand_ids.len() != 2 {
                    return Err(Status::invalid_argument("Binary operation requires 2 operands"));
                }

                let a = self
                    .ciphertext_store
                    .get_integer(&req.operand_ids[0])
                    .ok_or_else(|| Status::not_found("First operand not found"))?;

                let b = self
                    .ciphertext_store
                    .get_integer(&req.operand_ids[1])
                    .ok_or_else(|| Status::not_found("Second operand not found"))?;

                let result = match req.operation() {
                    OperationType::Add => operations::integer_add(&a, &b),
                    OperationType::Subtract => operations::integer_subtract(&a, &b),
                    OperationType::Multiply => operations::integer_multiply(&a, &b),
                    _ => unreachable!(),
                };

                let result_id = self.ciphertext_store.store_integer(result);
                
                Ok(Response::new(EvaluationResponse {
                    result_id,
                    serialized_result: vec![],
                }))
            }
            
            // Comparison operations - simplified for demo
            OperationType::GreaterThan | OperationType::LessThan | OperationType::Equal => {
                Err(Status::unimplemented("Comparison operations not implemented in this demo"))
            }
        }
    }

    async fn decrypt_boolean(
        &self,
        request: Request<DecryptBooleanRequest>,
    ) -> Result<Response<BooleanResponse>, Status> {
        let req = request.into_inner();
        
        // Get the client key
        let client_key = self
            .key_store
            .get_client_key(&req.client_key_id)
            .ok_or_else(|| Status::not_found("Client key not found"))?;

        // Need to dereference Arc to get the ClientKey reference
        let client_key_ref = &*client_key;
        
        // Get the encrypted value
        let encrypted = self
            .ciphertext_store
            .get_boolean(&req.encrypted_data_id)
            .ok_or_else(|| Status::not_found("Encrypted data not found"))?;

        // Decrypt the value
        let value = encrypted.decrypt(client_key_ref);
        
        Ok(Response::new(BooleanResponse { value }))
    }

    async fn decrypt_integer(
        &self,
        request: Request<DecryptIntegerRequest>,
    ) -> Result<Response<IntegerResponse>, Status> {
        let req = request.into_inner();
        
        // Get the client key
        let client_key = self
            .key_store
            .get_client_key(&req.client_key_id)
            .ok_or_else(|| Status::not_found("Client key not found"))?;

        // Need to dereference Arc to get the ClientKey reference
        let client_key_ref = &*client_key;
        
        // Get the encrypted value
        let encrypted = self
            .ciphertext_store
            .get_integer(&req.encrypted_data_id)
            .ok_or_else(|| Status::not_found("Encrypted data not found"))?;

        // Decrypt the value - explicitly specify u8 as the type
        let value = <FheUint8 as FheDecrypt<u8>>::decrypt(&encrypted, client_key_ref) as i64;
        
        Ok(Response::new(IntegerResponse { value }))
    }
} 