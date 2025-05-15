// Include the generated proto code
pub mod hermetic_fhe {
    tonic::include_proto!("hermetic_fhe");
}

// Re-export the proto types for easier access
pub use hermetic_fhe::{
    BooleanResponse, DecryptBooleanRequest, DecryptIntegerRequest, EncryptBooleanRequest,
    EncryptIntegerRequest, EncryptedDataResponse, EvaluationRequest, EvaluationResponse,
    IntegerResponse, KeyGenerationRequest, KeyGenerationResponse, OperationType,
};

// Re-export server
pub use hermetic_fhe::fhe_service_server::{FheService, FheServiceServer}; 