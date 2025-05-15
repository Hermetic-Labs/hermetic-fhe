fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=proto/fhe_service.proto");
    
    tonic_build::compile_protos("proto/fhe_service.proto")?;
    
    Ok(())
} 