# Testing hermetic-fhe

This document explains how to run tests, examples, and benchmarks for the hermetic-fhe project.

## Running Tests

The project includes various test suites to verify the functionality of the FHE service.

### Running All Tests

To run all tests:

```bash
cargo test
```

### Running Specific Test Files

To run tests from a specific test file:

```bash
cargo test --test <test_file_name>
```

Examples:

```bash
# Run basic service tests
cargo test --test service_test

# Run integer operation tests
cargo test --test integer_test

# Run error handling tests
cargo test --test error_handling_test

# Run complex operations tests
cargo test --test complex_operations_test
```

### Running Specific Tests

To run a specific test by name:

```bash
cargo test <test_name>
```

Example:

```bash
cargo test test_boolean_and_operation
```

## Running Examples

The project includes example client applications that demonstrate how to use the FHE service.

### Running the Server

First, start the FHE service in one terminal:

```bash
cargo run
```

This will start the FHE service on `[::1]:50051`.

### Running the Basic Client Example

In another terminal, run the basic client example:

```bash
cargo run --bin client
```

This will demonstrate basic FHE operations.

### Running the Advanced Client Example

For a more complex demonstration of FHE capabilities, run the advanced client:

```bash
cargo run --bin advanced_client
```

This example demonstrates:

1. Boolean circuit evaluation
2. Complex integer arithmetic
3. Different parameter sets

## Running Benchmarks

The project includes benchmarks to measure the performance of FHE operations.

### Running All Benchmarks

To run all benchmarks:

```bash
cargo bench
```

### Running Specific Benchmark Groups

To run benchmarks for a specific group:

```bash
cargo bench --bench fhe_benchmark <group_name>
```

Examples:

```bash
# Benchmark key generation performance
cargo bench --bench fhe_benchmark key_generation

# Benchmark boolean operations
cargo bench --bench fhe_benchmark boolean_operations

# Benchmark integer operations
cargo bench --bench fhe_benchmark integer_operations

# Benchmark different parameter sets
cargo bench --bench fhe_benchmark parameter_sets
```

## Interpreting Benchmark Results

Benchmark results will be displayed in the terminal and also saved as HTML reports in the `target/criterion` directory.

The benchmarks measure:

1. **Key Generation Performance**: Speed of key generation with different parameter sets
2. **Boolean Operations**: Performance of AND, OR, XOR, NOT operations
3. **Integer Operations**: Performance of ADD, SUBTRACT, MULTIPLY operations
4. **Parameter Sets**: Comparison of different security parameter sets (DEFAULT, FAST, SECURE)

## Security Parameter Sets

The FHE service supports three parameter sets:

1. **DEFAULT (0)**: Balanced security and performance
2. **FAST (1)**: Optimized for performance, with reduced security
3. **SECURE (2)**: Highest security level, but slower performance

Different parameter sets can be specified when generating keys in both tests and examples.

## Troubleshooting

### Common Issues

1. **Server Not Running**: If you get connection errors when running the client, ensure the server is running in another terminal.

2. **Port Already in Use**: If port 50051 is already in use, you may need to stop other services or change the port in the server code.

3. **Missing Protobuf Compiler**: If you get errors about missing protocol buffers, install the protobuf compiler:
   ```bash
   # Ubuntu/Debian
   apt-get install protobuf-compiler
   
   # macOS
   brew install protobuf
   ```

4. **Slow Tests**: FHE operations can be computationally intensive. The SECURE parameter set (2) may be significantly slower than others.

## Extending the Tests

When adding new functionality to the service, consider adding corresponding tests:

1. **Unit Tests**: Test individual components like key generation, encryption/decryption
2. **Integration Tests**: Test the full FHE workflow
3. **Benchmarks**: Measure performance of new operations

Test files should be added to the `tests/` directory, following the existing patterns. 