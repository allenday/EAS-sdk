# EAS SDK

A Python SDK for Ethereum Attestation Service (EAS) that provides easy-to-use methods for creating both on-chain and off-chain attestations.

## Features

### Core EAS Functionality
- **On-chain Attestations**: Create and submit attestations directly to the blockchain
- **Off-chain Attestations**: Generate signed attestation data for off-chain use
- **Multi-Attestations**: Efficient batch attestation operations
- **Attestation Revocation**: Revoke both on-chain and off-chain attestations
- **Schema Management**: Register and retrieve EAS schemas
- **Data Timestamping**: Timestamp arbitrary data on-chain

### Python SDK Advantages
- **Beautiful CLI**: Rich command-line interface with syntax highlighting and tables
- **GraphQL API**: Direct integration with EAS GraphQL endpoints for data retrieval
- **Protocol Buffers**: Generated protobuf messages for type-safe API responses
- **EIP-712 Support**: Full support for EIP-712 typed data signing
- **Web3 Integration**: Built on top of web3.py for Ethereum interaction
- **Multi-Network Support**: Works with mainnet, testnets, and Layer 2 networks
- **Enhanced DX**: Structured logging, error handling, and Python-native patterns

### Currently Not Supported
- **Delegated Attestations**: Use TypeScript SDK for delegation functionality
- **Private Data & Merkle Trees**: Use TypeScript SDK for selective data disclosure
- **Off-chain Signature Verification**: Use TypeScript SDK for signature verification

## Feature Comparison with TypeScript SDK

| Feature | Python SDK | TypeScript SDK | Notes |
|---------|------------|----------------|--------|
| **Core Attestations** | | | |
| On-chain attestations | ✅ `create_attestation()` | ✅ `attest()` | Full support |
| Off-chain attestations | ✅ `attest_offchain()` | ✅ `signOffchainAttestation()` | Full support |
| Multi-attestations | ✅ `multi_attest()` | ✅ `multiAttest()` | Batch operations |
| Attestation revocation | ✅ `revoke_attestation()` | ✅ `revoke()` | Full support |
| Multi-revocation | ✅ `multi_revoke()` | ✅ `multiRevoke()` | Batch operations |
| Off-chain revocation | ✅ `revoke_offchain()` | ✅ `revokeOffchain()` | Full support |
| **Schema Management** | | | |
| Schema registration | ✅ `register_schema()` | ✅ `register()` | Full support |
| Schema retrieval | ✅ `get_schema()` | ✅ `getSchema()` | Full support |
| Schema encoding | 🟡 Manual encoding | ✅ `SchemaEncoder` class | Different approach |
| **Delegated Operations** | | | |
| Delegated attestations | ❌ Not implemented | ✅ `attestByDelegation()` | **Missing** |
| Delegated revocations | ❌ Not implemented | ✅ `revokeByDelegation()` | **Missing** |
| **Private Data** | | | |
| Merkle tree support | ❌ Not implemented | ✅ `PrivateData` class | **Missing** |
| Selective revelation | ❌ Not implemented | ✅ `generateMultiProof()` | **Missing** |
| **Verification** | | | |
| Off-chain signature verification | ❌ Not implemented | ✅ `verifyOffchainAttestationSignature()` | **Missing** |
| **Timestamps** | | | |
| Data timestamping | ✅ `timestamp()` | ✅ `timestamp()` | Full support |
| Multi-timestamping | ✅ `multi_timestamp()` | ✅ `multiTimestamp()` | Full support |
| **Python-Specific Advantages** | | | |
| CLI tools with rich output | ✅ `eas-tools` | ❌ Not available | **Python advantage** |
| Protocol Buffers integration | ✅ Auto-generated | ❌ Not available | **Python advantage** |
| GraphQL API integration | ✅ Direct API calls | ❌ Not available | **Python advantage** |
| Structured logging | ✅ Built-in | ❌ Manual setup | **Python advantage** |

### Current Limitations

The Python SDK is missing several key features compared to the TypeScript SDK:

**❌ Missing High-Impact Features:**
- **Delegated Attestations & Revocations**: Complete absence of delegation functionality
- **Private Data & Merkle Trees**: No support for selective data disclosure
- **Off-chain Signature Verification**: Cannot verify off-chain attestation signatures

**🟡 API Differences:**
- **Schema Encoding**: Python uses manual encoding vs TypeScript's `SchemaEncoder` class
- **Method Naming**: Different naming conventions (`create_attestation()` vs `attest()`)
- **Architecture**: Integrated approach vs separate class-based design

**✅ Python SDK Unique Advantages:**
- **Rich CLI Tools**: Beautiful command-line interface with tables and syntax highlighting
- **Protocol Buffers**: Type-safe schema generation and binary encoding
- **GraphQL Integration**: Direct API access for querying attestations and schemas
- **Developer Experience**: Enhanced logging, error handling, and Python-native patterns

### When to Choose Each SDK

**Choose TypeScript SDK when:**
- You need delegated attestations or revocations
- Private data and selective revelation are required
- Full feature parity with EAS protocol is needed
- Working in a JavaScript/TypeScript ecosystem

**Choose Python SDK when:**
- You prefer Python development environment
- CLI tools and rich output formatting are valuable
- Protocol Buffers integration is beneficial
- Core attestation functionality is sufficient for your use case

## Development Roadmap

### Planned Features (Future Releases)

**High Priority:**
- **Delegated Attestations**: Implementation of `attestByDelegation()` and `revokeByDelegation()` methods ([#14](https://github.com/allenday/EAS-sdk/issues/14))
- **Off-chain Signature Verification**: Add `verifyOffchainAttestationSignature()` functionality ([#15](https://github.com/allenday/EAS-sdk/issues/15))
- **Schema Encoder Class**: Python equivalent of TypeScript's `SchemaEncoder` for easier schema handling ([#16](https://github.com/allenday/EAS-sdk/issues/16))

**Medium Priority:**
- **Private Data Support**: Merkle tree implementation for selective data disclosure ([#17](https://github.com/allenday/EAS-sdk/issues/17))
- **Enhanced Gas Estimation**: More sophisticated gas optimization strategies ([#18](https://github.com/allenday/EAS-sdk/issues/18))
- **Batch Operations Optimization**: Performance improvements for large batch operations

**Low Priority:**
- **Additional Network Support**: Expanded testnet and Layer 2 network configurations
- **Advanced CLI Features**: More interactive CLI tools and data visualization

### Contributing

Missing a feature you need? We welcome contributions! Check out our:
- [GitHub Issues](https://github.com/allenday/EAS-sdk/issues) for feature requests
- [Contributing Guidelines](CONTRIBUTING.md) for development setup
- [Security Guidelines](SECURITY.md) for security-related contributions

## Installation

```bash
pip install eas-sdk
```

## Quick Start

### 1. Environment Setup (Recommended)

Create a `.env` file in your project directory:

```bash
# Copy the example file
cp env.example .env

# Edit with your actual values
nano .env
```

Required variables in `.env`:
```bash
# Your wallet's private key (without 0x prefix)
PRIVATE_KEY=1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef

# Your wallet's public address
FROM_ACCOUNT=0x0fB2FA8306F661E31C7BFE76a5fF3A3F85a9f9A2

# Network to use (mainnet, sepolia, goerli)
NETWORK=sepolia
```

### 2. Using Configuration Helper (Recommended)

```python
from EAS import EAS
from EAS.config import create_eas_instance, get_example_attestation_data

# Create EAS instance using environment variables
eas = create_eas_instance()  # Reads from .env file automatically

# Get example attestation data
attestation_data = get_example_attestation_data()

# Create an off-chain attestation
attestation = eas.offchain_attestation(
    schema=attestation_data["schema"],
    recipient=attestation_data["recipient"],
    expiration=attestation_data["expiration"],
    revocable=attestation_data["revocable"],
    refUID=attestation_data["refUID"],
    data=attestation_data["data"]
)

# Save to file
eas.save_to_file(attestation, "attestation.json")

# Create an on-chain attestation
receipt = eas.onchain_attestation(
    schema=attestation_data["schema"],
    recipient=attestation_data["recipient"],
    expiration=attestation_data["expiration"],
    revocable=attestation_data["revocable"],
    refUID=attestation_data["refUID"],
    data=attestation_data["data"],
    value=attestation_data["value"]
)
```

### Manual Configuration

```python
from EAS import EAS

# Initialize the EAS client manually
eas = EAS(
    rpc_url="https://mainnet.infura.io/v3/YOUR_PROJECT_ID",
    contract_address="0x...",  # EAS contract address
    chain_id=1,  # Mainnet
    contract_version="0.26",
    from_account="0x...",  # Your wallet address
    private_key="0x..."  # Your private key
)

# Create an off-chain attestation
attestation = eas.offchain_attestation(
    schema="0x...",  # Schema UID
    recipient="0x...",  # Recipient address
    expiration=1234567890,  # Expiration timestamp
    revocable=True,
    refUID="0x0000000000000000000000000000000000000000000000000000000000000000",
    data=b"attestation data"
)

# Save to file
eas.save_to_file(attestation, "attestation.json")

# Create an on-chain attestation
receipt = eas.onchain_attestation(
    schema="0x...",
    recipient="0x...",
    expiration=1234567890,
    revocable=True,
    refUID="0x0000000000000000000000000000000000000000000000000000000000000000",
    data=b"attestation data",
    value=0  # ETH value to send with transaction
)
```

### Advanced Configuration

#### Custom Networks and Contract Addresses

```python
from EAS import EAS

# Custom RPC, contract address, and version configuration
eas = EAS(
    rpc_url="https://custom-rpc.network",
    contract_address="0x4200000000000000000000000000000000000021",  # Custom EAS contract
    chain_id=42,  # Custom network
    contract_version="0.26",
    from_account="0x0fB2FA8306F661E31C7BFE76a5fF3A3F85a9f9A2",
    private_key="1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
)
```

#### Multi-Attestation Operations

```python
import time
from EAS import EAS

# Multi-attestation for efficient batch operations
multi_attestation_requests = [
    {
        "schema_uid": "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef12",
        "attestations": [
            {
                "recipient": "0x5678901234abcdef5678901234abcdef56789012",
                "data": b"first attestation data",
                "expiration_time": int(time.time()) + 86400  # 1 day from now
            },
            {
                "recipient": "0x9012345678abcdef9012345678abcdef90123456",
                "data": b"second attestation data",
                "revocable": False
            }
        ]
    }
]

result = eas.multi_attest(multi_attestation_requests)
print(f"Multi-attestation transaction: {result.tx_hash}")
```

#### Off-chain Revocation

```python
# Create off-chain revocation with optional reason
revocation = eas.revoke_offchain(
    attestation_uid="0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890ab",
    reason="Incorrect information provided"
)

# Save revocation to file
eas.save_to_file(revocation, "revocation.json")

# The revocation includes signature and can be verified off-chain
print(f"Revocation UID: {revocation['uid']}")
print(f"Signature: {revocation['signature']}")
```

#### Error Handling Best Practices

```python
from EAS import EAS
from EAS.exceptions import EASValidationError, EASTransactionError

try:
    eas = EAS(
        rpc_url="https://mainnet.infura.io/v3/YOUR_PROJECT_ID",
        from_account="0x...",
        private_key="0x..."
    )
    
    # Attempt attestation with validation
    result = eas.onchain_attestation(
        schema="0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef12",
        recipient="0x5678901234abcdef5678901234abcdef56789012",
        data=b"attestation data"
    )
    
    print(f"Attestation successful: {result.tx_hash}")
    
except EASValidationError as e:
    print(f"Validation error: {e.message}")
    print(f"Invalid field: {e.field_name} = {e.field_value}")
    
except EASTransactionError as e:
    print(f"Transaction failed: {e.message}")
    print(f"Transaction hash: {e.tx_hash}")
    if e.receipt:
        print(f"Gas used: {e.receipt.get('gasUsed')}")
        
except Exception as e:
    print(f"Unexpected error: {e}")
```

## Examples

Check out the `examples/` directory for complete working examples:

- **`offchain_attestation_example.py`** - Create off-chain attestations
- **`onchain_attestation_example.py`** - Create on-chain attestations  
- **`complete_example.py`** - Complete workflow with both types

```bash
# Setup environment variables
cp env.example .env
# Edit .env with your actual values

# Run an example
python examples/complete_example.py
```

See [examples/README.md](examples/README.md) for detailed usage instructions.

## Command Line Interface

The EAS SDK provides a beautiful command-line interface for querying schema and attestation data using the EAS GraphQL API. This approach doesn't require RPC connections or private keys for read operations.

**Features:**
- 🎨 **Beautiful Output**: Rich tables with colors and formatting
- 📊 **Multiple Formats**: EAS, JSON, and YAML with syntax highlighting
- 🌐 **Multi-Network Support**: Query across different Ethereum networks
- ⚡ **Fast**: Direct GraphQL API calls
- 🔒 **Secure**: No private keys required for read operations

### Module-based CLI

```bash
# Show schema information (defaults to mainnet)
python -m main.EAS show-schema 0x2d0c6308e44797efaad90e4d1402391da661cd884c453d32373d0aa088b66a01

# Show schema on specific network
python -m main.EAS show-schema 0x2d0c6308e44797efaad90e4d1402391da661cd884c453d32373d0aa088b66a01 --network base-sepolia

# Show schema in different formats
python -m main.EAS show-schema 0x2d0c6308e44797efaad90e4d1402391da661cd884c453d32373d0aa088b66a01 --format json
python -m main.EAS show-schema 0x2d0c6308e44797efaad90e4d1402391da661cd884c453d32373d0aa088b66a01 --format yaml

# Show attestation information
python -m main.EAS show-attestation 0x12b4b8b2090f9bbde32db55cfc8e40ab7bda4512f6d8517226e9a9109fc9f8ed --network base-sepolia

# Generate code from schema definition
python -m main.EAS generate-schema 0x2d0c6308e44797efaad90e4d1402391da661cd884c453d32373d0aa088b66a01 --format proto

### Installable CLI Tool

After installation, you can use the `eas-tools` command:

```bash
# Install the package
pip install -e .

# Use the CLI tool
eas-tools show-schema 0x2d0c6308e44797efaad90e4d1402391da661cd884c453d32373d0aa088b66a01
eas-tools show-schema 0x2d0c6308e44797efaad90e4d1402391da661cd884c453d32373d0aa088b66a01 --network base-sepolia
eas-tools show-schema 0x2d0c6308e44797efaad90e4d1402391da661cd884c453d32373d0aa088b66a01 --format yaml
eas-tools show-attestation 0x12b4b8b2090f9bbde32db55cfc8e40ab7bda4512f6d8517226e9a9109fc9f8ed --network base-sepolia
```

### Available Commands

- `show-schema <uid>` - Display schema information with beautiful tables
- `show-attestation <uid>` - Display attestation information with rich formatting
- `generate-schema <uid>` - Generate code from EAS schema definition
- `encode-schema <attestation_uid>` - Retrieve attestation data and encode it using schema-based encoding

### Supported Networks

- `mainnet` - Ethereum mainnet
- `sepolia` - Sepolia testnet  
- `base-sepolia` - Base Sepolia testnet
- `optimism` - Optimism
- `arbitrum` - Arbitrum
- `base` - Base
- `polygon` - Polygon

### Output Formats

- `eas` (default) - Beautiful Rich tables with colors and formatting
- `json` - JSON with syntax highlighting and line numbers
- `yaml` - YAML with syntax highlighting and line numbers
- `proto` - Protocol Buffer message definitions (for generate-schema only)

### Examples

```bash
# Beautiful table output (default) - Schema
eas-tools show-schema 0x2d0c6308e44797efaad90e4d1402391da661cd884c453d32373d0aa088b66a01 --network base-sepolia

# JSON with syntax highlighting - Schema
eas-tools show-schema 0x2d0c6308e44797efaad90e4d1402391da661cd884c453d32373d0aa088b66a01 --format json

# Beautiful table output - Attestation
eas-tools show-attestation 0x12b4b8b2090f9bbde32db55cfc8e40ab7bda4512f6d8517226e9a9109fc9f8ed --network base-sepolia

# YAML with syntax highlighting - Attestation
eas-tools show-attestation 0x12b4b8b2090f9bbde32db55cfc8e40ab7bda4512f6d8517226e9a9109fc9f8ed --format yaml

# Generate code from schema definition - EAS format
eas-tools generate-schema 0x2d0c6308e44797efaad90e4d1402391da661cd884c453d32373d0aa088b66a01 --network base-sepolia

# Generate protobuf message from schema
eas-tools generate-schema 0x2d0c6308e44797efaad90e4d1402391da661cd884c453d32373d0aa088b66a01 --format proto

# Note: Complex types with fixed dimensions are not supported in protobuf
# eas-tools generate-schema 0x0081196516957509db14e998fa4191dd2d7e0c9a21377214806b3fbb8566f4c1 --format proto
# Error: Protobuf generation does not support complex types with fixed dimensions. 
# Unsupported fields: polygonArea (int40[2][]). 
# Consider using 'eas', 'json', or 'yaml' format instead.

# Retrieve and encode attestation data as JSON
eas-tools encode-schema 0x12b4b8b2090f9bbde32db55cfc8e40ab7bda4512f6d8517226e9a9109fc9f8ed --format-type json --output-format json --network base-sepolia

# Retrieve and encode attestation data as YAML
eas-tools encode-schema 0x12b4b8b2090f9bbde32db55cfc8e40ab7bda4512f6d8517226e9a9109fc9f8ed --format-type yaml --output-format yaml --network base-sepolia

# Retrieve and encode attestation data using protobuf (requires generated protobuf classes)
eas-tools encode-schema 0x12b4b8b2090f9bbde32db55cfc8e40ab7bda4512f6d8517226e9a9109fc9f8ed --format-type protobuf --output-format base64 --network base-sepolia

## Schema Generator

The SDK includes a powerful schema generator that can convert EAS schema definitions into various code formats:

### Supported EAS Field Types

- **Basic Types**: `address`, `string`, `bool`, `bytes32`, `bytes`
- **Integer Types**: `uint8` to `uint256` (step by 8), `int8` to `int256` (step by 8)
- **Array Support**: All types can be arrays (e.g., `address[]`, `uint256[]`)
- **Nested Arrays**: Complex arrays like `int40[2][]` are supported

### Generated Output Formats

- **EAS Format**: Newline-separated field definitions
- **JSON Format**: Structured field information with metadata
- **YAML Format**: Human-readable field definitions
- **Protobuf Format**: Protocol Buffer message definitions with proper type mapping

### Type Mapping

The generator automatically maps EAS types to appropriate protobuf types:
- `address` → `string`
- `uint8-uint32` → `uint32`
- `uint40-uint256` → `uint64`
- `int8-int32` → `int32`
- `int40-int256` → `int64`
- `bytes32`, `bytes` → `bytes`
- Simple arrays use the `repeated` keyword

**Protobuf Limitations:**
- Fixed-size arrays (e.g., `int40[2]`, `uint256[10]`) are **not supported** in protobuf format
- Complex types with fixed dimensions will raise an error with a helpful message
- Use `eas`, `json`, or `yaml` format for schemas with complex types

## Schema Encoder

The SDK includes a schema encoder that can encode data using various formats based on EAS schema definitions:

### Supported Encoding Types

- **Protobuf**: Uses generated protobuf classes for type-safe encoding
- **JSON**: Simple JSON encoding with validation
- **YAML**: YAML encoding with validation

### Output Formats

- **binary**: Raw binary data (displayed as hex)
- **base64**: Base64-encoded string
- **hex**: Hexadecimal string
- **json**: JSON string representation
- **yaml**: YAML string representation

### Protobuf Type Resolution

For protobuf encoding, the encoder can resolve types using:
- **Namespace**: `--namespace vendor.v1` (defaults to `vendor.v1`)
- **Message Type**: `--message-type vendor.v1.message_0x1234` (for custom message names)

### Usage Examples

```bash
# Encode data as JSON
eas-tools encode-schema <schema_uid> '{"field1": "value1", "field2": 42}' --format-type json --output-format json

# Encode data as YAML
eas-tools encode-schema <schema_uid> '{"field1": "value1", "field2": 42}' --format-type yaml --output-format yaml

# Encode data using protobuf with default namespace
eas-tools encode-schema <schema_uid> '{"field1": "value1", "field2": 42}' --format-type protobuf --output-format base64

# Encode data using protobuf with custom namespace
eas-tools encode-schema <schema_uid> '{"field1": "value1", "field2": 42}' --format-type protobuf --namespace mycompany.v1 --output-format hex

# Encode data using protobuf with custom message type
eas-tools encode-schema <schema_uid> '{"field1": "value1", "field2": 42}' --format-type protobuf --message-type mycompany.v1.CustomMessage --output-format json
```

## Protocol Buffers

The SDK includes generated Protocol Buffer definitions for EAS GraphQL API responses, providing type safety and validation for all API interactions.

### Generated Files

- `src/proto/eas/v1/messages.proto` - Protobuf definitions for EAS messages
- `src/main/EAS/generated/eas/v1/messages_pb2.py` - Generated Python protobuf classes
- `src/main/EAS/proto_helpers.py` - Helper functions for JSON ↔ Protobuf conversion

### Message Types

- **Schema**: Complete schema information with all fields
- **Attestation**: Full attestation data including metadata
- **GraphQLResponse**: Wrapper for GraphQL API responses
- **GraphQLError**: Error handling for GraphQL responses

### Usage

```python
from main.EAS.proto_helpers import parse_graphql_response

# Parse GraphQL response through protobuf for type safety
parsed_data = parse_graphql_response(json_response, "schema")
if parsed_data:
    print(f"Schema ID: {parsed_data['id']}")
    print(f"Creator: {parsed_data['creator']}")
```

## Development

### Setup

1. Clone the repository
2. Install dependencies:
   ```bash
   pip install -e ".[dev]"
   ```

### Regenerating Protobuf Files

If you modify the protobuf definitions, regenerate the Python files:

```bash
# Install grpcio-tools if not already installed
pip install grpcio-tools

# Generate Python protobuf files
python -m grpc_tools.protoc \
    --python_out=src/main/EAS/generated \
    --grpc_python_out=src/main/EAS/generated \
    --proto_path=src/proto \
    src/proto/eas/v1/messages.proto
```

### Running Tests

```bash
pytest
```

### Code Formatting

```bash
black src/
isort src/
```

## Environment Variables

The SDK supports configuration through environment variables. See `env.example` for all available options:

### Required Variables
- `PRIVATE_KEY` - Your wallet's private key (without 0x prefix)
- `FROM_ACCOUNT` - Your wallet's public address

### Optional Variables
- `NETWORK` - Network to use (mainnet, sepolia, goerli) - defaults to sepolia
- `RPC_URL` - Custom RPC URL (overrides network defaults)
- `CONTRACT_ADDRESS` - Custom EAS contract address
- `CHAIN_ID` - Custom chain ID
- `EXAMPLE_SCHEMA` - Example schema UID for testing
- `EXAMPLE_RECIPIENT` - Example recipient address for testing

### Security Notes
- **Never commit your `.env` file** to version control
- Keep your private key secure and never share it
- Use test networks (sepolia, goerli) for testing
- Only use mainnet when ready for production

## License

MIT License - see LICENSE file for details. 