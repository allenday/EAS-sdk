### Advanced Configuration

#### Custom Networks and Factory Methods

```python
from EAS import EAS

# Use factory method with custom RPC endpoint
eas_custom = EAS.from_chain(
    chain="custom_network",
    private_key="1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
    from_account="0x0fB2FA8306F661E31C7BFE76a5fF3A3F85a9f9A2",
    rpc_url="https://custom-rpc.network",
    contract_address="0x4200000000000000000000000000000000000021",  # Custom EAS contract
    chain_id=42  # Custom network
)

# List available chains
all_chains = EAS.list_supported_chains()
print("Supported Chains:", all_chains)

# List mainnet chains
mainnet_chains = EAS.get_mainnet_chains()
print("Mainnet Chains:", mainnet_chains)

# Get network configuration for a specific chain
base_config = EAS.get_network_config("base")
print("Base Network Config:", base_config)
```