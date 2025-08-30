"""
Configuration helper for EAS SDK with network configurations and example data.
"""

import os
from eth_abi import encode
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Network configurations
NETWORKS = {
    "mainnet": {
        "rpc_url": "https://mainnet.infura.io/v3/YOUR_PROJECT_ID",
        "contract_address": "0xA1207F3BBa224E2c9c3c6D5aF63D0eb1582Ce587",
        "chain_id": 1,
        "contract_version": "0.26",
        "name": "Ethereum Mainnet"
    },
    "sepolia": {
        "rpc_url": "https://sepolia.infura.io/v3/YOUR_PROJECT_ID",
        "contract_address": "0xC2679fBD37d54388Ce493F1DB75320D236e1815e",
        "chain_id": 11155111,
        "contract_version": "0.26",
        "name": "Sepolia Testnet"
    },
    "goerli": {
        "rpc_url": "https://goerli.infura.io/v3/YOUR_PROJECT_ID",
        "contract_address": "0xAcfE09Fd03f7812F022FBf636700AdEA18Fd2A7A",
        "chain_id": 5,
        "contract_version": "0.26",
        "name": "Goerli Testnet"
    }
}

# Example attestation data
EXAMPLE_ATTESTATION_DATA = {
    "schema": os.getenv("EXAMPLE_SCHEMA", "0xb7a45c9772f2fada6c02b9084b3e75217aa01a610e724eecd36aeb1a654a4c7e"),
    "recipient": os.getenv("EXAMPLE_RECIPIENT", "0x1e3de6aE412cA218FD2ae3379750388D414532dc"),
    "expiration": 0,  # 0 means no expiration
    "revocable": True,
    "refUID": "0x0000000000000000000000000000000000000000000000000000000000000000",
    "data": encode(
        ['bool', 'bytes32'],
        [True, bytes.fromhex("0x04b2d1a4a9b3a32f47b2f969479087bd2c16434fb9165759c9e420d7df391260"[2:])]
    ),
    "value": 0
}


def get_network_config(network_name: str) -> dict:
    """
    Get network configuration by name.
    
    Args:
        network_name: Name of the network (mainnet, sepolia, goerli)
        
    Returns:
        Network configuration dictionary
        
    Raises:
        ValueError: If network name is not supported
    """
    if network_name not in NETWORKS:
        raise ValueError(f"Unsupported network: {network_name}. Supported networks: {list(NETWORKS.keys())}")
    
    return NETWORKS[network_name].copy()


def get_example_attestation_data() -> dict:
    """
    Get example attestation data for testing.
    
    Returns:
        Dictionary with example attestation parameters
    """
    return EXAMPLE_ATTESTATION_DATA.copy()


def create_eas_instance(network_name: str = None, from_account: str = None, private_key: str = None, rpc_url: str = None):
    """
    Create an EAS instance with network configuration.
    
    Args:
        network_name: Name of the network (mainnet, sepolia, goerli). If None, uses NETWORK env var.
        from_account: Wallet address. If None, uses FROM_ACCOUNT env var.
        private_key: Private key for signing. If None, uses PRIVATE_KEY env var.
        rpc_url: Optional custom RPC URL (overrides network default). If None, uses RPC_URL env var.
        
    Returns:
        EAS instance configured for the specified network
        
    Raises:
        ValueError: If required environment variables are missing
    """
    from .core import EAS
    
    # Use environment variables if not provided
    network_name = network_name or os.getenv("NETWORK", "sepolia")
    from_account = from_account or os.getenv("FROM_ACCOUNT")
    private_key = private_key or os.getenv("PRIVATE_KEY")
    
    if not from_account:
        raise ValueError("FROM_ACCOUNT not provided and not found in environment variables")
    if not private_key:
        raise ValueError("PRIVATE_KEY not provided and not found in environment variables")
    
    config = get_network_config(network_name)
    
    # Override with environment variables or provided parameters
    if rpc_url:
        config["rpc_url"] = rpc_url
    elif os.getenv("RPC_URL"):
        config["rpc_url"] = os.getenv("RPC_URL")
    
    # Override contract address and chain ID if provided in environment
    if os.getenv("CONTRACT_ADDRESS"):
        config["contract_address"] = os.getenv("CONTRACT_ADDRESS")
    if os.getenv("CHAIN_ID"):
        config["chain_id"] = int(os.getenv("CHAIN_ID"))
    
    return EAS(
        rpc_url=config["rpc_url"],
        contract_address=config["contract_address"],
        chain_id=config["chain_id"],
        contract_version=config["contract_version"],
        from_account=from_account,
        private_key=private_key
    ) 