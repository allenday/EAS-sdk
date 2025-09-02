import pytest
import os
from unittest.mock import patch, MagicMock

# Import the EAS class and related modules
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from main.EAS.core import EAS
from main.EAS.config import get_network_config, list_supported_chains, get_mainnet_chains, get_testnet_chains


class TestMultiChainSupport:
    """Comprehensive test suite for multi-chain support functionality"""

    @pytest.fixture
    def mock_env_vars(self):
        """Fixture to manage environment variables during tests"""
        original_env = dict(os.environ)
        yield
        # Reset environment variables after test
        os.environ.clear()
        os.environ.update(original_env)

    def test_list_supported_chains(self):
        """Test the list_supported_chains() function"""
        chains = list_supported_chains()
        
        # Basic validation
        assert len(chains) >= 12, "Should support at least 12 chains"
        assert "ethereum" in chains, "Ethereum should be in supported chains"
        assert "polygon" in chains, "Polygon should be in supported chains"

    def test_get_mainnet_chains(self):
        """Test retrieving mainnet chains"""
        mainnet_chains = get_mainnet_chains()
        
        assert len(mainnet_chains) > 0, "Should have at least one mainnet chain"
        for chain in mainnet_chains:
            config = get_network_config(chain)
            assert config.get('is_testnet', False) is False, f"{chain} should be a mainnet chain"

    def test_get_testnet_chains(self):
        """Test retrieving testnet chains"""
        testnet_chains = get_testnet_chains()
        
        assert len(testnet_chains) > 0, "Should have at least one testnet chain"
        for chain in testnet_chains:
            config = get_network_config(chain)
            assert config.get('is_testnet', False) is True, f"{chain} should be a testnet chain"

    def test_get_network_config_valid_chains(self):
        """Test network configuration retrieval for all supported chains"""
        for chain in list_supported_chains():
            config = get_network_config(chain)
            
            # Common configuration validation
            assert 'rpc_url' in config, f"RPC URL missing for {chain}"
            assert 'contract_address' in config, f"Contract address missing for {chain}"
            assert 'chain_id' in config, f"Chain ID missing for {chain}"
            assert 'contract_version' in config, f"Contract version missing for {chain}"

    def test_get_network_config_invalid_chain(self):
        """Test error handling for unsupported chain names"""
        with pytest.raises(ValueError, match="Unsupported chain"):
            get_network_config("non_existent_chain")

    @patch('main.EAS.core.web3.Web3')
    def test_eas_from_chain_valid_chain(self, mock_web3_class):
        """Test EAS.from_chain() with valid chain names"""
        # Mock web3 connection
        mock_w3 = MagicMock()
        mock_w3.is_connected.return_value = True
        mock_web3_class.return_value = mock_w3

        # Test supported chains
        supported_chains = ["ethereum", "polygon", "arbitrum", "optimism"]
        
        for chain in supported_chains:
            eas = EAS.from_chain(chain)
            
            # Validate basic properties
            assert eas.chain_id is not None
            assert eas.contract_address is not None
            assert eas.rpc_url is not None

    @patch('main.EAS.core.web3.Web3')
    def test_eas_from_chain_with_overrides(self, mock_web3_class):
        """Test EAS.from_chain() with custom RPC URL and contract address"""
        # Mock web3 connection
        mock_w3 = MagicMock()
        mock_w3.is_connected.return_value = True
        mock_web3_class.return_value = mock_w3

        # Custom override parameters
        custom_rpc = "https://custom-rpc.example.com"
        custom_contract = "0x1234567890123456789012345678901234567890"
        
        eas = EAS.from_chain("ethereum", 
                              rpc_url=custom_rpc, 
                              contract_address=custom_contract)
        
        assert eas.rpc_url == custom_rpc
        assert eas.contract_address == custom_contract

    def test_eas_from_chain_invalid_chain(self):
        """Test EAS.from_chain() with invalid chain name"""
        with pytest.raises(ValueError, match="Unsupported chain"):
            EAS.from_chain("non_existent_chain")

    def test_eas_from_environment(self, mock_env_vars):
        """Test EAS.from_environment() parsing"""
        # Set environment variables
        os.environ['EAS_CHAIN'] = 'polygon'
        os.environ['EAS_PRIVATE_KEY'] = '0x1234567890123456789012345678901234567890123456789012345678901234'
        os.environ['EAS_FROM_ACCOUNT'] = '0x1234567890123456789012345678901234567890'

        with patch('main.EAS.core.web3.Web3'):
            eas = EAS.from_environment()
            
            assert eas.chain_id is not None
            assert eas.from_account == os.environ['EAS_FROM_ACCOUNT']

    def test_eas_from_environment_missing_vars(self, mock_env_vars):
        """Test EAS.from_environment() with missing required variables"""
        # Clear all EAS-related environment variables
        for var in ['EAS_CHAIN', 'EAS_PRIVATE_KEY', 'EAS_FROM_ACCOUNT']:
            os.environ.pop(var, None)

        with pytest.raises(ValueError, match="Missing required environment variables"):
            EAS.from_environment()

    def test_backward_compatibility_factory_method(self):
        """Test that original create_eas_instance() works with new multi-chain support"""
        from main.EAS.core import create_eas_instance

        # Test with legacy network names
        legacy_networks = ['mainnet', 'goerli', 'sepolia']
        
        for network in legacy_networks:
            eas = create_eas_instance(network)
            
            assert eas.chain_id is not None
            assert eas.contract_address is not None

    def test_multiple_eas_instances(self):
        """Test creating multiple EAS instances for different chains"""
        chains_to_test = ["ethereum", "polygon", "arbitrum"]
        
        eas_instances = {}
        for chain in chains_to_test:
            eas_instances[chain] = EAS.from_chain(chain)
        
        # Verify unique chain IDs and contract addresses
        chain_ids = {eas.chain_id for eas in eas_instances.values()}
        contract_addresses = {eas.contract_address for eas in eas_instances.values()}
        
        assert len(chain_ids) == len(chains_to_test), "Each chain should have a unique chain ID"
        assert len(contract_addresses) == len(chains_to_test), "Each chain should have a unique contract address"

    @patch('main.EAS.core.web3.Web3')
    def test_performance_factory_methods(self, mock_web3_class):
        """Verify performance of factory methods"""
        import time

        # Mock web3 connection
        mock_w3 = MagicMock()
        mock_w3.is_connected.return_value = True
        mock_web3_class.return_value = mock_w3

        # Measure initialization time
        start_time = time.time()
        eas = EAS.from_chain("ethereum")
        from_chain_time = time.time() - start_time

        start_time = time.time()
        eas_env = EAS.from_environment()
        from_env_time = time.time() - start_time

        # Assert reasonable initialization times (less than 0.5 seconds)
        assert from_chain_time < 0.5, f"from_chain() initialization too slow: {from_chain_time} seconds"
        assert from_env_time < 0.5, f"from_environment() initialization too slow: {from_env_time} seconds"