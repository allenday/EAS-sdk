"""
Tests for the foundation modules (exceptions, transaction wrapper, observability).

Demonstrates proper use of test markers and conditional skipping.
"""
import pytest
import os
from unittest.mock import Mock, patch

from main.EAS.exceptions import (
    EASError, EASValidationError, EASTransactionError, 
    EASNetworkError, EASContractError
)
from main.EAS.transaction import TransactionResult
from main.EAS.observability import log_operation, get_logger

from .test_utils import requires_private_key, requires_network, has_private_key


class TestExceptions:
    """Unit tests for structured exception hierarchy."""
    
    def test_base_eas_error(self):
        """Test base EAS error with context."""
        context = {'operation': 'test', 'value': 123}
        error = EASError("Test error", context)
        
        assert str(error) == "Test error"
        assert error.context == context
    
    def test_validation_error(self):
        """Test validation error with field context."""
        error = EASValidationError("Invalid address", field_name="recipient", field_value="0xinvalid")
        
        assert "Invalid address" in str(error)
        assert error.context['field_name'] == "recipient"
        # Security: field_value is now sanitized for security (short addresses become [ADDR_TOO_SHORT])
        assert error.context['field_value'] == "[ADDR_TOO_SHORT]"
    
    def test_transaction_error(self):
        """Test transaction error with blockchain context."""
        tx_hash = "0x123456"
        receipt = {'gasUsed': 50000, 'blockNumber': 12345}
        
        error = EASTransactionError("Transaction failed", tx_hash=tx_hash, receipt=receipt)
        
        assert error.context['tx_hash'] == tx_hash
        assert error.context['gas_used'] == 50000
        assert error.context['block_number'] == 12345


class TestTransactionResult:
    """Unit tests for transaction result wrapper."""
    
    def test_success_result_creation(self):
        """Test creating successful transaction result."""
        tx_hash = "0xabcdef"
        receipt = {'gasUsed': 75000, 'blockNumber': 54321, 'status': 1}
        
        result = TransactionResult.success_from_receipt(tx_hash, receipt)
        
        assert result.success is True
        assert result.tx_hash == tx_hash
        assert result.gas_used == 75000
        assert result.block_number == 54321
    
    def test_failure_result_creation(self):
        """Test creating failed transaction result."""
        tx_hash = "0xfailed"
        error = Exception("Transaction reverted")
        
        result = TransactionResult.failure_from_error(tx_hash, error)
        
        assert result.success is False
        assert result.tx_hash == tx_hash
        assert result.error == error
    
    def test_to_dict_serialization(self):
        """Test transaction result serialization."""
        result = TransactionResult(
            success=True,
            tx_hash="0x123",
            gas_used=50000,
            block_number=12345
        )
        
        data = result.to_dict()
        
        assert data['success'] is True
        assert data['tx_hash'] == "0x123"
        assert data['gas_used'] == 50000
        assert data['block_number'] == 12345


class TestObservability:
    """Unit tests for observability utilities."""
    
    def test_logger_creation(self):
        """Test structured logger creation."""
        logger = get_logger("test_logger")
        assert logger is not None
    
    def test_log_operation_decorator_success(self, caplog):
        """Test operation logging decorator for successful operations."""
        @log_operation("test_operation")
        def successful_function():
            return "success"
        
        result = successful_function()
        
        assert result == "success"
        # Note: structlog output may not appear in caplog, but function should complete
    
    def test_log_operation_decorator_failure(self):
        """Test operation logging decorator for failed operations."""
        @log_operation("test_operation") 
        def failing_function():
            raise ValueError("Test error")
        
        with pytest.raises(ValueError, match="Test error"):
            failing_function()


@pytest.mark.integration
class TestFoundationIntegration:
    """Integration tests for foundation components working together."""
    
    @requires_network
    def test_network_error_with_logging(self):
        """Test network error handling with observability."""
        rpc_url = os.getenv('RPC_URL', 'https://sepolia.base.org')
        
        error = EASNetworkError(
            "Failed to connect", 
            rpc_url=rpc_url, 
            network_name="base-sepolia"
        )
        
        assert error.context['rpc_url'] == rpc_url
        assert error.context['network_name'] == "base-sepolia"
    
    def test_transaction_error_context_preservation(self):
        """Test that transaction errors preserve full context."""
        tx_hash = "0x" + "a" * 64
        receipt = {
            'gasUsed': 100000,
            'blockNumber': 98765,
            'status': 0,  # Failed transaction
            'logs': []
        }
        
        error = EASTransactionError("Smart contract execution failed", tx_hash=tx_hash, receipt=receipt)
        result = TransactionResult.failure_from_error(tx_hash, error)
        
        # Verify context is preserved through the error chain
        assert result.error == error
        assert error.context['tx_hash'] == tx_hash
        assert error.context['gas_used'] == 100000


@pytest.mark.live_write
class TestLiveWriteOperations:
    """Tests that require real private keys and perform blockchain writes."""
    
    @requires_private_key
    def test_private_key_availability(self):
        """Test that private key is available for live write tests."""
        # This test only runs if PRIVATE_KEY is set to a non-default value
        assert has_private_key()
        private_key = os.getenv('PRIVATE_KEY')
        assert private_key != '1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef'
        # Private key should be 64 hex chars, optionally prefixed with 0x
        clean_key = private_key.replace('0x', '') if private_key.startswith('0x') else private_key
        assert len(clean_key) == 64  # 32 bytes hex encoded
    
    @requires_private_key 
    @requires_network
    def test_transaction_result_with_real_receipt(self):
        """Test transaction result creation with real blockchain receipt format."""
        # This would be filled in when we have actual transaction functionality
        pytest.skip("Will be implemented when transaction functionality is added")


# Test runner helpers for different test categories
def run_unit_tests():
    """Run only unit tests (no network, no private key required)."""
    return pytest.main([
        "src/test/test_foundation.py::TestExceptions",
        "src/test/test_foundation.py::TestTransactionResult", 
        "src/test/test_foundation.py::TestObservability",
        "-v"
    ])


def run_integration_tests():
    """Run integration tests (network required, but no private key)."""
    return pytest.main([
        "src/test/",
        "-m", "integration and not live_write",
        "-v"
    ])


def run_live_write_tests():
    """Run live write tests (requires private key and network)."""
    return pytest.main([
        "src/test/",
        "-m", "live_write",
        "-v"
    ])


if __name__ == "__main__":
    # Run unit tests by default
    run_unit_tests()