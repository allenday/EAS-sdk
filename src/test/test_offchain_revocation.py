"""
Tests for EAS SDK off-chain revocation operations.

Demonstrates comprehensive testing of off-chain revocation functionality
including EIP-712 signing, validation, and data structures.
"""
import pytest
import time
from unittest.mock import Mock, patch, MagicMock

from main.EAS.core import EAS
from main.EAS.exceptions import EASValidationError, EASTransactionError

from .test_utils import (
    requires_private_key, requires_network, has_private_key,
    mock_private_key, mock_address, mock_tx_hash, mock_schema_uid, mock_attestation_uid
)


class TestOffchainRevocation:
    """Unit tests for off-chain revocation functionality."""
    
    @patch('main.EAS.core.web3.Web3')
    @patch('builtins.open', new_callable=lambda: mock_file_content('[]'))
    def test_revoke_offchain_validation(self, mock_open, mock_web3_class):
        """Test off-chain revocation input validation."""
        mock_w3 = Mock()
        mock_web3_class.return_value = mock_w3
        mock_w3.is_connected.return_value = True
        
        eas = EAS("http://test", "0x1234", 1, "0.26", "0xabcd", "deadbeef" * 8)
        
        # Test invalid UID format
        with pytest.raises(EASValidationError, match="Invalid attestation UID format"):
            eas.revoke_offchain("")
        
        with pytest.raises(EASValidationError, match="Invalid attestation UID format"):
            eas.revoke_offchain("invalid-uid")
    
    @patch('main.EAS.core.web3.Web3')
    @patch('builtins.open', new_callable=lambda: mock_file_content('[]'))
    def test_get_offchain_revocation_uid_version_0(self, mock_open, mock_web3_class):
        """Test off-chain revocation UID calculation for version 0."""
        mock_w3 = Mock()
        mock_web3_class.return_value = mock_w3
        mock_w3.is_connected.return_value = True
        mock_w3.keccak.return_value = b'mock_uid'
        
        eas = EAS("http://test", "0x1234", 1, "0.26", "0xabcd", "deadbeef" * 8)
        
        message = {
            "version": 0,
            "schema": "0x0000000000000000000000000000000000000000",
            "uid": "0xtest",
            "value": 0,
            "time": 1234567890,
            "salt": "0xsalt"
        }
        
        uid = eas.get_offchain_revocation_uid(message, version=0)
        
        assert uid == b'mock_uid'
        mock_w3.keccak.assert_called_once()
    
    @patch('main.EAS.core.web3.Web3')
    @patch('builtins.open', new_callable=lambda: mock_file_content('[]'))
    def test_get_offchain_revocation_uid_version_1(self, mock_open, mock_web3_class):
        """Test off-chain revocation UID calculation for version 1 - currently blocked by EIP-712 issues."""
        mock_w3 = Mock()
        mock_web3_class.return_value = mock_w3
        mock_w3.is_connected.return_value = True
        
        eas = EAS("http://test", "0x1234", 1, "0.26", "0xabcd", "deadbeef" * 8)
        
        message = {
            "version": 1,
            "schema": "0x0000000000000000000000000000000000000000",
            "uid": "0xtest",
            "value": 0,
            "time": 1234567890,
            "salt": "0xsalt"
        }
        
        # Should raise NotImplementedError until EIP-712 is fixed (issue #11)
        with pytest.raises(NotImplementedError, match="EIP-712 implementation blocked"):
            eas.get_offchain_revocation_uid(message, version=1)
    
    @patch('main.EAS.core.web3.Web3')
    @patch('builtins.open', new_callable=lambda: mock_file_content('[]'))
    def test_get_offchain_revocation_uid_invalid_version(self, mock_open, mock_web3_class):
        """Test off-chain revocation UID calculation with invalid version."""
        mock_w3 = Mock()
        mock_web3_class.return_value = mock_w3
        mock_w3.is_connected.return_value = True
        
        eas = EAS("http://test", "0x1234", 1, "0.26", "0xabcd", "deadbeef" * 8)
        
        message = {"uid": "0xtest"}
        
        with pytest.raises(ValueError, match="Unsupported off-chain revocation UID version: 99"):
            eas.get_offchain_revocation_uid(message, version=99)
    
    @patch('main.EAS.core.web3.Web3')
    @patch('builtins.open', new_callable=lambda: mock_file_content('[]'))
    @patch('main.EAS.core.os.urandom')
    @patch('main.EAS.core.time.time')
    def test_revoke_offchain_success(self, mock_time, mock_urandom, mock_open, mock_web3_class):
        """Test off-chain revocation - currently blocked by EIP-712 implementation issues."""
        # Setup mocks
        mock_w3 = Mock()
        mock_web3_class.return_value = mock_w3
        mock_w3.is_connected.return_value = True
        
        mock_time.return_value = 1234567890
        mock_urandom.return_value = b'salt_bytes_32_length_salt_bytes'
        
        eas = EAS("http://test", "0x1234", 1, "0.26", "0xabcd", "deadbeef" * 8)
        
        # Should raise EASTransactionError wrapping the NotImplementedError
        with pytest.raises(EASTransactionError, match="Off-chain revocation failed.*EIP-712 implementation blocked"):
            eas.revoke_offchain(
                attestation_uid="0xtest_attestation_uid",
                schema_uid="0xtest_schema_uid",
                value=100,
                reason="Test revocation"
            )
    
    @patch('main.EAS.core.web3.Web3')
    @patch('builtins.open', new_callable=lambda: mock_file_content('[]'))
    def test_revoke_offchain_default_parameters(self, mock_open, mock_web3_class):
        """Test off-chain revocation with default parameters - currently blocked by EIP-712 issues."""
        mock_w3 = Mock()
        mock_web3_class.return_value = mock_w3
        mock_w3.is_connected.return_value = True
        
        eas = EAS("http://test", "0x1234", 1, "0.26", "0xabcd", "deadbeef" * 8)
        
        # Should raise EASTransactionError wrapping the NotImplementedError
        with pytest.raises(EASTransactionError, match="Off-chain revocation failed.*EIP-712 implementation blocked"):
            eas.revoke_offchain("0xtest_attestation_uid")


@pytest.mark.integration
class TestOffchainRevocationIntegration:
    """Integration tests for off-chain revocation with network connectivity."""
    
    @requires_network
    @patch('main.EAS.core.web3.Web3')
    @patch('builtins.open', new_callable=lambda: mock_file_content('[]'))
    def test_offchain_revocation_structure(self, mock_open, mock_web3_class):
        """Test that off-chain revocation returns proper structure."""
        mock_w3 = Mock()
        mock_web3_class.return_value = mock_w3
        mock_w3.is_connected.return_value = True
        
        eas = EAS("http://test", "0x1234", 84532, "1.3.0", "0xabcd", "deadbeef" * 8)
        
        # Mock required methods for integration test
        with patch.object(eas, 'get_offchain_revocation_uid', return_value=b'mock_uid'):
            with patch('main.EAS.core.eip_712.eip712_encode', return_value=b'encoded_data'):
                with patch('main.EAS.core.eip_712.eip712_signature', return_value=b'r' * 32 + b's' * 32 + b'\x1c'):
                    with patch('main.EAS.core.os.urandom', return_value=b'salt' * 8):
                        with patch('main.EAS.core.time.time', return_value=1234567890):
                            
                            result = eas.revoke_offchain(
                                attestation_uid="0x" + "a" * 64,
                                reason="Integration test revocation"
                            )
                            
                            # Verify complete structure
                            assert isinstance(result, dict)
                            assert len(result['uid']) > 0
                            assert result['revoker'].startswith('0x')
                            
                            # Verify EIP-712 domain
                            domain = result['data']['domain']
                            assert domain['name'] == "EAS Attestation"
                            assert domain['version'] == "1.3.0"
                            assert domain['chainId'] == 84532
                            assert domain['verifyingContract'] == "0x1234"
                            
                            # Verify types structure
                            types = result['data']['types']
                            assert 'Revoke' in types
                            revoke_type = types['Revoke']
                            expected_fields = ['version', 'schema', 'uid', 'value', 'time', 'salt']
                            assert len(revoke_type) == len(expected_fields)
                            for field in revoke_type:
                                assert field['name'] in expected_fields
                                assert 'type' in field


@pytest.mark.live_write  
class TestLiveOffchainRevocation:
    """Live tests for off-chain revocation (requires real private key)."""
    
    @requires_private_key
    @requires_network
    def test_real_offchain_revocation(self):
        """Test off-chain revocation with real cryptographic operations."""
        assert has_private_key()
        
        import os
        rpc_url = os.getenv('RPC_URL', 'https://sepolia.base.org')
        contract_address = os.getenv('EAS_CONTRACT_ADDRESS', '0x4200000000000000000000000000000000000021')
        from_account = os.getenv('FROM_ACCOUNT')
        private_key = os.getenv('PRIVATE_KEY')
        
        # Create real EAS instance
        eas = EAS(rpc_url, contract_address, 84532, "1.3.0", from_account, private_key)
        
        # Use a mock attestation UID for testing
        test_attestation_uid = "0x" + "1234567890abcdef" * 8  # 64 hex chars
        test_reason = f"Test revocation - {time.time()}"
        
        try:
            result = eas.revoke_offchain(
                attestation_uid=test_attestation_uid,
                reason=test_reason
            )
            
            # Verify result structure
            assert isinstance(result, dict)
            assert 'revoker' in result
            assert 'uid' in result
            assert 'data' in result
            
            # Verify revoker matches our account
            assert result['revoker'] == from_account
            
            # Verify revocation UID was generated
            assert result['uid'].startswith('0x')
            assert len(result['uid']) == 66  # 0x + 64 hex chars
            
            # Verify data structure
            data = result['data']
            assert data['primaryType'] == 'Revoke'
            assert data['reason'] == test_reason
            
            # Verify message content
            message = data['message']
            assert message['uid'] == test_attestation_uid
            assert message['version'] == 1
            assert message['time'] > 0
            assert message['salt'].startswith('0x')
            
            # Verify signature exists and has proper format
            signature = data['signature']
            assert signature['r'].startswith('0x')
            assert signature['s'].startswith('0x')
            assert isinstance(signature['v'], int)
            assert len(signature['r']) == 66  # 0x + 64 hex chars
            assert len(signature['s']) == 66  # 0x + 64 hex chars
            
            print(f"✅ Off-chain revocation created successfully")
            print(f"   Revocation UID: {result['uid']}")
            print(f"   Attestation UID: {test_attestation_uid}")
            print(f"   Revoker: {result['revoker']}")
            print(f"   Reason: {test_reason}")
            print(f"   Signature valid: r={signature['r'][:10]}..., s={signature['s'][:10]}..., v={signature['v']}")
            
        except Exception as e:
            # Only skip if it's a network/infrastructure issue
            if "connection" in str(e).lower() or "timeout" in str(e).lower():
                pytest.skip(f"Off-chain revocation failed due to network conditions: {e}")
            else:
                raise


# Helper function to create mock file content for ABI loading
def mock_file_content(content='[]'):
    """Create mock file content for testing."""
    from unittest.mock import mock_open
    return mock_open(read_data=content)


if __name__ == "__main__":
    # Run unit tests by default
    pytest.main([__file__ + "::TestOffchainRevocation", "-v"])