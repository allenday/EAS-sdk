"""
Test utilities for EAS SDK tests.

Provides utilities for conditional test skipping based on environment configuration
and helper functions for test setup.
"""
import os
import pytest
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()


def has_private_key() -> bool:
    """Check if a private key is available in environment variables or .env file."""
    private_key = os.getenv('PRIVATE_KEY', '').strip()
    # Check if it's not empty and not the default example value
    return bool(private_key and private_key != '1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef')


def has_network_config() -> bool:
    """Check if network configuration is available for testing."""
    return bool(os.getenv('RPC_URL') or os.getenv('NETWORK'))


def requires_private_key(func):
    """Decorator to skip tests that require a real private key for live write operations."""
    return pytest.mark.skipif(
        not has_private_key(),
        reason="Requires PRIVATE_KEY in environment or .env file for live write operations"
    )(func)


def requires_network(func):
    """Decorator to skip tests that require network connectivity."""
    return pytest.mark.skipif(
        not has_network_config(),
        reason="Requires network configuration (RPC_URL or NETWORK) for integration tests"
    )(func)


# Pytest fixtures for common test setup
@pytest.fixture
def mock_private_key():
    """Provide a mock private key for unit tests."""
    return "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"


@pytest.fixture
def mock_address():
    """Provide a mock Ethereum address for unit tests."""
    return "0x1234567890123456789012345678901234567890"


@pytest.fixture
def mock_tx_hash():
    """Provide a mock transaction hash for unit tests."""
    return "0xabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdef"


@pytest.fixture
def mock_schema_uid():
    """Provide a mock schema UID for unit tests."""
    return "0xb7a45c9772f2fada6c02b9084b3e75217aa01a610e724eecd36aeb1a654a4c7e"


@pytest.fixture
def mock_attestation_uid():
    """Provide a mock attestation UID for unit tests."""
    return "0x3564005984522b56de1b87c44e2164ddc0bf5fe2b9a374e18edbfc9d85131e53"