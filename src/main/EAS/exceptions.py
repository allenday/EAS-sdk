"""
Structured exception handling for EAS SDK operations.

Provides a clean error hierarchy for different types of failures,
enabling proper error handling and debugging context.
"""
from typing import Optional, Dict, Any


class EASError(Exception):
    """Base exception for all EAS SDK operations."""
    
    def __init__(self, message: str, context: Optional[Dict[str, Any]] = None):
        super().__init__(message)
        self.context = context or {}


class EASValidationError(EASError):
    """Input validation failures before blockchain operations."""
    
    def __init__(self, message: str, field_name: Optional[str] = None, field_value: Any = None):
        context = {}
        if field_name:
            context['field_name'] = field_name
        if field_value is not None:
            context['field_value'] = field_value
        super().__init__(message, context)


class EASTransactionError(EASError):
    """Blockchain transaction failures with transaction context."""
    
    def __init__(self, message: str, tx_hash: Optional[str] = None, receipt: Optional[dict] = None):
        context = {}
        if tx_hash:
            context['tx_hash'] = tx_hash
        if receipt:
            context['receipt'] = receipt
            context['gas_used'] = receipt.get('gasUsed')
            context['block_number'] = receipt.get('blockNumber')
        super().__init__(message, context)


class EASNetworkError(EASError):
    """RPC/network connectivity issues."""
    
    def __init__(self, message: str, rpc_url: Optional[str] = None, network_name: Optional[str] = None):
        context = {}
        if rpc_url:
            context['rpc_url'] = rpc_url
        if network_name:
            context['network_name'] = network_name
        super().__init__(message, context)


class EASContractError(EASError):
    """Smart contract interaction failures."""
    
    def __init__(self, message: str, contract_address: Optional[str] = None, method_name: Optional[str] = None):
        context = {}
        if contract_address:
            context['contract_address'] = contract_address
        if method_name:
            context['method_name'] = method_name
        super().__init__(message, context)