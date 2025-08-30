"""
Basic observability utilities for EAS SDK operations.

Provides structured logging and operation timing for debugging and monitoring
without over-engineering the solution.
"""
import time
import functools
from typing import Any, Dict, Optional
import structlog

# Configure structlog for EAS SDK
structlog.configure(
    processors=[
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.JSONRenderer()
    ],
    context_class=dict,
    logger_factory=structlog.stdlib.LoggerFactory(),
    wrapper_class=structlog.stdlib.BoundLogger,
    cache_logger_on_first_use=True,
)

logger = structlog.get_logger("eas_sdk")


def log_operation(operation_name: str):
    """Decorator to log operation start, completion, and errors with timing."""
    
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            start_time = time.time()
            operation_id = f"{operation_name}_{int(start_time)}"
            
            # Log operation start
            logger.info(
                "operation_started",
                operation=operation_name,
                operation_id=operation_id
            )
            
            try:
                result = func(*args, **kwargs)
                duration = time.time() - start_time
                
                # Log successful completion
                log_data = {
                    "operation": operation_name,
                    "operation_id": operation_id,
                    "duration_seconds": round(duration, 3),
                    "success": True
                }
                
                # Add transaction details if result has them
                if hasattr(result, 'tx_hash'):
                    log_data["tx_hash"] = result.tx_hash
                if hasattr(result, 'gas_used') and result.gas_used:
                    log_data["gas_used"] = result.gas_used
                if hasattr(result, 'block_number') and result.block_number:
                    log_data["block_number"] = result.block_number
                
                logger.info("operation_completed", **log_data)
                return result
                
            except Exception as e:
                duration = time.time() - start_time
                
                # Log operation failure
                log_data = {
                    "operation": operation_name,
                    "operation_id": operation_id,
                    "duration_seconds": round(duration, 3),
                    "success": False,
                    "error": str(e),
                    "error_type": type(e).__name__
                }
                
                # Add error context if available
                if hasattr(e, 'context') and e.context:
                    log_data.update(e.context)
                
                logger.error("operation_failed", **log_data)
                raise
                
        return wrapper
    return decorator


def log_transaction_metrics(tx_result, operation: str, context: Optional[Dict[str, Any]] = None):
    """Log transaction metrics for monitoring and analysis."""
    
    log_data = {
        "operation": operation,
        "tx_hash": tx_result.tx_hash,
        "success": tx_result.success,
    }
    
    if tx_result.gas_used:
        log_data["gas_used"] = tx_result.gas_used
    
    if tx_result.block_number:
        log_data["block_number"] = tx_result.block_number
    
    if context:
        log_data.update(context)
    
    if tx_result.error:
        log_data["error"] = str(tx_result.error)
        log_data["error_type"] = type(tx_result.error).__name__
    
    if tx_result.success:
        logger.info("transaction_success", **log_data)
    else:
        logger.error("transaction_failure", **log_data)


def get_logger(name: str = "eas_sdk"):
    """Get a configured structlog logger for EAS SDK operations."""
    return structlog.get_logger(name)