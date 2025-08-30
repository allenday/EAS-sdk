# EAS v1 proto package
from . import messages_pb2
from . import messages_pb2_grpc

# Import the main message classes for easy access
from .messages_pb2 import (
    Schema,
    Attestation,
    SchemaResponse,
    AttestationResponse,
    GraphQLError,
    GraphQLResponse,
)

__all__ = [
    "messages_pb2",
    "messages_pb2_grpc",
    "Schema",
    "Attestation", 
    "SchemaResponse",
    "AttestationResponse",
    "GraphQLError",
    "GraphQLResponse",
] 