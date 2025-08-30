# Generated protobuf files for EAS SDK
from .eas.v1 import messages_pb2
from .eas.v1 import messages_pb2_grpc

# Import the main message classes for easy access
from .eas.v1.messages_pb2 import (
    Schema,
    Attestation,
    SchemaResponse,
    AttestationResponse,
    GraphQLError,
    GraphQLResponse,
)

__all__ = [
    "eas.v1.messages_pb2",
    "eas.v1.messages_pb2_grpc",
    "Schema",
    "Attestation", 
    "SchemaResponse",
    "AttestationResponse",
    "GraphQLError",
    "GraphQLResponse",
] 