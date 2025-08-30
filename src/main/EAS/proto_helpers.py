"""
Helper functions for converting between GraphQL JSON responses and protobuf messages.
"""

import json
from typing import Dict, Any, Optional

from .generated.eas.v1.messages_pb2 import Schema, Attestation, SchemaResponse, AttestationResponse


def json_to_schema(json_data: Dict[str, Any]) -> Schema:
    """
    Convert a GraphQL JSON schema response to a protobuf Schema message.
    
    Args:
        json_data: Dictionary containing schema data from GraphQL API
        
    Returns:
        Schema protobuf message
    """
    return Schema(
        id=json_data.get("id", ""),
        schema=json_data.get("schema", ""),
        creator=json_data.get("creator", ""),
        resolver=json_data.get("resolver", ""),
        revocable=json_data.get("revocable", False),
        index=json_data.get("index", ""),
        txid=json_data.get("txid", ""),
        time=json_data.get("time", 0),
    )


def json_to_attestation(json_data: Dict[str, Any]) -> Attestation:
    """
    Convert a GraphQL JSON attestation response to a protobuf Attestation message.
    
    Args:
        json_data: Dictionary containing attestation data from GraphQL API
        
    Returns:
        Attestation protobuf message
    """
    return Attestation(
        id=json_data.get("id", ""),
        schema_id=json_data.get("schemaId", ""),
        attester=json_data.get("attester", ""),
        recipient=json_data.get("recipient", ""),
        time=json_data.get("time", 0),
        expiration_time=json_data.get("expirationTime", 0),
        revocable=json_data.get("revocable", False),
        revoked=json_data.get("revoked", False),
        data=json_data.get("data", ""),
        txid=json_data.get("txid", ""),
        time_created=json_data.get("timeCreated", 0),
        revocation_time=json_data.get("revocationTime", 0),
        ref_uid=json_data.get("refUID", ""),
        ipfs_hash=json_data.get("ipfsHash", ""),
        is_offchain=json_data.get("isOffchain", False),
    )


def schema_to_dict(schema: Schema) -> Dict[str, Any]:
    """
    Convert a protobuf Schema message to a dictionary.
    
    Args:
        schema: Schema protobuf message
        
    Returns:
        Dictionary representation of the schema
    """
    return {
        "id": schema.id,
        "schema": schema.schema,
        "creator": schema.creator,
        "resolver": schema.resolver,
        "revocable": schema.revocable,
        "index": schema.index,
        "txid": schema.txid,
        "time": schema.time,
    }


def attestation_to_dict(attestation: Attestation) -> Dict[str, Any]:
    """
    Convert a protobuf Attestation message to a dictionary.
    
    Args:
        attestation: Attestation protobuf message
        
    Returns:
        Dictionary representation of the attestation
    """
    return {
        "id": attestation.id,
        "schemaId": attestation.schema_id,
        "attester": attestation.attester,
        "recipient": attestation.recipient,
        "time": attestation.time,
        "expirationTime": attestation.expiration_time,
        "revocable": attestation.revocable,
        "revoked": attestation.revoked,
        "data": attestation.data,
        "txid": attestation.txid,
        "timeCreated": attestation.time_created,
        "revocationTime": attestation.revocation_time,
        "refUID": attestation.ref_uid,
        "ipfsHash": attestation.ipfs_hash,
        "isOffchain": attestation.is_offchain,
    }


def parse_graphql_response(response_text: str, response_type: str) -> Optional[Dict[str, Any]]:
    """
    Parse a GraphQL response and convert to protobuf message.
    
    Args:
        response_text: JSON string response from GraphQL API
        response_type: Either 'schema' or 'attestation'
        
    Returns:
        Dictionary representation of the parsed data, or None if parsing failed
    """
    try:
        response_data = json.loads(response_text)
        
        if "errors" in response_data:
            return None
            
        data = response_data.get("data", {})
        
        if response_type == "schema":
            schema_data = data.get("schema")
            if schema_data:
                return schema_to_dict(json_to_schema(schema_data))
        elif response_type == "attestation":
            attestation_data = data.get("attestation")
            if attestation_data:
                return attestation_to_dict(json_to_attestation(attestation_data))
                
        return None
    except (json.JSONDecodeError, KeyError, TypeError):
        return None 