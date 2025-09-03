"""
Tests for proto_helpers module.
"""

import json

from main.EAS.proto_helpers import (
    attestation_to_dict,
    json_to_attestation,
    json_to_schema,
    parse_graphql_response,
    schema_to_dict,
)


class TestProtoHelpers:
    """Test cases for proto_helpers module."""

    def test_json_to_schema(self):
        """Test converting JSON schema data to protobuf Schema."""
        json_data = {
            "id": "0x1234567890abcdef",
            "schema": "string domain,string path",
            "creator": "0xabcdef1234567890",
            "resolver": "0x0000000000000000000000000000000000000000",
            "revocable": True,
            "index": "1234",
            "txid": "0x9876543210fedcba",
            "time": 1234567890,
        }

        schema = json_to_schema(json_data)

        assert schema.id == "0x1234567890abcdef"
        assert schema.schema == "string domain,string path"
        assert schema.creator == "0xabcdef1234567890"
        assert schema.resolver == "0x0000000000000000000000000000000000000000"
        assert schema.revocable is True
        assert schema.index == "1234"
        assert schema.txid == "0x9876543210fedcba"
        assert schema.time == 1234567890

    def test_json_to_attestation(self):
        """Test converting JSON attestation data to protobuf Attestation."""
        json_data = {
            "id": "0x1234567890abcdef",
            "schemaId": "0xabcdef1234567890",
            "attester": "0x1111111111111111",
            "recipient": "0x2222222222222222",
            "time": 1234567890,
            "expirationTime": 0,
            "revocable": True,
            "revoked": False,
            "data": "0x0000000000000000000000000000000000000000000000000000000000000000",
            "txid": "0x9876543210fedcba",
            "timeCreated": 1234567891,
            "revocationTime": 0,
            "refUID": "0x0000000000000000000000000000000000000000000000000000000000000000",
            "ipfsHash": "",
            "isOffchain": False,
        }

        attestation = json_to_attestation(json_data)

        assert attestation.id == "0x1234567890abcdef"
        assert attestation.schema_id == "0xabcdef1234567890"
        assert attestation.attester == "0x1111111111111111"
        assert attestation.recipient == "0x2222222222222222"
        assert attestation.time == 1234567890
        assert attestation.expiration_time == 0
        assert attestation.revocable is True
        assert attestation.revoked is False
        assert (
            attestation.data
            == "0x0000000000000000000000000000000000000000000000000000000000000000"
        )
        assert attestation.txid == "0x9876543210fedcba"
        assert attestation.time_created == 1234567891
        assert attestation.revocation_time == 0
        assert (
            attestation.ref_uid
            == "0x0000000000000000000000000000000000000000000000000000000000000000"
        )
        assert attestation.ipfs_hash == ""
        assert attestation.is_offchain is False

    def test_schema_to_dict(self):
        """Test converting protobuf Schema to dictionary."""
        from main.EAS.generated.eas.v1.messages_pb2 import Schema

        schema = Schema(
            id="0x1234567890abcdef",
            schema="string domain,string path",
            creator="0xabcdef1234567890",
            resolver="0x0000000000000000000000000000000000000000",
            revocable=True,
            index="1234",
            txid="0x9876543210fedcba",
            time=1234567890,
        )

        result = schema_to_dict(schema)

        assert result["id"] == "0x1234567890abcdef"
        assert result["schema"] == "string domain,string path"
        assert result["creator"] == "0xabcdef1234567890"
        assert result["resolver"] == "0x0000000000000000000000000000000000000000"
        assert result["revocable"] is True
        assert result["index"] == "1234"
        assert result["txid"] == "0x9876543210fedcba"
        assert result["time"] == 1234567890

    def test_attestation_to_dict(self):
        """Test converting protobuf Attestation to dictionary."""
        from main.EAS.generated.eas.v1.messages_pb2 import Attestation

        attestation = Attestation(
            id="0x1234567890abcdef",
            schema_id="0xabcdef1234567890",
            attester="0x1111111111111111",
            recipient="0x2222222222222222",
            time=1234567890,
            expiration_time=0,
            revocable=True,
            revoked=False,
            data="0x0000000000000000000000000000000000000000000000000000000000000000",
            txid="0x9876543210fedcba",
            time_created=1234567891,
            revocation_time=0,
            ref_uid="0x0000000000000000000000000000000000000000000000000000000000000000",
            ipfs_hash="",
            is_offchain=False,
        )

        result = attestation_to_dict(attestation)

        assert result["id"] == "0x1234567890abcdef"
        assert result["schemaId"] == "0xabcdef1234567890"
        assert result["attester"] == "0x1111111111111111"
        assert result["recipient"] == "0x2222222222222222"
        assert result["time"] == 1234567890
        assert result["expirationTime"] == 0
        assert result["revocable"] is True
        assert result["revoked"] is False
        assert (
            result["data"]
            == "0x0000000000000000000000000000000000000000000000000000000000000000"
        )
        assert result["txid"] == "0x9876543210fedcba"
        assert result["timeCreated"] == 1234567891
        assert result["revocationTime"] == 0
        assert (
            result["refUID"]
            == "0x0000000000000000000000000000000000000000000000000000000000000000"
        )
        assert result["ipfsHash"] == ""
        assert result["isOffchain"] is False

    def test_parse_graphql_response_schema(self):
        """Test parsing GraphQL schema response."""
        response = {
            "data": {
                "schema": {
                    "id": "0x1234567890abcdef",
                    "schema": "string domain,string path",
                    "creator": "0xabcdef1234567890",
                    "resolver": "0x0000000000000000000000000000000000000000",
                    "revocable": True,
                    "index": "1234",
                    "txid": "0x9876543210fedcba",
                    "time": 1234567890,
                }
            }
        }

        result = parse_graphql_response(json.dumps(response), "schema")

        assert result is not None
        assert result["id"] == "0x1234567890abcdef"
        assert result["schema"] == "string domain,string path"
        assert result["creator"] == "0xabcdef1234567890"

    def test_parse_graphql_response_attestation(self):
        """Test parsing GraphQL attestation response."""
        response = {
            "data": {
                "attestation": {
                    "id": "0x1234567890abcdef",
                    "schemaId": "0xabcdef1234567890",
                    "attester": "0x1111111111111111",
                    "recipient": "0x2222222222222222",
                    "time": 1234567890,
                    "expirationTime": 0,
                    "revocable": True,
                    "revoked": False,
                    "data": "0x0000000000000000000000000000000000000000000000000000000000000000",
                    "txid": "0x9876543210fedcba",
                    "timeCreated": 1234567891,
                    "revocationTime": 0,
                    "refUID": "0x0000000000000000000000000000000000000000000000000000000000000000",
                    "ipfsHash": "",
                    "isOffchain": False,
                }
            }
        }

        result = parse_graphql_response(json.dumps(response), "attestation")

        assert result is not None
        assert result["id"] == "0x1234567890abcdef"
        assert result["schemaId"] == "0xabcdef1234567890"
        assert result["attester"] == "0x1111111111111111"

    def test_parse_graphql_response_with_errors(self):
        """Test parsing GraphQL response with errors."""
        response = {"errors": [{"message": "Schema not found"}]}

        result = parse_graphql_response(json.dumps(response), "schema")
        assert result is None

    def test_parse_graphql_response_invalid_json(self):
        """Test parsing invalid JSON response."""
        result = parse_graphql_response("invalid json", "schema")
        assert result is None
