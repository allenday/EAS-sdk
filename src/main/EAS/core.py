import json
import time
import os
from typing import List, Dict, Any, Optional, Union
from eth_abi import encode
from eth_abi.packed import encode_packed
from eth_defi import eip_712
import web3
from eth_account import Account

from .exceptions import EASError, EASValidationError, EASTransactionError
from .transaction import TransactionResult
from .observability import log_operation, get_logger
from .schema_registry import SchemaRegistry

logger = get_logger("eas_core")


class EAS:

    ZERO_ADDRESS = '0x0000000000000000000000000000000000000000'

    def __init__(self, rpc_url, contract_address, chain_id, contract_version, from_account, private_key):
        self.w3 = web3.Web3(web3.HTTPProvider(rpc_url))
        if not self.w3.is_connected():
            raise Exception("Failed to connect to Ethereum network")
        
        self.contract_address = contract_address
        self.chain_id = chain_id
        self.contract_version = contract_version
        self.from_account = from_account
        self.private_key = private_key

        # Load the ABI files
        eas_abi_path = os.path.join(os.path.dirname(__file__), 'contracts', 'eas-abi.json')
        try:
            with open(eas_abi_path, 'r') as eas_abi_file:
                eas_abi = json.load(eas_abi_file)
        except FileNotFoundError:
            eas_abi = []

        # Create contract instances
        self.easContract = self.w3.eth.contract(address=contract_address, abi=eas_abi)

    def get_attestation(self, uid):
        """Get an attestation by UID."""
        try:
            attestation = self.easContract.functions.getAttestation(uid).call()
            return attestation
        except Exception as e:
            raise Exception(f"Failed to get attestation: {str(e)}")
    
    def get_schema(self, schema_uid):
        """Get a schema by its UID."""
        try:
            schema = self.easContract.functions.getSchema(schema_uid).call()
            return schema
        except Exception as e:
            raise Exception(f"Failed to get schema: {str(e)}")

    def get_offchain_uid(self, message, version=1):
        """Calculate the UID for an off-chain attestation message."""
        if version == 0:
            # Version 0 uses direct keccak
            message_bytes = json.dumps(message).encode('utf-8')
            return self.w3.keccak(message_bytes)
        elif version == 1:
            # Version 1 uses EIP-712 structured data hashing
            domain = {
                "name": "EAS Attestation",
                "version": self.contract_version,
                "chainId": self.chain_id,
                "verifyingContract": self.contract_address
            }

            types = {
                "Attest": [
                    {"name": "version", "type": "uint16"},
                    {"name": "schema", "type": "bytes32"},
                    {"name": "recipient", "type": "address"},
                    {"name": "time", "type": "uint64"},
                    {"name": "expirationTime", "type": "uint64"},
                    {"name": "revocable", "type": "bool"},
                    {"name": "refUID", "type": "bytes32"},
                    {"name": "data", "type": "bytes"},
                    {"name": "salt", "type": "bytes32"}
                ]
            }

            signed_message = eip_712.encode_typed_data(
                domain_data=domain,
                message_types=types,
                message_data=message
            )

            return self.w3.keccak(signed_message)
        else:
            raise ValueError(f"Unsupported off-chain UID version: {version}")

    def attest_offchain(self, message):
        """Create an off-chain attestation."""
        # Calculate UID for the message
        message['uid'] = self.get_offchain_uid(message).hex()
        
        # Sign the message
        signature = self.w3.eth.account.sign_message(
            text=json.dumps(message, sort_keys=True),
            private_key=self.private_key
        )
        
        # Create the final attestation with signature
        offchain_attestation = {
            'message': message,
            'signature': {
                'r': signature.r,
                's': signature.s,
                'v': signature.v
            }
        }
        
        return offchain_attestation

    def attest(self, schema_uid, recipient, data_values=None, expiration=0, revocable=True, ref_uid=None):
        """Create an on-chain attestation."""
        # Encode the data
        encoded_data = b''
        if data_values:
            try:
                encoded_data = encode(data_values['types'], data_values['values'])
            except Exception as e:
                raise Exception(f"Failed to encode attestation data: {str(e)}")
        
        # Prepare attestation request
        attestation_request_data = (
            recipient,
            expiration,
            revocable, 
            ref_uid or self.ZERO_ADDRESS,
            encoded_data,
            0  # No value sent
        )
        attestation_request = (schema_uid, attestation_request_data)
        
        # Gas estimation
        gas_estimate = self.easContract.functions.attest(attestation_request).estimate_gas()
        
        # Create a transaction dictionary
        transaction = self.easContract.functions.attest(attestation_request).build_transaction({
            'from': self.from_account,
            'gas': gas_estimate,
            'nonce': self.w3.eth.get_transaction_count(self.from_account)
        })
        # Sign the transaction
        signed_transaction = self.w3.eth.account.sign_transaction(transaction, self.private_key)
        # Send the transaction
        tx_hash = self.w3.eth.send_raw_transaction(signed_transaction.rawTransaction)
        # Get the transaction receipt
        receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)
        return receipt

    def __init_schema_registry(self, network_name: str) -> SchemaRegistry:
        """Initialize schema registry for the current network."""
        try:
            registry_address = SchemaRegistry.get_registry_address(network_name)
            return SchemaRegistry(
                web3=self.w3,
                registry_address=registry_address,
                from_account=self.from_account,
                private_key=self.private_key
            )
        except Exception as e:
            raise EASTransactionError(f"Failed to initialize schema registry: {str(e)}")

    @log_operation("schema_registration")
    def register_schema(
        self,
        schema: str,
        network_name: str = "base-sepolia",
        resolver: Optional[str] = None,
        revocable: bool = True
    ) -> TransactionResult:
        """
        Register a new schema on-chain.
        
        Args:
            schema: Schema definition string (e.g., "uint256 id,string name")
            network_name: Network to register on (default: base-sepolia)
            resolver: Optional resolver contract address
            revocable: Whether attestations using this schema can be revoked
            
        Returns:
            TransactionResult with schema UID and transaction details
        """
        registry = self.__init_schema_registry(network_name)
        return registry.register_schema(schema, resolver, revocable)

    @log_operation("attestation_revocation")
    def revoke_attestation(self, uid: str) -> TransactionResult:
        """
        Revoke a single attestation by UID.
        
        Args:
            uid: Attestation UID to revoke
            
        Returns:
            TransactionResult with revocation transaction details
        """
        if not uid or not uid.startswith('0x'):
            raise EASValidationError("Invalid attestation UID format", field_name="uid", field_value=uid)
        
        logger.info("attestation_revocation_started", attestation_uid=uid)
        
        try:
            # Build revocation request
            revocation_request_data = (uid, 0)  # (uid, value)
            revocation_request = (bytes.fromhex(self.ZERO_ADDRESS[2:]), revocation_request_data)  # (schema, data)
            
            # Estimate gas
            gas_estimate = self.easContract.functions.revoke(revocation_request).estimate_gas({'from': self.from_account})
            gas_limit = int(gas_estimate * 1.2)  # 20% buffer
            
            # Build transaction
            transaction = self.easContract.functions.revoke(revocation_request).build_transaction({
                'from': self.from_account,
                'gas': gas_limit,
                'gasPrice': self.w3.eth.gas_price,
                'nonce': self.w3.eth.get_transaction_count(self.from_account)
            })
            
            # Sign transaction
            signed_txn = Account.sign_transaction(transaction, private_key=self.private_key)
            
            # Send transaction
            tx_hash = self.w3.eth.send_raw_transaction(signed_txn.rawTransaction)
            tx_hash_hex = tx_hash.hex()
            
            logger.info("attestation_revocation_submitted", tx_hash=tx_hash_hex, attestation_uid=uid)
            
            # Wait for confirmation
            receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)
            
            if receipt.get('status') != 1:
                return TransactionResult.failure_from_error(
                    tx_hash_hex,
                    EASTransactionError(f"Revocation transaction failed for UID {uid}", tx_hash_hex, receipt)
                )
            
            result = TransactionResult.success_from_receipt(tx_hash_hex, receipt)
            
            logger.info(
                "attestation_revocation_completed",
                tx_hash=tx_hash_hex,
                attestation_uid=uid,
                gas_used=receipt.get('gasUsed'),
                block_number=receipt.get('blockNumber')
            )
            
            return result
            
        except Exception as e:
            if isinstance(e, (EASValidationError, EASTransactionError)):
                raise
                
            logger.error("attestation_revocation_failed", attestation_uid=uid, error=str(e))
            raise EASTransactionError(f"Attestation revocation failed: {str(e)}")

    @log_operation("batch_revocation")
    def multi_revoke(self, revocations: List[Dict[str, Any]]) -> TransactionResult:
        """
        Revoke multiple attestations in a single transaction.
        
        Args:
            revocations: List of revocation requests, each containing 'uid' and optional 'value'
            
        Returns:
            TransactionResult with batch revocation transaction details
        """
        if not revocations:
            raise EASValidationError("Revocations list cannot be empty", field_name="revocations")
        
        logger.info("batch_revocation_started", revocation_count=len(revocations))
        
        try:
            # Build revocation requests
            revocation_requests = []
            for i, revocation in enumerate(revocations):
                uid = revocation.get('uid')
                value = revocation.get('value', 0)
                
                if not uid:
                    raise EASValidationError(f"Missing UID in revocation {i}", field_name=f"revocations[{i}].uid")
                
                # Each revocation needs (schema, RevocationRequestData)
                revocation_data = (uid, value)
                revocation_request = (bytes.fromhex(self.ZERO_ADDRESS[2:]), revocation_data)
                revocation_requests.append(revocation_request)
            
            # Estimate gas for batch operation
            gas_estimate = self.easContract.functions.multiRevoke(revocation_requests).estimate_gas({'from': self.from_account})
            gas_limit = int(gas_estimate * 1.2)  # 20% buffer
            
            # Build transaction
            transaction = self.easContract.functions.multiRevoke(revocation_requests).build_transaction({
                'from': self.from_account,
                'gas': gas_limit,
                'gasPrice': self.w3.eth.gas_price,
                'nonce': self.w3.eth.get_transaction_count(self.from_account)
            })
            
            # Sign transaction
            signed_txn = Account.sign_transaction(transaction, private_key=self.private_key)
            
            # Send transaction
            tx_hash = self.w3.eth.send_raw_transaction(signed_txn.rawTransaction)
            tx_hash_hex = tx_hash.hex()
            
            logger.info("batch_revocation_submitted", tx_hash=tx_hash_hex, revocation_count=len(revocations))
            
            # Wait for confirmation
            receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)
            
            if receipt.get('status') != 1:
                return TransactionResult.failure_from_error(
                    tx_hash_hex,
                    EASTransactionError(f"Batch revocation transaction failed", tx_hash_hex, receipt)
                )
            
            result = TransactionResult.success_from_receipt(tx_hash_hex, receipt)
            
            logger.info(
                "batch_revocation_completed",
                tx_hash=tx_hash_hex,
                revocation_count=len(revocations),
                gas_used=receipt.get('gasUsed'),
                block_number=receipt.get('blockNumber')
            )
            
            return result
            
        except Exception as e:
            if isinstance(e, (EASValidationError, EASTransactionError)):
                raise
                
            logger.error("batch_revocation_failed", revocation_count=len(revocations), error=str(e))
            raise EASTransactionError(f"Batch revocation failed: {str(e)}")

    @log_operation("attestation_creation")
    def create_attestation(
        self, 
        schema_uid: str, 
        recipient: str,
        encoded_data: bytes,
        expiration: int = 0,
        revocable: bool = True,
        ref_uid: str = None,
        value: int = 0
    ) -> TransactionResult:
        """
        Create a generic attestation with any schema and data.
        
        Args:
            schema_uid: The schema UID to attest against
            recipient: Address of the attestation recipient
            encoded_data: ABI-encoded data according to the schema
            expiration: Expiration timestamp (0 for no expiration)
            revocable: Whether the attestation can be revoked
            ref_uid: Reference to another attestation (optional)
            value: ETH value to send with attestation
            
        Returns:
            TransactionResult with attestation transaction details
        """
        if not schema_uid or not schema_uid.startswith('0x'):
            raise EASValidationError("Invalid schema UID format", field_name="schema_uid", field_value=schema_uid)
        
        if not recipient or not recipient.startswith('0x'):
            raise EASValidationError("Invalid recipient address format", field_name="recipient", field_value=recipient)
            
        if not encoded_data:
            raise EASValidationError("Encoded data cannot be empty", field_name="encoded_data")
        
        logger.info("attestation_creation_started", schema_uid=schema_uid, recipient=recipient)
        
        try:
            # Build attestation request
            attestation_request_data = (
                recipient,  # recipient
                expiration,  # expiration
                revocable,  # revocable
                ref_uid or self.ZERO_ADDRESS,  # refUID
                encoded_data,  # data
                value   # value
            )
            attestation_request = (schema_uid, attestation_request_data)
            
            # Estimate gas
            gas_estimate = self.easContract.functions.attest(attestation_request).estimate_gas({'from': self.from_account})
            gas_limit = int(gas_estimate * 1.2)  # 20% buffer
            
            # Build transaction
            transaction = self.easContract.functions.attest(attestation_request).build_transaction({
                'from': self.from_account,
                'gas': gas_limit,
                'gasPrice': self.w3.eth.gas_price,
                'nonce': self.w3.eth.get_transaction_count(self.from_account)
            })
            
            # Sign transaction
            signed_txn = Account.sign_transaction(transaction, private_key=self.private_key)
            
            # Send transaction
            tx_hash = self.w3.eth.send_raw_transaction(signed_txn.rawTransaction)
            tx_hash_hex = tx_hash.hex()
            
            logger.info("attestation_creation_submitted", tx_hash=tx_hash_hex, schema_uid=schema_uid, recipient=recipient)
            
            # Wait for confirmation
            receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)
            
            if receipt.get('status') != 1:
                return TransactionResult.failure_from_error(
                    tx_hash_hex,
                    EASTransactionError("Attestation creation transaction failed", tx_hash_hex, receipt)
                )
            
            result = TransactionResult.success_from_receipt(tx_hash_hex, receipt)
            
            logger.info(
                "attestation_creation_completed",
                tx_hash=tx_hash_hex,
                schema_uid=schema_uid,
                recipient=recipient,
                gas_used=receipt.get('gasUsed'),
                block_number=receipt.get('blockNumber')
            )
            
            return result
            
        except Exception as e:
            if isinstance(e, (EASValidationError, EASTransactionError)):
                raise
                
            logger.error("attestation_creation_failed", schema_uid=schema_uid, recipient=recipient, error=str(e))
            raise EASTransactionError(f"Attestation creation failed: {str(e)}")

    @log_operation("timestamping")
    def timestamp(self, data: Union[str, bytes]) -> TransactionResult:
        """
        Create a timestamp attestation using the contract's timestamp method.
        
        Args:
            data: Data to timestamp
            
        Returns:
            TransactionResult with timestamp transaction details
        """
        if not data:
            raise EASValidationError("Data cannot be empty", field_name="data")
        
        # Convert to bytes if string
        if isinstance(data, str):
            data_bytes = data.encode('utf-8')
        else:
            data_bytes = data
            
        logger.info("timestamping_started", data_length=len(data_bytes))
        
        try:
            # Call contract's timestamp method directly
            gas_estimate = self.easContract.functions.timestamp(data_bytes).estimate_gas({'from': self.from_account})
            gas_limit = int(gas_estimate * 1.2)  # 20% buffer
            
            # Build transaction
            transaction = self.easContract.functions.timestamp(data_bytes).build_transaction({
                'from': self.from_account,
                'gas': gas_limit,
                'gasPrice': self.w3.eth.gas_price,
                'nonce': self.w3.eth.get_transaction_count(self.from_account)
            })
            
            # Sign transaction
            signed_txn = Account.sign_transaction(transaction, private_key=self.private_key)
            
            # Send transaction
            tx_hash = self.w3.eth.send_raw_transaction(signed_txn.rawTransaction)
            tx_hash_hex = tx_hash.hex()
            
            logger.info("timestamping_submitted", tx_hash=tx_hash_hex, data_length=len(data_bytes))
            
            # Wait for confirmation
            receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)
            
            if receipt.get('status') != 1:
                return TransactionResult.failure_from_error(
                    tx_hash_hex,
                    EASTransactionError("Timestamp transaction failed", tx_hash_hex, receipt)
                )
            
            result = TransactionResult.success_from_receipt(tx_hash_hex, receipt)
            
            logger.info(
                "timestamping_completed",
                tx_hash=tx_hash_hex,
                data_length=len(data_bytes),
                gas_used=receipt.get('gasUsed'),
                block_number=receipt.get('blockNumber')
            )
            
            return result
            
        except Exception as e:
            if isinstance(e, (EASValidationError, EASTransactionError)):
                raise
                
            logger.error("timestamping_failed", data_length=len(data_bytes), error=str(e))
            raise EASTransactionError(f"Timestamping failed: {str(e)}")

    @log_operation("batch_timestamping")
    def multi_timestamp(self, data_items: List[Union[str, bytes]]) -> TransactionResult:
        """
        Create multiple timestamp attestations using the contract's multiTimestamp method.
        
        Args:
            data_items: List of data to timestamp
            
        Returns:
            TransactionResult with batch timestamp transaction details
        """
        if not data_items:
            raise EASValidationError("Data items list cannot be empty", field_name="data_items")
            
        for i, item in enumerate(data_items):
            if not item:
                raise EASValidationError(f"Data item {i} cannot be empty", field_name=f"data_items[{i}]")
        
        # Convert all items to bytes
        data_bytes_list = []
        for item in data_items:
            if isinstance(item, str):
                data_bytes_list.append(item.encode('utf-8'))
            else:
                data_bytes_list.append(item)
        
        logger.info("batch_timestamping_started", item_count=len(data_items))
        
        try:
            # Call contract's multiTimestamp method directly
            gas_estimate = self.easContract.functions.multiTimestamp(data_bytes_list).estimate_gas({'from': self.from_account})
            gas_limit = int(gas_estimate * 1.2)  # 20% buffer
            
            # Build transaction
            transaction = self.easContract.functions.multiTimestamp(data_bytes_list).build_transaction({
                'from': self.from_account,
                'gas': gas_limit,
                'gasPrice': self.w3.eth.gas_price,
                'nonce': self.w3.eth.get_transaction_count(self.from_account)
            })
            
            # Sign transaction
            signed_txn = Account.sign_transaction(transaction, private_key=self.private_key)
            
            # Send transaction
            tx_hash = self.w3.eth.send_raw_transaction(signed_txn.rawTransaction)
            tx_hash_hex = tx_hash.hex()
            
            logger.info("batch_timestamping_submitted", tx_hash=tx_hash_hex, item_count=len(data_items))
            
            # Wait for confirmation
            receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)
            
            if receipt.get('status') != 1:
                return TransactionResult.failure_from_error(
                    tx_hash_hex,
                    EASTransactionError("Batch timestamp transaction failed", tx_hash_hex, receipt)
                )
            
            result = TransactionResult.success_from_receipt(tx_hash_hex, receipt)
            
            logger.info(
                "batch_timestamping_completed",
                tx_hash=tx_hash_hex,
                item_count=len(data_items),
                gas_used=receipt.get('gasUsed'),
                block_number=receipt.get('blockNumber')
            )
            
            return result
            
        except Exception as e:
            if isinstance(e, (EASValidationError, EASTransactionError)):
                raise
                
            logger.error("batch_timestamping_failed", item_count=len(data_items), error=str(e))
            raise EASTransactionError(f"Batch timestamping failed: {str(e)}")