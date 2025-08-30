import json
import time
import os
from eth_abi import encode
from eth_abi.packed import encode_packed
from eth_defi import eip_712
import web3

from .exceptions import EASError, EASValidationError, EASTransactionError
from .transaction import TransactionResult
from .observability import log_operation, get_logger

logger = get_logger("eas_core")


class EAS:

    ZERO_ADDRESS = '0x0000000000000000000000000000000000000000'

    def __init__(self, rpc_url, contract_address, chain_id, contract_version, from_account, private_key):
        self.w3 = web3.Web3(web3.HTTPProvider(rpc_url))
        if not self.w3.is_connected():
            raise Exception("Failed to connect to Ethereum network")
        
        # Load ABI from the package data
        abi_path = os.path.join(os.path.dirname(__file__), "contracts", "eas-abi.json")
        with open(abi_path, 'r') as f:
            abi = json.load(f)
        
        self.easContract = self.w3.eth.contract(address=contract_address, abi=abi)
        self.from_account = from_account
        self.private_key = private_key
        self.chain_id = chain_id
        self.contract_version = contract_version

    def _solidity_packed_keccak256(self, types, values):
        packed_data = encode_packed(types, values)
        return self.w3.keccak(packed_data)

    def get_offchain_uid(self, version, schema, recipient, time, expiration_time, revocable, ref_uid, data):
        if version == 0:
            uid = self._solidity_packed_keccak256(
                ['bytes32', 'address', 'address', 'uint64', 'uint64', 'bool', 'bytes32', 'bytes', 'uint32'],
                [bytes(schema, 'utf-8'), recipient, self.ZERO_ADDRESS, time, expiration_time, revocable, bytes.fromhex(ref_uid[2:]), data, 0]
            )
            return uid.hex()

        elif version == 1:
            uid = self._solidity_packed_keccak256(
                ['uint16', 'bytes', 'address', 'address', 'uint64', 'uint64', 'bool', 'bytes32', 'bytes', 'uint32'],
                [version, bytes(schema, 'utf-8'), recipient, self.ZERO_ADDRESS, time, expiration_time, revocable, bytes.fromhex(ref_uid[2:]), data, 0]
            )
            return uid.hex()

        else:
            raise ValueError('Unsupported version')

    def offchain_attestation(self, schema, recipient, expiration, revocable, refUID, data):
        domain = {
            "name": "EAS Attestation",
            "version": self.contract_version,
            "chainId": self.chain_id,
            "verifyingContract": self.easContract.address
        }
        unixTime = int(time.time())
        message = {
            "version": 1,
            "schema": schema,
            "recipient": recipient,
            "time": unixTime,
            "expirationTime": expiration,
            "refUID": refUID,
            "revocable": revocable,
            "data": "0x" + data.hex(),
            "nonce": 0
        }
        types = {
            "EIP712Domain": [
                {"name": "name", "type": "string"},
                {"name": "version", "type": "string"},
                {"name": "chainId", "type": "uint256"},
                {"name": "verifyingContract", "type": "address"}
            ],
            "Attest": [
                {"name": "version", "type": "uint16"},
                {"name": "schema", "type": "bytes32"},
                {"name": "recipient", "type": "address"},
                {"name": "time", "type": "uint64"},
                {"name": "expirationTime", "type": "uint64"},
                {"name": "revocable", "type": "bool"},
                {"name": "refUID", "type": "bytes32"},
                {"name": "data", "type": "bytes"}
            ]
        }
        typed_data = {
            'types': types,
            'primaryType': 'Attest',
            'domain': domain,
            'message': message
        }
        # Get encoded data and its hash
        encoded_data = eip_712.eip712_encode(typed_data)
        encoded_data_hash = eip_712.eip712_encode_hash(typed_data)
        # Sign the data
        signature = eip_712.eip712_signature(encoded_data, self.private_key)
        r = self.w3.to_hex(signature[:32])
        s = self.w3.to_hex(signature[32:64])
        v = signature[64]
        # Build the final object
        final_object = {
            "signer": self.from_account,
            "sig": {
                "domain": domain,
                "primaryType": "Attest",
                "types": types,
                "signature": {
                    "r": r,
                    "s": s,
                    "v": v
                },
                "uid": self.get_offchain_uid(1, schema, recipient, unixTime, expiration, revocable, refUID, data),
                "message": message
            }
        }
        return final_object

    def save_to_file(self, attestation_object, filename):
        with open(filename, 'w') as outfile:
            json.dump(attestation_object, outfile)
        return f"Saved to {filename}"

    def onchain_attestation(self, schema, recipient, expiration, revocable, refUID, data, value):
        attestation_request_data = (recipient, expiration, revocable, refUID, data, value)
        attestation_request = (schema, attestation_request_data)
        # Estimate gas
        gas_estimate = self.easContract.functions.attest(attestation_request).estimate_gas({'from': self.from_account})
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