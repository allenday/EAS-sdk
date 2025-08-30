"""
Parser for EAS attestation data according to schema definitions.
"""

import re
from typing import Dict, Any, List, Union
from web3 import Web3

from .type_parser import EASTypeParser, EASField, EASType


def parse_attestation_data(data_hex: str, schema_definition: str) -> Dict[str, Any]:
    """
    Parse attestation data according to schema definition.
    
    Args:
        data_hex: Hex-encoded attestation data
        schema_definition: EAS schema definition string
        
    Returns:
        Dictionary containing parsed field values
    """
    # Parse the schema definition to get field information
    fields = EASTypeParser.parse_schema_definition(schema_definition)
    
    # Remove '0x' prefix if present
    if data_hex.startswith('0x'):
        data_hex = data_hex[2:]
    
    # Convert hex to bytes
    data_bytes = bytes.fromhex(data_hex)
    
    # Parse the data according to the schema
    result = {}
    offset = 0
    
    for field in fields:
        field_name = field.name
        field_type = field.type
        
        # Parse the field value based on its type
        value, new_offset = parse_field_value(data_bytes, offset, field_type)
        result[field_name] = value
        offset = new_offset
    
    return result


def parse_field_value(data_bytes: bytes, offset: int, field_type: EASType) -> tuple[Any, int]:
    """
    Parse a single field value from bytes.
    
    Args:
        data_bytes: Raw data bytes
        offset: Current offset in bytes
        field_type: EAS type information
        
    Returns:
        Tuple of (parsed_value, new_offset)
    """
    base_type = field_type.base_type
    is_array = field_type.is_array
    dimensions = field_type.dimensions
    
    # Handle different base types
    if base_type == "address":
        if is_array:
            return parse_address_array(data_bytes, offset, dimensions)
        else:
            return parse_address(data_bytes, offset)
    
    elif base_type == "string":
        if is_array:
            return parse_string_array(data_bytes, offset, dimensions)
        else:
            return parse_string(data_bytes, offset)
    
    elif base_type == "bool":
        if is_array:
            return parse_bool_array(data_bytes, offset, dimensions)
        else:
            return parse_bool(data_bytes, offset)
    
    elif base_type.startswith("uint") or base_type.startswith("int"):
        if is_array:
            return parse_integer_array(data_bytes, offset, field_type, dimensions)
        else:
            return parse_integer(data_bytes, offset, field_type)
    
    elif base_type.startswith("bytes"):
        if is_array:
            return parse_bytes_array(data_bytes, offset, field_type, dimensions)
        else:
            return parse_bytes(data_bytes, offset, field_type)
    
    else:
        raise ValueError(f"Unsupported field type: {base_type}")


def parse_address(data_bytes: bytes, offset: int) -> tuple[str, int]:
    """Parse an address field."""
    if offset + 32 > len(data_bytes):
        raise ValueError("Insufficient data for address")
    
    # Address is stored as 32 bytes, but only the last 20 bytes are used
    address_bytes = data_bytes[offset:offset + 32]
    address = Web3.to_checksum_address(address_bytes[-20:])
    return address, offset + 32


def parse_address_array(data_bytes: bytes, offset: int, dimensions: List[int]) -> tuple[List[str], int]:
    """Parse an address array field."""
    # For now, handle simple dynamic arrays
    if not dimensions and len(dimensions) == 0:
        # Dynamic array - first 32 bytes contain the offset to the array data
        array_offset = int.from_bytes(data_bytes[offset:offset + 32], 'big')
        
        # Read array length at the offset
        length = int.from_bytes(data_bytes[array_offset:array_offset + 32], 'big')
        
        addresses = []
        current_offset = array_offset + 32
        
        for _ in range(length):
            address, current_offset = parse_address(data_bytes, current_offset)
            addresses.append(address)
        
        return addresses, offset + 32
    
    else:
        # Fixed-size array
        addresses = []
        current_offset = offset
        
        for _ in range(dimensions[0]):
            address, current_offset = parse_address(data_bytes, current_offset)
            addresses.append(address)
        
        return addresses, current_offset


def parse_string(data_bytes: bytes, offset: int) -> tuple[str, int]:
    """Parse a string field."""
    if offset + 32 > len(data_bytes):
        raise ValueError("Insufficient data for string offset")
    
    # String is stored as offset to the actual string data
    string_offset = int.from_bytes(data_bytes[offset:offset + 32], 'big')
    
    # Read string length at the offset
    length = int.from_bytes(data_bytes[string_offset:string_offset + 32], 'big')
    
    # Read the actual string data
    string_data = data_bytes[string_offset + 32:string_offset + 32 + length]
    string_value = string_data.decode('utf-8')
    
    return string_value, offset + 32


def parse_string_array(data_bytes: bytes, offset: int, dimensions: List[int]) -> tuple[List[str], int]:
    """Parse a string array field."""
    # For now, handle simple dynamic arrays
    if not dimensions and len(dimensions) == 0:
        # Dynamic array - first 32 bytes contain the offset to the array data
        array_offset = int.from_bytes(data_bytes[offset:offset + 32], 'big')
        
        # Read array length at the offset
        length = int.from_bytes(data_bytes[array_offset:array_offset + 32], 'big')
        
        strings = []
        current_offset = array_offset + 32
        
        for _ in range(length):
            string, current_offset = parse_string(data_bytes, current_offset)
            strings.append(string)
        
        return strings, offset + 32
    
    else:
        # Fixed-size array
        strings = []
        current_offset = offset
        
        for _ in range(dimensions[0]):
            string, current_offset = parse_string(data_bytes, current_offset)
            strings.append(string)
        
        return strings, current_offset


def parse_bool(data_bytes: bytes, offset: int) -> tuple[bool, int]:
    """Parse a boolean field."""
    if offset + 32 > len(data_bytes):
        raise ValueError("Insufficient data for boolean")
    
    # Boolean is stored as 32 bytes, but only the last byte is used
    bool_bytes = data_bytes[offset:offset + 32]
    bool_value = bool(int.from_bytes(bool_bytes, 'big'))
    return bool_value, offset + 32


def parse_bool_array(data_bytes: bytes, offset: int, dimensions: List[int]) -> tuple[List[bool], int]:
    """Parse a boolean array field."""
    # For now, handle simple dynamic arrays
    if not dimensions and len(dimensions) == 0:
        # Dynamic array - first 32 bytes contain the offset to the array data
        array_offset = int.from_bytes(data_bytes[offset:offset + 32], 'big')
        
        # Read array length at the offset
        length = int.from_bytes(data_bytes[array_offset:array_offset + 32], 'big')
        
        bools = []
        current_offset = array_offset + 32
        
        for _ in range(length):
            bool_val, current_offset = parse_bool(data_bytes, current_offset)
            bools.append(bool_val)
        
        return bools, offset + 32
    
    else:
        # Fixed-size array
        bools = []
        current_offset = offset
        
        for _ in range(dimensions[0]):
            bool_val, current_offset = parse_bool(data_bytes, current_offset)
            bools.append(bool_val)
        
        return bools, current_offset


def parse_integer(data_bytes: bytes, offset: int, field_type: EASType) -> tuple[int, int]:
    """Parse an integer field."""
    base_type = field_type.base_type
    
    # Determine bit size from type name
    if base_type.startswith("uint"):
        bit_size = int(base_type[4:])
    elif base_type.startswith("int"):
        bit_size = int(base_type[3:])
    else:
        raise ValueError(f"Invalid integer type: {base_type}")
    
    # Calculate byte size (rounded up to nearest 32 bytes for ABI encoding)
    byte_size = 32
    
    if offset + byte_size > len(data_bytes):
        raise ValueError(f"Insufficient data for {base_type}")
    
    # Read the value
    value_bytes = data_bytes[offset:offset + byte_size]
    value = int.from_bytes(value_bytes, 'big')
    
    # Handle signed integers
    if base_type.startswith("int"):
        # Convert from two's complement if negative
        max_value = 2 ** (bit_size - 1)
        if value >= max_value:
            value = value - (2 ** bit_size)
    
    return value, offset + byte_size


def parse_integer_array(data_bytes: bytes, offset: int, field_type: EASType, dimensions: List[int]) -> tuple[List[int], int]:
    """Parse an integer array field."""
    # For now, handle simple dynamic arrays
    if not dimensions and len(dimensions) == 0:
        # Dynamic array - first 32 bytes contain the offset to the array data
        array_offset = int.from_bytes(data_bytes[offset:offset + 32], 'big')
        
        # Read array length at the offset
        length = int.from_bytes(data_bytes[array_offset:array_offset + 32], 'big')
        
        integers = []
        current_offset = array_offset + 32
        
        for _ in range(length):
            integer, current_offset = parse_integer(data_bytes, current_offset, field_type)
            integers.append(integer)
        
        return integers, offset + 32
    
    else:
        # Fixed-size array
        integers = []
        current_offset = offset
        
        for _ in range(dimensions[0]):
            integer, current_offset = parse_integer(data_bytes, current_offset, field_type)
            integers.append(integer)
        
        return integers, current_offset


def parse_bytes(data_bytes: bytes, offset: int, field_type: EASType) -> tuple[str, int]:
    """Parse a bytes field."""
    base_type = field_type.base_type
    
    if base_type == "bytes":
        # Dynamic bytes - first 32 bytes contain the offset to the actual data
        bytes_offset = int.from_bytes(data_bytes[offset:offset + 32], 'big')
        
        # Read bytes length at the offset
        length = int.from_bytes(data_bytes[bytes_offset:bytes_offset + 32], 'big')
        
        # Read the actual bytes data
        bytes_data = data_bytes[bytes_offset + 32:bytes_offset + 32 + length]
        return bytes_data.hex(), offset + 32
    
    else:
        # Fixed-size bytes (e.g., bytes32)
        # Extract size from type name
        match = re.match(r'bytes(\d+)', base_type)
        if not match:
            raise ValueError(f"Invalid bytes type: {base_type}")
        
        size = int(match.group(1))
        if offset + size > len(data_bytes):
            raise ValueError(f"Insufficient data for {base_type}")
        
        bytes_data = data_bytes[offset:offset + size]
        return bytes_data.hex(), offset + size


def parse_bytes_array(data_bytes: bytes, offset: int, field_type: EASType, dimensions: List[int]) -> tuple[List[str], int]:
    """Parse a bytes array field."""
    # For now, handle simple dynamic arrays
    if not dimensions and len(dimensions) == 0:
        # Dynamic array - first 32 bytes contain the offset to the array data
        array_offset = int.from_bytes(data_bytes[offset:offset + 32], 'big')
        
        # Read array length at the offset
        length = int.from_bytes(data_bytes[array_offset:array_offset + 32], 'big')
        
        bytes_list = []
        current_offset = array_offset + 32
        
        for _ in range(length):
            bytes_data, current_offset = parse_bytes(data_bytes, current_offset, field_type)
            bytes_list.append(bytes_data)
        
        return bytes_list, offset + 32
    
    else:
        # Fixed-size array
        bytes_list = []
        current_offset = offset
        
        for _ in range(dimensions[0]):
            bytes_data, current_offset = parse_bytes(data_bytes, current_offset, field_type)
            bytes_list.append(bytes_data)
        
        return bytes_list, current_offset 