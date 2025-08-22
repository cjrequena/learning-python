import json
import struct
from typing import TypedDict


class BlockHeader(TypedDict):
    """Type definition for decoded block header data."""

    version: int
    previous_block_hash: str
    merkle_root: str
    timestamp: int
    bits: int
    nonce: int


class TransactionInput(TypedDict):
    """Type definition for decoded block tx input data."""

    previous_tx_hash: str
    previous_output_index: int
    script_sig: str
    script_sig_length: str
    sequence: str
    is_coinbase: bool


class TransactionOutput(TypedDict):
    """Type definition for decoded block transaction output data."""

    value_satoshi: int
    value_btc: float
    script_pubkey: str
    script_pubkey_length: int

class WitnessItem(TypedDict):
    """Type definition for a single witness item."""
    data: str
    length: int
    type: str
    description: str


class TransactionWitness(TypedDict):
    """Type definition for witness data of a single input."""
    input_index: int
    witness_count: int
    witness_items: list[WitnessItem]
    witness_type: str
    total_witness_size: int


# class BlockWitnessItem(TypedDict):
#     """Type definition for decoded block Witness Item."""
#
#     witness_item_length: int
#     witness_item: str


class BlockDecoder:
    """
    A comprehensive Bitcoin block decoder that handles both Legacy and SegWit transactions.
    Provides methods to decode block headers, block bodies, and complete blocks.
    """

    def __init__(self):
        """Initialize the Bitcoin block decoder."""
        pass

    # --------------------------------------------------------------------------------------------
    def decode_block_header(self, header: str) -> str:
        # Validate input
        match header:
            case str() if header.strip():
                header = header.strip().lower()
            case _:
                raise ValueError("Header must be a non-empty string")

        # Validate hex string length (80 bytes = 160 hex characters)
        if len(header) != 160:
            raise ValueError(
                f"Header must be exactly 160 hex characters, got {len(header)}"
            )

        # Validate hex string format and convert to bytes
        try:
            header_bytes = bytes.fromhex(header)
        except ValueError as e:
            raise ValueError(f"Invalid hex string: {e}") from e

        try:
            (version,) = struct.unpack("<I", header_bytes[0:4])
            previous_block_hash = header_bytes[4:36][::-1].hex()
            merkle_root = header_bytes[36:68][::-1].hex()
            (timestamp,) = struct.unpack("<I", header_bytes[68:72])
            (bits,) = struct.unpack("<I", header_bytes[72:76])
            (nonce,) = struct.unpack("<I", header_bytes[76:80])
        except ValueError as e:
            raise struct.error(f"Failed to unpack header data: {e}") from e

        block_header: BlockHeader = {
            "version": version,
            "previous_block_hash": previous_block_hash,
            "merkle_root": merkle_root,
            "timestamp": timestamp,
            "bits": bits,
            "nonce": nonce,
        }

        # Return JSON string
        return json.dumps(block_header, indent=4)

    # --------------------------------------------------------------------------------------------
    def decode_transaction_inputs_from_raw_tx(self, tx: str) -> tuple[list[TransactionInput], int]:
        """
        Decode and return the list of transaction inputs from a raw transaction hex string.

        """
        tx_bytes = bytes.fromhex(tx)
        offset = 0

        # Skip version (4 bytes)
        offset += 4

        # Check for SegWit marker + flag
        if tx_bytes[offset] == 0x00 and tx_bytes[offset + 1] == 0x01:
            offset += 2

        # Input count
        input_count, offset = self.decode_varint(tx_bytes, offset)

        inputs: list[TransactionInput] = []

        for _ in range(input_count):
            prev_tx_hash = tx_bytes[offset:offset + 32][::-1].hex()
            offset += 32

            prev_output_index = struct.unpack("<I", tx_bytes[offset:offset + 4])[0]
            offset += 4

            script_len, offset = self.decode_varint(tx_bytes, offset)

            script_sig = tx_bytes[offset:offset + script_len].hex()
            offset += script_len

            sequence = struct.unpack("<I", tx_bytes[offset:offset + 4])[0]
            offset += 4

            is_coinbase = (prev_tx_hash == "00" * 32 and prev_output_index == 0xFFFFFFFF)

            inputs.append({
                "previous_tx_hash": prev_tx_hash,
                "previous_output_index": prev_output_index,
                "script_sig": script_sig,
                "script_sig_length": hex(script_len),
                "sequence": hex(sequence),
                "is_coinbase": is_coinbase,
            })

        return inputs, offset


    # -------------------------------------------------------------------------------------------------
    def decode_transaction_outputs_from_raw_tx(self, tx: str, /) -> tuple[list[TransactionOutput], int]:
        """
        Decode and return the list of transaction outputs from a raw transaction hex string.

        Args:
            tx: Raw transaction as hexadecimal string

        Returns:
            List of decoded transaction outputs

        Raises:
            ValueError: If transaction format is invalid
            struct.error: If data cannot be unpacked
        """
        # Validate and convert input
        if not isinstance(tx, str) or not tx.strip():
            raise ValueError("Transaction must be a non-empty string")

        try:
            tx_bytes = bytes.fromhex(tx.strip())
        except ValueError as e:
            raise ValueError(f"Invalid hex string: {e}") from e

        if len(tx_bytes) < 10:  # Minimum transaction size
            raise ValueError("Transaction too short to be valid")

        offset = 0

        try:
            # Skip version (4 bytes)
            offset += 4

            # Check for SegWit marker + flag
            is_segwit = False
            if (offset + 1 < len(tx_bytes) and
                    tx_bytes[offset] == 0x00 and
                    tx_bytes[offset + 1] == 0x01):
                is_segwit = True
                offset += 2

            # Input count and skip inputs
            input_count, offset = self.decode_varint(tx_bytes, offset)

            # Skip all inputs
            for _ in range(input_count):
                # Skip previous tx hash (32 bytes) + output index (4 bytes)
                offset += 36

                # Skip script sig
                script_pubkey_length, offset = self.decode_varint(tx_bytes, offset)
                offset += script_pubkey_length

                # Skip sequence (4 bytes)
                offset += 4

            # Output count
            output_count, offset = self.decode_varint(tx_bytes, offset)

            outputs: list[TransactionOutput] = []

            for i in range(output_count):
                if offset + 8 > len(tx_bytes):
                    raise ValueError(f"Insufficient data for output {i} value")

                # Value (8 bytes, little-endian)
                value_satoshi = struct.unpack("<Q", tx_bytes[offset:offset + 8])[0]
                offset += 8

                # Script length and script
                script_pubkey_length, offset = self.decode_varint(tx_bytes, offset)

                if offset + script_pubkey_length > len(tx_bytes):
                    raise ValueError(f"Insufficient data for output {i} script")

                script_pubkey = tx_bytes[offset:offset + script_pubkey_length].hex()
                offset += script_pubkey_length

                block_tx_output: TransactionOutput = {
                    "value_satoshi": value_satoshi,
                    "value_btc": value_satoshi / 100000000.0,
                    "script_pubkey": script_pubkey,
                    "script_pubkey_length": script_pubkey_length
                }

                outputs.append(block_tx_output)

        except (struct.error, IndexError) as e:
            raise ValueError(f"Failed to decode transaction: {e}") from e

        return outputs, offset

    def decode_transaction_witnesses_from_raw_tx(self, tx: str, /) -> tuple [list[TransactionWitness], int]:
        """
        Decode and return the witness data from a raw SegWit transaction hex string.

        Args:
            tx: Raw transaction as hexadecimal string

        Returns:
            List of TransactionWitness for each input

        Raises:
            ValueError: If transaction format is invalid or not SegWit
            struct.error: If data cannot be unpacked
        """
        # Validate and convert input
        if not isinstance(tx, str) or not tx.strip():
            raise ValueError("Transaction must be a non-empty string")

        try:
            tx_bytes = bytes.fromhex(tx.strip())
        except ValueError as e:
            raise ValueError(f"Invalid hex string: {e}") from e

        if len(tx_bytes) < 10:  # Minimum transaction size
            raise ValueError("Transaction too short to be valid")

        offset = 0

        try:
            # Skip version (4 bytes)
            offset += 4

            # Check for SegWit marker + flag
            if not (offset + 1 < len(tx_bytes) and
                    tx_bytes[offset] == 0x00 and
                    tx_bytes[offset + 1] == 0x01):
                raise ValueError("Transaction is not SegWit format (no witness marker/flag)")

            offset += 2  # Skip marker and flag

            # Input count
            input_count, offset = self.decode_varint(tx_bytes, offset)

            # Skip all inputs
            for _ in range(input_count):
                # Skip previous tx hash (32 bytes) + output index (4 bytes)
                offset += 36

                # Skip script sig
                script_len, offset = self.decode_varint(tx_bytes, offset)
                offset += script_len

                # Skip sequence (4 bytes)
                offset += 4

            # Skip outputs
            output_count, offset = self.decode_varint(tx_bytes, offset)

            for _ in range(output_count):
                # Skip value (8 bytes)
                offset += 8

                # Skip script pubkey
                script_len, offset = self.decode_varint(tx_bytes, offset)
                offset += script_len

            # Now decode witness data
            witnesses: list[TransactionWitness] = []

            for input_index in range(input_count):
                # Number of witness items for this input
                witness_count, offset = self.decode_varint(tx_bytes, offset)

                witness_items: list[WitnessItem] = []
                total_witness_size = 0

                # Decode each witness item
                for item_index in range(witness_count):
                    # Length of this witness item
                    item_len, offset = self.decode_varint(tx_bytes, offset)

                    if offset + item_len > len(tx_bytes):
                        raise ValueError(f"Insufficient data for witness item {item_index} of input {input_index}")

                    # Extract witness item data
                    item_data = tx_bytes[offset:offset + item_len]
                    offset += item_len

                    # Analyze the witness item
                    witness_item = self.decode_witness_item(item_data, item_index, witness_count)
                    witness_items.append(witness_item)
                    total_witness_size += item_len

                # Determine witness type
                witness_type = self.determine_witness_type(witness_count, witness_items)

                witnesses.append(TransactionWitness(
                    input_index=input_index,
                    witness_count=witness_count,
                    witness_items=witness_items,
                    witness_type=witness_type,
                    total_witness_size=total_witness_size,
                ))

        except (struct.error, IndexError) as e:
            raise ValueError(f"Failed to decode transaction witnesses: {e}") from e

        return witnesses, offset

    #-------------------------------------------------------------------------------------------------
    def decode_witness_item(self, data: bytes, index: int, witness_count: int, /) -> WitnessItem:
        """
        Analyze a witness item to determine its type and purpose.

        Args:
            data: Raw witness item data
            index: Index of this item in the witness stack
            witness_count: Total number of witness items

        Returns:
            WitnessItem
        """
        hex_data = data.hex()
        length = len(data)

        # Empty witness item
        if length == 0:
            return WitnessItem(
                data="",
                length=0,
                type="EMPTY",
                description="Empty witness item"
            )

        # For P2WPKH (2 items: signature + pubkey)
        if witness_count == 2:
            if index == 0:
                # First item should be signature (typically 70-72 bytes with DER encoding + sighash)
                if 70 <= length <= 73:
                    sighash_type = data[-1] if length > 0 else 0
                    sighash_desc = self.get_sighash_description(sighash_type)
                    return WitnessItem(
                        data=hex_data,
                        length=length,
                        type="SIGNATURE",
                        description=f"ECDSA signature ({length} bytes) - {sighash_desc}"
                    )
                else:
                    return WitnessItem(
                        data=hex_data,
                        length=length,
                        type="SIGNATURE",
                        description=f"ECDSA signature ({length} bytes) - non-standard length"
                    )
            elif index == 1:
                # Second item should be public key (33 bytes compressed or 65 bytes uncompressed)
                if length == 33:
                    return WitnessItem(
                        data=hex_data,
                        length=length,
                        type="PUBLIC_KEY",
                        description="Compressed public key (33 bytes)"
                    )
                elif length == 65:
                    return WitnessItem(
                        data=hex_data,
                        length=length,
                        type="PUBLIC_KEY",
                        description="Uncompressed public key (65 bytes)"
                    )
                else:
                    return WitnessItem(
                        data=hex_data,
                        length=length,
                        type="PUBLIC_KEY",
                        description=f"Public key ({length} bytes) - non-standard length"
                    )

        # For P2WSH (multisig or script)
        elif witness_count > 2:
            if index == 0:
                # First item is typically empty for multisig due to OP_CHECKMULTISIG bug
                if length == 0:
                    return WitnessItem(
                        data=hex_data,
                        length=length,
                        type="EMPTY",
                        description="Empty item (OP_CHECKMULTISIG dummy)"
                    )
            elif index == witness_count - 1:
                # Last item is typically the redeem script
                return WitnessItem(
                    data=hex_data,
                    length=length,
                    type="REDEEM_SCRIPT",
                    description=f"Witness script/redeem script ({length} bytes)"
                )
            else:
                # Middle items are typically signatures
                if 70 <= length <= 73:
                    sighash_type = data[-1] if length > 0 else 0
                    sighash_desc = self.get_sighash_description(sighash_type)
                    return WitnessItem(
                        data=hex_data,
                        length=length,
                        type="SIGNATURE",
                        description=f"ECDSA signature ({length} bytes) - {sighash_desc}"
                    )
                else:
                    return WitnessItem(
                        data=hex_data,
                        length=length,
                        type="SIGNATURE",
                        description=f"ECDSA signature ({length} bytes) - non-standard length"
                    )

        # Single witness item (unusual)
        elif witness_count == 1:
            return WitnessItem(
                data=hex_data,
                length=length,
                type="UNKNOWN",
                description=f"Single witness item ({length} bytes) - possibly custom script"
            )

        # Default case
        return WitnessItem(
            data=hex_data,
            length=length,
            type="UNKNOWN",
            description=f"Unknown witness data ({length} bytes)"
        )

    #-------------------------------------------------------------------------------------------------
    @staticmethod
    def determine_witness_type(witness_count: int, witness_items: list[WitnessItem], /) -> str:
        """
        Determine the overall witness type based on witness items.

        Args:
            witness_count: Number of witness items
            witness_items: List of analyzed witness items

        Returns:
            String describing the witness type
        """
        match witness_count:
            case 0:
                return "NO_WITNESS"
            case 1:
                return "CUSTOM_SCRIPT"
            case 2:
                # P2WPKH pattern: signature + pubkey
                if (len(witness_items) == 2 and
                        witness_items[0].get("type") == "SIGNATURE" and
                        witness_items[1].get("type") == "PUBLIC_KEY"):
                    return "P2WPKH"
                else:
                    return "UNKNOWN_2_ITEM"
            case count if count > 2:
                # P2WSH multisig pattern: empty + signatures + script
                if (witness_items and
                        witness_items[0].get("type") == "EMPTY" and
                        witness_items[-1].get("type") == "REDEEM_SCRIPT"):
                    sig_count = sum(1 for item in witness_items[1:-1]
                                    if item.get("type") == "SIGNATURE")
                    return f"P2WSH_MULTISIG_{sig_count}_OF_N"
                elif witness_items and witness_items[-1].get("type") == "REDEEM_SCRIPT":
                    return "P2WSH_CUSTOM_SCRIPT"
                else:
                    return f"COMPLEX_WITNESS_{count}_ITEMS"
            case _:
                return "UNKNOWN_WITNESS"

    #-------------------------------------------------------------------------------------------------
    @staticmethod
    def get_sighash_description(sighash_type: int, /) -> str:
        """
        Get description of sighash type.

        Args:
            sighash_type: Sighash type byte

        Returns:
            Human-readable description of sighash type
        """
        base_type = sighash_type & 0x1f
        anyonecanpay = bool(sighash_type & 0x80)

        match base_type:
            case 0x01:
                base_desc = "SIGHASH_ALL"
            case 0x02:
                base_desc = "SIGHASH_NONE"
            case 0x03:
                base_desc = "SIGHASH_SINGLE"
            case _:
                base_desc = f"SIGHASH_UNKNOWN({base_type:02x})"

        if anyonecanpay:
            return f"{base_desc} | SIGHASH_ANYONECANPAY"
        else:
            return base_desc

    #-------------------------------------------------------------------------------------------------
    def decode_transaction(self, tx: str) -> tuple[any, int]:
        """
        Decode a single transaction (handles both Legacy and SegWit).

        Args:
            tx (str): Block transaction data

        Returns:
            str: JSON string of the decoded transaction output
        """

        # Validate data
        match tx:
            case str() if tx.strip():
                tx = tx.strip().lower()
            case _:
                raise ValueError("Witness data must be a non-empty string")

        # Validate hex string format and convert to bytes
        try:
            tx_bytes: bytes = bytes.fromhex(tx)
        except ValueError as e:
            raise ValueError(f"Invalid hex string: {e}") from e

        try:
            offset: int = 0
            start_offset: int = offset

            # Version (4 bytes)
            version: int = struct.unpack('<I', tx_bytes[offset:offset + 4])[0]
            offset += 4

            # Check for SegWit marker and flag
            has_witness = False
            if offset + 1 < len(tx_bytes) and tx_bytes[offset] == 0x00 and tx_bytes[offset + 1] == 0x01:
                has_witness = True
                offset += 2  # Skip marker (0x00) and flag (0x01)

            # Input count (varint)
            input_count, offset = self.decode_varint(tx_bytes, offset)

            # Decode inputs
            tx_inputs: list[TransactionInput]

            for _ in range(input_count):
                result_arr = self.decode_transaction_inputs_from_raw_tx(tx_bytes.hex())
                tx_inputs = result_arr[0]
                offset = result_arr[1]


            # Output count (varint)
            output_count, offset = self.decode_varint(tx_bytes, offset)

            # Decode outputs
            tx_outputs: list[TransactionOutput]

            for _ in range(output_count):
                result_arr = self.decode_transaction_outputs_from_raw_tx(tx_bytes.hex())
                tx_outputs = result_arr[0]
                offset = result_arr[1]


            # Witness count (varint)
            witness_count, offset = self.decode_varint(tx_bytes, offset)

            # Decode witness
            tx_witnesses: list[TransactionWitness]

            for _ in range(witness_count):
                result_arr = self.decode_transaction_witnesses_from_raw_tx(tx_bytes.hex())
                tx_witnesses = result_arr[0]
                offset = result_arr[1]

            # Lock time (4 bytes)
            lock_time = struct.unpack('<I', tx_bytes[offset:offset + 4])[0]
            offset += 4

            # Calculate transaction size
            tx_size = offset - start_offset

            # Calculate total output value
            total_output_value = sum(tx_output['value_satoshi'] for tx_output in tx_outputs)

            print("version: ", version)
            print("has_witness: ", has_witness)
            print("input_count: ", input_count)
            print("output_count", output_count)
            print("tx_inputs", tx_inputs)
            print("tx_outputs", tx_outputs)
            print("tx_witnesses", tx_witnesses)
            print("lock_time", lock_time)
            print("tx_size", tx_size)
            print("total_output_value: ", total_output_value)

            transaction = {
                'version': version,
                'transaction_type': 'SegWit' if has_witness else 'Legacy',
                'has_witness': has_witness,
                'input_count': input_count,
                'inputs': tx_inputs,
                'output_count': output_count,
                'outputs': tx_outputs,
                'lock_time': lock_time,
                'size_bytes': tx_size,
                'total_output_value_satoshis': total_output_value,
                'total_output_value_btc': total_output_value / 100000000.0
            }

            if has_witness and tx_witnesses:
                transaction['witness_data'] = tx_witnesses

        except ValueError as e:
            raise struct.error(f"Failed to unpack transaction data: {e}") from e

        return transaction, offset

    # --------------------------------------------------------------------------------------------
    @staticmethod
    def decode_varint(data: bytes, offset: int) -> tuple[int, int]:
        """
        Decode a variable-length integer from the data starting at offset.

        Args:
            data (bytes): The byte data
            offset (int): Starting position

        Returns:
            tuple: (value, new_offset)
        """
        first_byte = data[offset]
        if first_byte < 0xFD:
            return first_byte, offset + 1
        elif first_byte == 0xFD:
            return struct.unpack("<H", data[offset + 1: offset + 3])[0], offset + 3
        elif first_byte == 0xFE:
            return struct.unpack("<I", data[offset + 1: offset + 5])[0], offset + 5
        elif first_byte == 0xFF:
            return struct.unpack("<Q", data[offset + 1: offset + 9])[0], offset + 9
        else:
            raise ValueError("Invalid varint prefix byte")

# -------------------------------------------------------------------------------------------------
def main():
    # Example usage
    blockDecoder: BlockDecoder = BlockDecoder()

    # print("================== HEADER DECODED ==================")
    # header = "00201321b34f3ea8a91b54101b097544b78a2135783576ba3dd300000000000000000000f38bb3efa0fe5849c68bf122e4e6059eb72a5df399ff7a524cc7dc40a67ed07f75caa668b32c02174e71eeb6"
    # header_decoded = blockDecoder.decode_block_header(header)
    # print(header_decoded)

    # print("================== INPUT DECODED ==================")
    # tx_input: str = "0000000000000000000000000000000000000000000000000000000000000000ffffffff5d0395e60d0475caa6682f466f756e6472792055534120506f6f6c202364726f70676f6c642ffabe6d6d76154e5a870337f000d110efbdc40da9e19828614084f6f49d96abbe303f946d01000000000000004641a00b000020d802110000ffffffff"
    # tx_input_decoded: str = blockDecoder.decode_transaction_input(tx_input)
    # print(tx_input_decoded)

    # print("================== OUTPUT DECODED ==================")
    # tx_output: str = "9e3cc312000000002200207086320071974eef5e72eaa01dd9096e10c0383483855ea6b344259c244f73c2000000000000000026"
    # tx_output_decoded: str = blockDecoder.decode_transaction_output(tx_output)
    # print(tx_output_decoded)
    # #
    # print("================== INPUT DECODED ==================")
    # tx_input: str = "a03a1266e4c7dd79d4e32a32a6361ba9cb330fdb75b1b44f7a2063fd4d3ddb990100000017160014bdf0625e221224dc3165b801f657b129a6779e0701000000"
    # tx_input_decoded: str = blockDecoder.decode_transaction_input(tx_input)
    # print(tx_input_decoded)
    #
    # print("================== WITNESS DECODED ==================")
    # witness_data: str = "024730440220711a19de7461c592de856eddf20b36c15dd8cd44f16123dd42e844dbfceeef42022005eff1e9effb25c3235d3d0cfe5b6f5f4abee0534f734befcbc3dab63d0a81bd0121029f9406fd769e29631200d56143d88947fa9313be0b32ea728fa68f6b4fbd54e0"
    # witness_data_decoded = blockDecoder.decode_witness(witness_data)
    # print(witness_data_decoded)

    # print("================== TRANSACTION DECODED ==================")
    # tx: str = "0200000000010299a16d72bc9d715c814d9bda44c6bd1274f43916d7be13b5a6dc68adf2c6405f0000000000000000003f8d059c8c96eefd901d0b8c29cc74a5c8f2f49fd7546cb4fe130357903c36ad00000000000000000002c2e9030000000000225120a92dc3d6fb48ea45594d96f42a003d207234acf3733adaaccd3816cb74091d66cc07ef0000000000220020f8dac9cd19036102022df3e7d5c633530cdb94c3db759927e75264709c370d6f0140e683f71a72acaf54ccd5cc70f8d5bccc80be383bb09734d7aeee556babde1db3bde9c6104bbfff64f174bf2fc534945df1d08e514cee2b9c4e439df3a6d4a77902473044022065cb99f5f30c9fa07f8fd2ec9155b2d8e03f977cc67f8320daa3431745379a520220371ed2c20d8276403718db0bf5e69efc268f0d98c0d5b5c2ac5eb4709305a4790121038f97fb8778f6ea08b5848096a300fcee691974c2c731806432f790979ff144ce00000000"
    # tx_decoded: list[TransactionInput] = blockDecoder.decode_transaction_inputs_from_raw_tx(tx)
    # print(json.dumps(tx_decoded, indent=4))
    #
    # print("================== TRANSACTION DECODED ==================")
    # tx: str = "0200000000010299a16d72bc9d715c814d9bda44c6bd1274f43916d7be13b5a6dc68adf2c6405f0000000000000000003f8d059c8c96eefd901d0b8c29cc74a5c8f2f49fd7546cb4fe130357903c36ad00000000000000000002c2e9030000000000225120a92dc3d6fb48ea45594d96f42a003d207234acf3733adaaccd3816cb74091d66cc07ef0000000000220020f8dac9cd19036102022df3e7d5c633530cdb94c3db759927e75264709c370d6f0140e683f71a72acaf54ccd5cc70f8d5bccc80be383bb09734d7aeee556babde1db3bde9c6104bbfff64f174bf2fc534945df1d08e514cee2b9c4e439df3a6d4a77902473044022065cb99f5f30c9fa07f8fd2ec9155b2d8e03f977cc67f8320daa3431745379a520220371ed2c20d8276403718db0bf5e69efc268f0d98c0d5b5c2ac5eb4709305a4790121038f97fb8778f6ea08b5848096a300fcee691974c2c731806432f790979ff144ce00000000"
    # tx_decoded: list[TransactionOutput] = blockDecoder.decode_transaction_outputs_from_raw_tx(tx)
    # print(json.dumps(tx_decoded, indent=4))

    # print("================== TRANSACTION DECODED ==================")
    # tx: str = "0200000000010299a16d72bc9d715c814d9bda44c6bd1274f43916d7be13b5a6dc68adf2c6405f0000000000000000003f8d059c8c96eefd901d0b8c29cc74a5c8f2f49fd7546cb4fe130357903c36ad00000000000000000002c2e9030000000000225120a92dc3d6fb48ea45594d96f42a003d207234acf3733adaaccd3816cb74091d66cc07ef0000000000220020f8dac9cd19036102022df3e7d5c633530cdb94c3db759927e75264709c370d6f0140e683f71a72acaf54ccd5cc70f8d5bccc80be383bb09734d7aeee556babde1db3bde9c6104bbfff64f174bf2fc534945df1d08e514cee2b9c4e439df3a6d4a77902473044022065cb99f5f30c9fa07f8fd2ec9155b2d8e03f977cc67f8320daa3431745379a520220371ed2c20d8276403718db0bf5e69efc268f0d98c0d5b5c2ac5eb4709305a4790121038f97fb8778f6ea08b5848096a300fcee691974c2c731806432f790979ff144ce00000000"
    # tx_decoded: list[TransactionWitness] = blockDecoder.decode_transaction_witnesses_from_raw_tx(tx)
    # print(json.dumps(tx_decoded, indent=4))

    print("================== TRANSACTION DECODED ==================")
    tx: str = "0200000000010299a16d72bc9d715c814d9bda44c6bd1274f43916d7be13b5a6dc68adf2c6405f0000000000000000003f8d059c8c96eefd901d0b8c29cc74a5c8f2f49fd7546cb4fe130357903c36ad00000000000000000002c2e9030000000000225120a92dc3d6fb48ea45594d96f42a003d207234acf3733adaaccd3816cb74091d66cc07ef0000000000220020f8dac9cd19036102022df3e7d5c633530cdb94c3db759927e75264709c370d6f0140e683f71a72acaf54ccd5cc70f8d5bccc80be383bb09734d7aeee556babde1db3bde9c6104bbfff64f174bf2fc534945df1d08e514cee2b9c4e439df3a6d4a77902473044022065cb99f5f30c9fa07f8fd2ec9155b2d8e03f977cc67f8320daa3431745379a520220371ed2c20d8276403718db0bf5e69efc268f0d98c0d5b5c2ac5eb4709305a4790121038f97fb8778f6ea08b5848096a300fcee691974c2c731806432f790979ff144ce00000000"
    tx_decoded = blockDecoder.decode_transaction(tx)
    print(json.dumps(tx_decoded, indent=4))


if __name__ == "__main__":
    main()
