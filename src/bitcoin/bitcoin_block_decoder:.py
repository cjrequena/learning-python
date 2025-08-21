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


class BlockTransactionInput(TypedDict):
    """Type definition for decoded block tx input data."""

    previous_tx_hash: str
    previous_output_index: int
    script_sig: str
    script_sig_length: str
    sequence: str
    is_coinbase: bool


class BlockTransactionOuput(TypedDict):
    """Type definition for decoded block transaction output data."""

    value_satoshis: int
    value_btc: float
    script_pubkey: str
    script_pubkey_length: int


class BlockWitnessItem(TypedDict):
    """Type definition for decoded block Witness Item."""

    witness_item_length: int
    witness_item: str


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
    def decode_transaction_input(self, tx_input: str) -> str:
        """
        Decode a transaction input.

        Args:
            tx_input (str): Transaction input data

        Returns:
            str: JSON string of the decoded transaction input
        """

        # Validate data
        match tx_input:
            case str() if tx_input.strip():
                tx_input = tx_input.strip().lower()
            case _:
                raise ValueError("Transaction input must be a non-empty string")

        # Validate hex string format and convert to bytes
        try:
            tx_input_bytes = bytes.fromhex(tx_input)
        except ValueError as e:
            raise ValueError(f"Invalid hex string: {e}") from e

        try:

            offset: int = 0

            # Previous transaction hash (32 bytes, reversed)
            previous_tx_hash: str = tx_input_bytes[offset: offset + 32][::-1].hex()
            offset += 32

            # Previous output index (4 bytes)
            previous_output_index: int = struct.unpack('<I', tx_input_bytes[offset:offset + 4])[0]
            offset += 4

            # Script length (varint)
            script_sig_length, offset = self.decode_varint(tx_input_bytes, offset)

            # Script signature
            script_sig: str = (
                tx_input_bytes[offset: offset + script_sig_length].hex() if script_sig_length > 0 else ""
            )
            offset += script_sig_length

            # Sequence (4 bytes)
            sequence: str = struct.unpack("<I", tx_input_bytes[offset: offset + 4])[0]
            offset += 4

            #
            is_coinbase: bool = previous_tx_hash == '0' * 64 and previous_output_index == 0xffffffff

        except ValueError as e:
            raise struct.error(f"Failed to unpack transaction input data: {e}") from e

        block_tx_input: BlockTransactionInput = {
            "previous_tx_hash": previous_tx_hash,
            "previous_output_index": previous_output_index,
            "script_sig": script_sig,
            "script_sig_length": script_sig,
            "sequence": sequence,
            "is_coinbase": is_coinbase
        }

        # Return the decoded transaction input JSON string
        return json.dumps(block_tx_input, indent=4)

    # --------------------------------------------------------------------------------------------
    def decode_transaction_inputs_from_raw_tx(self, tx: str) -> list[BlockTransactionInput]:
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

        inputs: list[BlockTransactionInput] = []

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

        return inputs

    # --------------------------------------------------------------------------------------------
    def decode_transaction_output(self, tx_output: str) -> str:
        """
        Decode a transaction output.

        Args:
            tx_output (str): Transaction data

        Returns:
            str: JSON string of the decoded transaction output
        """

        # Validate data
        match tx_output:
            case str() if tx_output.strip():
                tx_output = tx_output.strip().lower()
            case _:
                raise ValueError("Transaction output must be a non-empty string")

        # Validate hex string format and convert to bytes
        try:
            tx_output_bytes: bytes = bytes.fromhex(tx_output)
        except ValueError as e:
            raise ValueError(f"Invalid hex string: {e}") from e

        try:

            offset: int = 0

            # Value (8 bytes)
            value_satoshis: int = struct.unpack('<Q', tx_output_bytes[offset:offset + 8])[0]
            offset += 8

            # Script length (varint)
            script_pubkey_length, offset = self.decode_varint(tx_output_bytes, offset)

            # Script public key
            script_pubkey = tx_output_bytes[
                offset:offset + script_pubkey_length].hex() if script_pubkey_length > 0 else ""
            offset += script_pubkey_length

        except ValueError as e:
            raise struct.error(f"Failed to unpack transaction output data: {e}") from e

        block_tx_output: BlockTransactionOuput = {
            "value_satoshis": value_satoshis,
            "value_btc": value_satoshis / 100000000.0,
            "script_pubkey": script_pubkey,
            "script_pubkey_length": script_pubkey_length
        }

        # Return the decoded transaction output JSON string
        return json.dumps(block_tx_output, indent=4)

    # --------------------------------------------------------------------------------------------
    def decode_witness(self, witness: str) -> str:
        """
        Decode witness data for SegWit transactions.

        Args:
            witness (bytes): Witness data

        Returns:
            str: JSON string of the decoded witness items
        """

        # Validate data
        match witness:
            case str() if witness.strip():
                witness = witness.strip().lower()
            case _:
                raise ValueError("Witness data must be a non-empty string")

        # Validate hex string format and convert to bytes
        try:
            witness_bytes: bytes = bytes.fromhex(witness)
        except ValueError as e:
            raise ValueError(f"Invalid hex string: {e}") from e

        try:
            offset: int = 0
            witness_count, offset = self.decode_varint(witness_bytes, offset)
            witness_items: list[BlockWitnessItem] = []

            for _ in range(witness_count):
                witness_item_length, offset = self.decode_varint(witness_bytes, offset)
                witness_item: str = witness_bytes[
                    offset:offset + witness_item_length].hex() if witness_item_length > 0 else ""

                witness_items.append({
                    'witness_item_length': witness_item_length,
                    'witness_item': witness_item
                })
                offset += witness_item_length
        except ValueError as e:
            raise struct.error(f"Failed to unpack witness data: {e}") from e

        # Return the decoded transaction output JSON string
        return json.dumps(witness_items, indent=4)

    def decode_transaction(self, tx: str) -> str:
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
            version = struct.unpack('<I', tx_bytes[offset:offset + 4])[0]
            offset += 4

            # Check for SegWit marker and flag
            has_witness = False
            if offset + 1 < len(tx_bytes) and tx_bytes[offset] == 0x00 and tx_bytes[
                offset + 1] == 0x01:
                has_witness = True
                offset += 2  # Skip marker (0x00) and flag (0x01)

            # Input count (varint)
            input_count, offset = self.decode_varint(tx_bytes, offset)

            # Decode inputs
            tx_inputs: list[BlockTransactionInput]

            for _ in range(input_count):
                tx_inputs = self.decode_transaction_inputs_from_raw_tx(tx_bytes.hex())
                print("tx_inputs", tx_inputs)

            print("version: ", version)
            print("has_witness: ", has_witness)
            print("input_count: ", input_count)


        except ValueError as e:
            raise struct.error(f"Failed to unpack transaction data: {e}") from e

        return ""

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
    header = "00201321b34f3ea8a91b54101b097544b78a2135783576ba3dd300000000000000000000f38bb3efa0fe5849c68bf122e4e6059eb72a5df399ff7a524cc7dc40a67ed07f75caa668b32c02174e71eeb6"
    blockDecoder: BlockDecoder = BlockDecoder()

    header_decoded = blockDecoder.decode_block_header(header)
    print(header_decoded)

    print("================== INPUT DECODED ==================")
    tx_input: str = "0000000000000000000000000000000000000000000000000000000000000000ffffffff5d0395e60d0475caa6682f466f756e6472792055534120506f6f6c202364726f70676f6c642ffabe6d6d76154e5a870337f000d110efbdc40da9e19828614084f6f49d96abbe303f946d01000000000000004641a00b000020d802110000ffffffff"
    tx_input_decoded: str = blockDecoder.decode_transaction_input(tx_input)
    print(tx_input_decoded)

    print("================== OUTPUT DECODED ==================")
    tx_output: str = "9e3cc312000000002200207086320071974eef5e72eaa01dd9096e10c0383483855ea6b344259c244f73c2000000000000000026"
    tx_output_decoded: str = blockDecoder.decode_transaction_output(tx_output)
    print(tx_output_decoded)

    print("================== INPUT DECODED ==================")
    tx_input: str = "a03a1266e4c7dd79d4e32a32a6361ba9cb330fdb75b1b44f7a2063fd4d3ddb990100000017160014bdf0625e221224dc3165b801f657b129a6779e0701000000"
    tx_input_decoded: str = blockDecoder.decode_transaction_input(tx_input)
    print(tx_input_decoded)

    print("================== WITNESS DECODED ==================")
    witness_data: str = "024730440220711a19de7461c592de856eddf20b36c15dd8cd44f16123dd42e844dbfceeef42022005eff1e9effb25c3235d3d0cfe5b6f5f4abee0534f734befcbc3dab63d0a81bd0121029f9406fd769e29631200d56143d88947fa9313be0b32ea728fa68f6b4fbd54e0"
    witness_data_decoded = blockDecoder.decode_witness(witness_data)
    print(witness_data_decoded)

    print("================== TRANSACTION DECODED ==================")
    tx: str = "01000000000103baaa916a04a883a47a2315d34c831a8150a956b909b3461843d10d7f95f04d340000000000fdffffffb3b59821636578cc822a0d0b53afe6d7a74c8f742cb92dcae26bb5d8d83290460000000000fdffffff88233905a8aaa6b627c5018ced7c6e66f2da9f798c96da7d0ca9fd1dddba51910100000000fdffffff02c0d8a70000000000160014aedff1c9895fc2d90e4aa533eec26e5129ce22ac451a080000000000160014feaf5eaf256b05a56f1404e948a53ded4fb2c01902483045022100c42081a322b9593e2dd77d3a2058876b8e82f5f916ce9fb9b594a46db08b857f02204571afad1474218238a815125bc50fc6168b4bdc14f48196b441b7fe57dfd7fb012102160d8648cd55199c8095ff0a4ef3eacf9e5f45ee7d0466f19d7e47dad94a84350247304402202542ef36ed7059158b51e1bf67f70fbefb476816429a818cd3a6e1c1b0863d82022011a525e8d25dafde060dcb76d0d31c073956cd917e754cddd5a4c82e076976a0012102160d8648cd55199c8095ff0a4ef3eacf9e5f45ee7d0466f19d7e47dad94a8435024730440220264c3585c0271c86664339e6d828daf855c41e1d787985199f7c8bc1f54cddc202206087a3be61a2d82fd0fecd924fbc6f5c591734083ae8cfe0ce1dd5611f87d852012102160d8648cd55199c8095ff0a4ef3eacf9e5f45ee7d0466f19d7e47dad94a843500000000"
    tx_decoded: list[BlockTransactionInput] = blockDecoder.decode_transaction_inputs_from_raw_tx(tx)
    print(json.dumps(tx_decoded, indent=4))


if __name__ == "__main__":
    main()
