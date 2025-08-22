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


class BlockTransactionOutput(TypedDict):
    """Type definition for decoded block transaction output data."""

    value_satoshi: int
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
            value_satoshi: int = struct.unpack('<Q', tx_output_bytes[offset:offset + 8])[0]
            offset += 8

            # Script length (varint)
            script_pubkey_length, offset = self.decode_varint(tx_output_bytes, offset)

            # Script public key
            script_pubkey = tx_output_bytes[
                offset:offset + script_pubkey_length].hex() if script_pubkey_length > 0 else ""
            offset += script_pubkey_length

        except ValueError as e:
            raise struct.error(f"Failed to unpack transaction output data: {e}") from e

        block_tx_output: BlockTransactionOutput = {
            "value_satoshi": value_satoshi,
            "value_btc": value_satoshi / 100000000.0,
            "script_pubkey": script_pubkey,
            "script_pubkey_length": script_pubkey_length
        }

        # Return the decoded transaction output JSON string
        return json.dumps(block_tx_output, indent=4)

    # -------------------------------------------------------------------------------------------------
    def decode_transaction_outputs_from_raw_tx(self, tx: str, /) -> list[BlockTransactionOutput]:
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

            outputs: list[BlockTransactionOutput] = []

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

                block_tx_output: BlockTransactionOutput = {
                    "value_satoshi": value_satoshi,
                    "value_btc": value_satoshi / 100000000.0,
                    "script_pubkey": script_pubkey,
                    "script_pubkey_length": script_pubkey_length
                }

                outputs.append(block_tx_output)

        except (struct.error, IndexError) as e:
            raise ValueError(f"Failed to decode transaction: {e}") from e

        return outputs


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

    #-------------------------------------------------------------------------------------------------
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
            tx_inputs: list[BlockTransactionInput]

            for _ in range(input_count):
                tx_inputs = self.decode_transaction_inputs_from_raw_tx(tx_bytes.hex())
                print("tx_inputs", tx_inputs)

            # Input count (varint)
            output_count, offset = self.decode_varint(tx_bytes, offset)

            # Decode inputs
            tx_outputs: list[BlockTransactionOutput]

            for _ in range(output_count):
                tx_outputs = self.decode_transaction_outputs_from_raw_tx(tx_bytes.hex())
                print("tx_outputs", tx_outputs)

            print("version: ", version)
            print("has_witness: ", has_witness)
            print("input_count: ", input_count)
            print("output_count", output_count)


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

    print("================== TRANSACTION DECODED ==================")
    tx: str = "01000000043fe3f3d1dc833f7333a9c38ddc547acdd025eab8ccf4c695702e8209c95ee70b00000000da00483045022100d93edf8fb82410f2005dc8d636c40a756227ce7a122b755a9d32ab3ed91d16350220758adf19bc5411fba5c5967745d8f4d9a314c303c148aacd59fe0df6dad2fc8d0147304402200ca0d4dd25d7f407bd6184297e041d5cdaece7934c3246fa0fd63de05ae7500a02204eca7856e8f2e763baa3b417dab7c0ab2409dbdab92e6dd4ceec3b79e9c317e00147522102f1ff11c3b2f8f6a7a636043adde524e2e130ce23ca7b364ed868a69d3980da5c21034f0457f9ceb8ba7a6a49f242f565f12f7039c996b9dd9a63aa812d75e51638d152aeffffffff7df1df419b2aa8bb5d0812e02afdb1a81241503ac10fd98b189610bdc3aec91ff4010000db0048304502210096cd98b4f39f13d9e54466bf09b292f86dbf4738a09ba1599f79a3e51eeb5e10022074a2c36d1da95e5ed94768fb1525689820dcc43b80ede9d2612c19b3f6bee65f01483045022100e163709303cd20029ef8c7e9a23bb3253968f684f3f3ec4dc8c6b6a750261c6f022007a93f04ebf911713ee347cfccccfc858b22017964b98281e0cdd9ca84fce04f0147522102f1ff11c3b2f8f6a7a636043adde524e2e130ce23ca7b364ed868a69d3980da5c21034f0457f9ceb8ba7a6a49f242f565f12f7039c996b9dd9a63aa812d75e51638d152aeffffffff9ef1d1fd18b4e8fa6cbc250ab8a184ff55aba1b74b08bb6194596b673f5813ac00000000da00473044022061e7d3708ebb10aa76d80099a2d5c3690f898a6008e21a0c18d741d36aebb95502204b6ba364cece90b0fda5927da49f1737905a47bed00dbde28cf0e966126b2cdb01483045022100cb08dde8a2be0d14866580b00d276f5355bf552ef1789cdd9ea9ea52b09d660502202bfd901ffc36e61ace4b42bcfa2b8d86b53747910790c49e67be91725ea92d010147522102f1ff11c3b2f8f6a7a636043adde524e2e130ce23ca7b364ed868a69d3980da5c21034f0457f9ceb8ba7a6a49f242f565f12f7039c996b9dd9a63aa812d75e51638d152aeffffffff827db2f6433f72b03a6327c4a586643f3bbadf6ab55fa0b0a6429db35a9986bb63010000db00483045022100c57fe8ec1ac092887b262baf9006b7b56c436032597d86de8a2a0f3a0eef306a02204c2d582050e6528f14320898fd7cab7a40bd0d864d2173f80170ac9866b80354014830450221009cbbd54099841da13b453c132330fe140b2e3b81208e47402dad2b94cc8f0352022031c75c254efe87df2150015faf3143c142162d49232ac0c124728761c80b011f0147522102f1ff11c3b2f8f6a7a636043adde524e2e130ce23ca7b364ed868a69d3980da5c21034f0457f9ceb8ba7a6a49f242f565f12f7039c996b9dd9a63aa812d75e51638d152aefffffffffd5601a4130d00000000001976a914f20f5744c526493965fa5ebaa0adde3c49ddfb4988ac456b0900000000001976a914d61c26109b62d6d52ae62294c65718452485341e88ac6d620900000000001976a9148c2504d3a1b1951e47c67ec3102dece28effcc2588ac9a470d000000000017a914f9322bccffd14d6d5f1ad681e2a4cc6257edb6078763b90c000000000016001451e0b46a0fcfa1b357d7a7f6e2c3dadfecedcd3b579d0800000000001976a914e757e66a2ba68cebc7d37dfb6e03f70ecbb2aa1688acbec00700000000001976a914e0273eb5f5d6604966275083b20a81b5e7ee9a0688ac140569000000000017a914811d16a8ea7fd0f9e67303a779a36823738424708795775400000000001976a9141dcff52a220c6d585040260576c05212f3154ce088acc8c707000000000017a9146ab852c6c641b94e478844833c9c802d7df181b387e090230000000000160014e7b6da19a0c1f2f336b113128be37ae0b7c0a5368cdd0700000000002200203a8d8a4b94f19c2d729333cb742613e61fd33002974c133509997568cc44cca29d9d080000000000160014cd6f71f664150cb4580e39ba13e2353dc73d23ed18060800000000001976a914eadecf61e5c88d7888694f0fad57ae10209ada2188ac82d42a0000000000220020e42e925f342d61ca31ced1acb4fabfc08a867f43c44e90c50a3e726dc15469121c4745000000000017a914b3f62eff69d20ba641d755980eba0d6a443327e187ce7b4d000000000017a914ccc8dfa42083393c21be76dc3fa1f9aa592ab20987cb6909000000000017a91403e0a87ae2dadfffd55a8224c16fa7ea6851679a8765e707000000000016001452b3394a4410c8810d8c1b6b31b7610270d44c8ac0ff83010000000017a9146ba34c01741dd497b6cd2572b060e9b5b3ec297f8703020a00000000001976a914aea17113ff03712aa19412524e791c99ffcaabf988acf74d0a000000000016001448616cb875aa61f09ff67cb931a3544ac318c5e3a4a7080000000000160014bbe092304c273ae1dfc61c99fc045a53988971c51b79090000000000220020b53e61bc57c4b726a53cfdcc4a8c685a1646fc18695ddc9d6057d003457256a425640a0000000000160014603d78a217cc840fe2f6c94dea82c77fe0b4788d09a70c0000000000160014b514c1b71bbfe9007ee33db210f5d8d46ab72650f6a40e00000000001976a914db144d69edcaa2f52556fe0aebc0b163b9928f8588ac7d45220000000000160014d1bf34733a30bf459d44ae6af6265fdd8a04b59de6bb2500000000001976a9142c66b5fa638a611c2e46863eef327c9f7dbdc8f188acc9101f000000000017a9140e569509ac7fc5b33f48f29fc3e43dce5b67e9208787c507000000000017a9148adc307e3de0b0a267c88ecb14915201a28e2f658794ba07000000000017a9149c483adc7a0bee8630a48ac60d96cda46e8fd38a8726a40900000000001976a91442dc178c3309451d2f68ad77ea22f2974c84ff6b88acc1b0070000000000160014451be5ca98deddb2360aa31cf1eb4e3ac3267229e2bf0e00000000001600140c903adf7b7aae30a67f75e013527186dc247931ff740f0000000000220020bbde61ac8dbaf89ba0261dbb03a949c232903f7ea1fadb4fc0f0ce06a66960c4ff8b0800000000001976a91427344f04565c9dd4e8935b96d6176d660b41cf4288ac33650900000000001976a914536d3353579644b06a3ab8d278f45ca215ede4b488ac9cc308000000000017a914a79eee04c421e6ea5bf5bc25cfe48833f7648f5687ee1a0e00000000001976a9142301395d6660c565829061c4c6d545136ef0d1a288ac4baa0700000000001976a91481f34d51b75faea4b519e9ca0ba6da102649219388ac047108000000000017a91451ad7f775348221e13875fb69c0b89d382925f518792b51100000000001976a9143c38eec5fbc95c866201f31306ec8484b7feb1d388aca811080000000000220020e4f420707ee739c200a69e7b0fd70f191bd76b92255af8bade8280550d1899521dd30a000000000017a914ede45383cebfdada166a762473832da748ac572887358e58000000000017a9144e9d065688c97a3db011fc9f66c473e5c7515b0f87f706090000000000160014584f0fa8966f4a451334c8f916bf0401aefb54bdca3209000000000017a914a1e87a795891e99024d5d6d2789621526ac8b229878cac5b0000000000160014aa6d680a3d4826cbe511a26c2eed97e2574db17b631208000000000017a9147454e0f27d88f7439d6f22ec740bb52c1abdafa887a1540900000000001600143a78a1d8f4354301c107e573044429e3f11904d2d41208000000000016001423f4cc84f0eb1bb16b41f060ed72b246347bf73cd3a20700000000001976a9141f77a13970f615db05f3f80e6bcd5c6f14d44bbd88acedf709000000000017a914ff70d487299b70ca4d47657624b6f39377d7385c875c4d0900000000002200205a284ed5af10a30ea041895774f9d8d0d7f48bd45ee927a66dabeb5d3d2b9dd1734e08000000000017a914de11cb5452da5eebebc52301a20f5b13032d1f538711e60b0000000000160014645a4a1377143294b92c9a92c7787891ce7d41ff35b4070000000000220020c172f8bd63e42bb6ddbbe9a871e03224d83fd3b6d5a6b9d58bf5944c7c2150204ba80a0000000000160014aa35225a00ba84e1e83a4068eb32e434b70c898f04cd07000000000017a9140e32826452ad67de8f6ac4b4ef4d9a2f8bcd10c387ff4508000000000017a9149140aac8839fc47b8873d2feea97123bece9a82087d0af0700000000001976a9142f3067f9624b66f44f037b90a4b5348a6b3dd6b788acb7a52300000000001600148db46d95cebfe9e18306a9ba0599f1ab9ffb27d109e109000000000017a9145b091b7e4f1f020a21ddf88d194903eb1bc9364787542f08000000000016001444b7dadef962245f08ac2abb002d2270a792fbbe565d34000000000017a91403ceef2de6d3e7f79205fb6f8692d56b0f1431f88744e40700000000001976a9141f1cb150280f2948213b2bab2f5ac614462c59de88ac366314000000000017a91433c5ced582ffc0807b9386b76d5ebf21b790b17287bdd02f000000000017a914cd6acfd8fd771b4fe764e8dd754cdf46e933a9e787e6540b00000000001976a91437504650eec9d52f518a4b5cdc77329850b3161c88acd900b4000000000016001457cf919b78c7f256afc5e59feb9f27e3b940deab0c1c0a00000000001976a914259a303dc91ba077e323e94e28686fe0b76df2ad88ac66b10700000000001976a9149fa403bb0cf8d93e0f372ea9ac45267f5bc6a2e288ac28b60700000000001976a914efe533633dc721b51f9560a3e5b1d934c719ec3588ac8a1a7600000000001976a91415eb4c9551f520aaf8e0992a22e63252e2502c1988acb1a207000000000017a91407be2033d21a452c357e99fb247e03ab54854e1d87945d0d0000000000220020bb271aa470560e3b801ea162c8bad6669ca128941146132cbe1573ce48f05340691f0a00000000001976a914cb90f36a3c30ab738c3340d6f600f794a7da9a3788ac896d0800000000001976a914f48faaae2522aa8fdf27f9844f690abdebd9965c88ac269a30000000000017a9147c7c3d79ef7fcf829d5b148f3eb65f259fd28e0e87730c63000000000016001482c92f14a52189bc38e83e9da2df6dd4490a6f1680bd07000000000017a914ea061f4c9deca9dbb4529a4c334f3607110797be8761d50900000000001976a914f8399b4c8524085060abe0e6b7f33fee693c335488ace2a207000000000016001465266f4baa753ca3b2457da91b1ebafbba4319f310080800000000001976a914754d1a9ae8c0f8b8f4fdb279e15bd124b3f08f9588acabf90800000000001976a91493d7790b1e2774bb82c0f34afc153d2c01ae04ba88ac49ab07000000000017a91466c3025db4cccbe6186c4283d269241cfddbd1988725340900000000001976a9147c85d5ff6bc4850c4f29284a7dce5ffa34cb6f7c88ac7d8f080000000000160014be07152190ca0c198735f9925445e9ab26e0b7715d74110000000000220020d3380245c2371ba452ad3762d41d321d6c63a9b2d1cc9b2724bc21a5c828bcab91b50f000000000016001495830ad22fd9112099701389fa6111551365308e906627000000000017a91471f7eedb90e6344379eeeb5b12ad0a8b8eed940c8721d509000000000017a9141cc402a331a166a45e05eac2fa3317e8e11dfb1c8702ef1e000000000017a914bffca9a20bd16870b3e7be0022efb487bb307d60875f091100000000001976a914206ed3da7885e186c94d123543fd32c639a0f6cb88ac9cef0e000000000017a914e170ad2ad244c4ce9c8ff732aa53149e512eeace87cb5a09000000000017a914f1b26a42d4a7793c2f263f11a649ea45dbe748be87f97b09000000000017a9144a8d4942fae11b1efd574b1aad42c2528ff31d6f87fc5f0b00000000001976a914c226ba4de47eb29603b6531841c0a17ca32f6d2588ac8b9809000000000017a914795acf91441bf988d7ebc4708022fc23797a284587dcb11c000000000017a9145e25ab53c2a95912ccdee7260a0d123c0213b95a8752c007000000000017a9143d7684f040411ca192be6a05a1b2a28ef8e94864877db307000000000017a91420a1b612f92db805eaafcaeaf86a6c0c9977970e87587209000000000016001452bc616870d16fd4215347b946b5e3cf67329ee632fe080000000000160014d651b06ffb99bd57cf0c1a56781bb1de570ba963f1450f0000000000160014cfee80338f0cd24da28316254a2a09c2dccebb43e90d08000000000017a9146363e8ec06e50e85808934c42f0bda0b905edca9874ca60700000000001976a9148b9a6cafa47d8b0c63b965de12416184065013ae88ac25d00c000000000017a914759086bef4b95964b5e73d291179fb7320e5ea5a87b3d614000000000017a914d9c11454493142dd7131ffcbb1df215772c68ed587c0b607000000000017a914cf77be78338df3ecf4cecf40b2071af35e54ac1d87cf1908000000000017a914142b3ba73f249d329e162a43f3dfece058696e3987b5010800000000001976a914a0706b07774353e43ef790d5d6ec9b25c917cd1688ac4db50700000000001976a9147c4e684824ea41a7d21ef140e064f82a00defc2c88ac7a7509000000000017a9145de3ca96fc7f8bf7e1ae01e27e30ceffaf4ca5a2878ba10700000000001976a9148b3c013fb26e0ed0b33958be254323bbe2f2e5c888acd4bed4020000000017a9149cf6199044257c175b9830107b7eeca522386a2887b5d40b00000000001976a914cb78c14af50916a2997cf341bd5ce0e013a222cd88ac50760b00000000001976a914e0f5d8a846aadebe12634cfc46811d819e2cf76f88ac9eab1f00000000001976a91411eba5220f38feaa0a855d84a89d03a52064c93c88ac3eb10700000000001976a9143e40481a2834f4b4a09c29875ecc9bebab24f5cd88ac1d1008000000000017a914f2c098825e2a2a92543731af5af5c91708939d9687db650800000000002251200341a8dcc8405d6a09c2c00b7977c184d9fbe3ed11c4b373d634ac1654a143fc61ee0a00000000001976a914524dd72fcc69b96d3fe8090d25fb7b63970a4f7d88ac2ed307000000000017a91444cb041e1c393e4e877e2a0d4f63e6e3d05341d78784f10800000000001976a914d78979c28149685a91a1259ee2cc10bf3b7c211388acd9040800000000001976a914924474d7723462f391a70576047bec8b634d66ee88aca7b10e000000000017a91444051c459761e0caa833b85c6151369706e9453c87053c0d000000000017a914f9af9d1b5f71a5271e2183ac73159f4d856d79b787426508000000000017a914080d2664a6bd9c6f1692fffe6e3a22bd414e89988736680a00000000001976a91407b52d788780c7c495b10af9f714a06a7456051888ac62ec0800000000001976a9143e5e5161e2bd27af00178526185b4d4b8400925b88acc15a0b0000000000160014f2d1788464d5644a1a56d2a73e87e48c03ca1e9276b00700000000001976a914122dfe5fc40268574b8247edb08f1ac0bc10b8e488acd9d70700000000001976a9145ec3fdb0aadca71762764d33113b594badf5156688ac1569080000000000160014be83e2375327999ea8b3de37760b9ccc052a9643831a0c000000000017a914078a6c87e5ae6fb6a4d8dfcd1ada0fbef7116947875d7a0b00000000001976a914366b11353487a5f42ecf49ffb13b8f73cbe0c57a88ac20bd0900000000001976a9146d3c6d86a831783d7e288a078f96a3b01cbd5e5888acad351c000000000017a9149c7a58c28a7a3b94c6197be8fbc85bc7c7fd949f87d4d107000000000016001438bfa3a5f0108851abe18206b2e42bc5cd69d85d336a0f00000000001976a914f154f69849c59e5e42466ecee299cdc0605d876c88ac790f09000000000017a91494d50ac1abd4c47fb039ffd50ee0c062aece6b3a870dfa0800000000001976a914fdacd50b161b1b85648a40600a4f155e5f40d66888ac9fd511000000000016001470ad8cc7744f92aa1b275dbdf5fa09ba5007a65fa6780a00000000001600140865d5ea0758d689b3f32159e299282a91f52843e8761501000000001976a9141837a306002d0e04e17cf5e206b749b09138f0b588aceb920800000000001976a914a3b3d5373a66296701295a54dd4b4bb984f6385b88ac0890080000000000160014de90b4cef578b88c520f86221c08c0c03c7330a001c20700000000001976a914f7cbe2343685ba86ccf40986622c7f962c9f3b4988acaf25150000000000160014380d52a5060f687266dee936f6a47424ed6df183d8400900000000001600149a4a14f762848581ad5d302118945455c853980e21650900000000001976a91444791dbaedb1c0c4bd672f7be761a116fe4dd5a088acfff70700000000001976a9143eae8bd216c041d25d1a1e1f2125d53808e23f9f88ac4ec4630000000000160014d04ad39197cf1cfeb006f4a0201c0a5f32096ef878d40700000000001976a914fb92165754d823b1c73462bbebc25803c99fb7f588acf0f00c00000000002200201c78b634e3ec8b007e666fbac434d42a4ebdaeec1903ddc8296ee7a47e048f5f89d80900000000001600149b7f3bc413d0eeada1359fb2f741d30dc173ec8d815d0900000000001976a914fb89ae489b3678f1814677b24676d6497cc40f4888ac1ad407000000000017a914d6b457a44ec446afbaed33e0c70dd333492a5e508710f51f00000000001600145eed8c7399104dfbc32fb40c8530752a3a6c82f1a4d70a000000000017a914950e59478e2b399d27f816a18bc4d82b9deb6d69877eaf08000000000017a91423bfd33b104aabb3d6f64137fb5eddf889ccba8e87a019080000000000160014ba337764cf3549a0c9a8e936c0f29230727fdc07b6ffd400000000001600146d68541dfe10f351d679fa36cb65346b4d8650974f330300000000001600147ba3a9b3721fac95a0830e81599b3def9b3baf5d343928000000000017a9144a6c1df634c0f8c2420a29dce7f6d4c3adaff22b87f5d73500000000001976a9147665fb32ca3cc9d46ed7d6b84bdb442c0ccf72a388ac75755b00000000001976a91480f4de0660447e3fa667a236fa252f90f0f6b12988ac7d9535000000000016001405e19e1b67950670aeadaa4c1e15c7bbfd33f13d44b908000000000017a914e50e7a99578b51eed30ba362337b4ca41854d898870ea02e000000000016001440f27dc046f1c996678e1e070ba244f773937f1c61913f00000000001976a91462b47cb5dc25814a23023ac69efdc12f5141443a88ac332bd200000000001976a9141f109e19a2f0d46a32c423efb9b7e507a07fce3188acb5a1d8050000000022002098d7824b9a9dc3f11c0e3f6783740a162b74874ef9a79b17fac7b1739b1d2cbf58278c000000000017a914f563b4f0a32a56e4db47afdb5f46308cf40f12f587a01532000000000017a91447b775ab23ba4dde75b476b6696e16a678d3f8838725ed2d0100000000160014e64ad6410efef4c1d31719b6a47287d629dfcc114ef6310000000000225120f1b99ed53f914129e299934473c453577ba45bf4ce6449a238d85d380a4267a06e4e4b0100000000160014977a8ab28f1515c7964988184deaa3f7657f0d8ec69b5a0a00000000160014e342a3d12e2cb80f9522d94a7955da4e0c92835cdb1a2000000000001976a914308bfb39b7bd31061c836743567ab85b941b058d88ac8b4b890300000000160014c2d95ded8e7f60e270a04a7619cc414f44d8dbf5821617000000000016001475779c0a479231e7b766fa783b525f77591c23c8fdb81400000000001976a914933a19fb2f7338b5aad78b16bbd3ee57ce2434a488acfacb1c000000000016001475b5c00c94fa96d5ce9595760a8e60f67578ed14b2f3810300000000220020840ecc1c09d05b4fdeef04729d2d12ba508608a9e1899963969f3388e3d31c0656b90f00000000001976a914854a8fb2673303563f7d45c10a28f99b6bd6af4288accea8f80f000000001976a914897fd9c4f7184fcf71c5535f70e1e47244d3fd8588ac8fc21a00000000001976a9142c60fd86e2f26b064a1204f1ee6927d1c6af170a88ac32b81c01000000001976a914be8bc9508bc647561feb7deb908e77cd74ff1cca88aca7440000000000001600142e9af69ee3066fd50206822878f8a95d4885f88af1113000000000001976a914d7b28dc5a70ee09bcc6541433467bcc34cc6421c88acb2937c0300000000220020beb957c4ea55ddbf6ef3c4d4d71c24ef02adb9950d647c593928682945cd313337471c00000000001976a9144b70fb97e079a175ca908c04624084585e2674cb88ac5ce9671a0000000017a9148e15b2feb07007b0a4ed079baf600cd21db7e5ca876b326426000000001976a9147c154ed1dc59609e3d26abb2df2ea3d587cd8c4188ac4611150000000000160014ece678d0a0f0609e51133f50138e86bfdfee4a90700117000000000017a914115e35029953009ccfb87441c029dca9a3412edc87fb855c1900000000220020ed6f65aa3bec00e7c55e3a809c919b83e933a881248f8b7d5fd987e2b05c98fa3a08f20f000000002200206b8d6fbe7ddb736347b9e623e464ddd9d1b42cd2262b964b091195bc6e46a6ab3a2563000000000017a9142801702f6cfa051efe95855615f10d801e8c87c7876c7d170000000000160014757d7e9c43c2e544e90dcd61bb08416465a3e1b697c322000000000017a914a37417bc67cf0010adf9ead98610a1ecd3737997874b2a1c000000000017a9149456a5fed8b8dcad27db2a960a2f61b1a267be198742c202010000000022002042444da6b7b85fdd6018a2b1db440a510d8465dd69a1c5131100ad4a80e2b7816d2888070000000017a9140cba5f33196f03d6414f7519a772ad4bd47210da87e8e515000000000017a9145f5e5dfece5d562df2750f183cffc87837f11a20871448330000000000160014df71dd05505bceec3679581d1fca94eef0bfa9db72fe28000000000016001495d165ba40e59ef570b4acd9cf6f35f2c8c81165afbff001000000002200207f6b0309fb368f6c956ec910c747d3af7c8ce57a8f0aef36361675a5047ae012e0533001000000001976a9143bc97e769d22572c155a613612c52450fc96744088ac6fae85000000000017a91480fb0e7c1399a0d0111c17b302890d96a38442af874a5816090000000017a91438d7463b6717477f77cd3872c98e6dd86bdc070687f0ed380000000000160014d2023810c1b46c23f9e10897234f51d1f22028f760b966000000000016001411ea06798939bdc96965b900d05e51e118bd740527020a00000000001976a914edfecc730fe114712b9b476bb714255ed132222a88ac5d8c6200000000002200202efed53514c3a51f830260fd6f02ca966e62c8f09afc18816f7b8b81df799329c8218300000000001976a914cba04a706c9a5cabb2e745b97e5368656fe7b92488acfd2917000000000017a914454b96995c25297ecb3f86c7ded99423fc2898c28728ae58000000000016001423b66bb9a31b8ee19206aaf15063976ba2d33b5591798600000000002200204d531ad99782381270b7db353e5b6333f49264390fa05a97ac5738680f4cae55d0fc6116000000001976a9149a377e6e011cdedccb0f4bb3555445b864ccd19688ac8a194d030000000017a91458ab8874d660806ef8f9c5fd92e8849734d7aba087e7dbea0000000000220020838a66bb98fda7d7801ae9f089a297060020f16183bad8b9c4e2561e1a93272289531a00000000001976a91432cecbe493e34ee5b67cee7042cf346c69f248eb88ac7ad562000000000017a91428c4db8dc8b4771f1d59469c09ed1733525a83478754321100000000001976a914022316a2269be4ac1dfb9ab310902273ab572cae88ac8320ea0000000000220020061d96527401c863fe41c4352e78f7e9f6df44bdf69eb1f74bd605747bc97b4712816b00000000001976a9145e5d41275d67f77b47259527e34b6accac71c30488ac102a830200000000220020c75a8449d3f698d0c25cdee86fda3b5bf2ccf102235f5d5789605d53ca0c200d271790000000000022002099510b22f981b7ae71324f5ce587a2f0bf661723c1e5a5710fed41e16e4282ee7b5b61000000000017a914ee60ea3e4189d4b8972a50c14dbd090f4d5b32b887b43252270000000022002051f77f8ee88c1bc47f834f38294de7cf0cd5a30d57b671bac4a8e2b23cda0f836a0c8500000000001976a914fa9853b1735d424e6e31cbec90c5d6cc397d3f3a88aca5d92101000000001600149868d4bb24dd924fc5c2d88069100fcc92ac4c24d17f69000000000017a9143d2b4ae72dc1fb674c505c3e48549f3ef5c19f9587f1ee4800000000001976a91438ef779fbc09ad797c0179ba755c358a3475b4d688acd8240702000000001976a9144b78f6f99b3a2f0db4d975fa4492d9c7258df1b488ac16b213000000000017a9146c86fa99133ecc863a7467a40a66df4eb2affb5e87d9a323000000000017a914d9cbf0e0079726ab129c36178ae7160585632df9877481af0a00000000220020a3f07ddf98a416d5038b626055b9749e17648d92f85d9bb3fcc7c9d0ae47ef5c41ccbd03000000001600147e8f6d6295ebd577ea1b579c5701306d935c6f64ea37e60000000000220020d631aada07d7a39f58f0d7453a155c84625758beabdf02490ad67dbaa35674ca4aa00100000000001600143b792aed9e5daa59d680352eebfd933ca6e2374c9824d0070000000017a914efbe93c4920a418a14bbb023c2e64ece9d3383ee87084a4c00000000001976a9145a1b44d65c5e2cae78736ad334907c27a03e3c8988ac3f0b2900000000001600142b61b00e18024c492d38cc1946b3bc3d985acec2850e3d000000000017a91488bb4888ba449262ba2acc1f1a9e14e5f4fa80418776a25602000000001976a9146e3aa22256b638f2f87a40b3ba9a84687029acc088ac702fcc00000000001976a91462b47cb5dc25814a23023ac69efdc12f5141443a88ac82002306000000001976a914d84b8ba836a978c9b0c0e3bc27f090d64b7eef3188ac183c63010000000016001423f3c8adfa4d7b2b4c5654aa0f09d9f789e724ddeb52150100000000220020e97a0534229dc3b99e741cd6640222574ccfee6fe7444cf192b136537ee2b9d27a665100000000001600143e191ebbed6154ebebe4a9809a9d1bc7fd355c6f05af12010000000017a914fbb1708f162357df887a010ffbe01b384d9376c787384413000000000017a9147b81789ae0d5848877e9021caa3904dddbb8e606877e5f4e01000000002200202fb7542d8d8188a772ede3e4a221908ab243486f8fbecb0d70e9cefd3bff9d2fa60b1400000000001976a9144aefa51a5c34f77ef73c301ba27c7fdcf2f9734788ac61db5d00000000002200201eb471622f9b5c5f99831cda4578c519604726593fafaf5cceb0a47ab2baa55b2c06120000000000220020fc729746ede8cfd6caf75261f8b6ed630a01c912b747cd789798b35be985fd63225e850500000000220020e14b4bed6e592f2b75f4fb80c46a18b778c2e15d12fe4af9caa8b5012940c80798ba1100000000001600140fe57128453b6a7b6c24dc3774f3677ba73e5dc4247b9d0a00000000220020f568475c10842d3eb8f0a1308b31e8e7dad9f613aad309391bd696c40541004974398d040000000017a914d4db11782707bbd1b48a1f7638c15a7744f7b7f987a1e702000000000022002099604f392648fae7e3db3dd1875e98b4b217cf6fcfd01d0889623eb5bdbd212715a423000000000017a9146642687f0cf3182d3dff345e12bc0ca78e2061a78753ce530300000000160014de552fad74f072310801b4f85d0b6d1b7d088d2bda941b00000000001976a91447b28c40f81ae390b34a573c443c8c702ead3e9d88acac11e40f000000001600141700b4e07fec57e80e6d32f881c9ba2625f4608634a5b900000000001976a914f50df06462ea72e6b8b0e6bdf854bad6dd390dae88ac338bbb0000000000220020a25dda37971342c1ec45c6e7223db9a53422657d20f7072e3dd54537dafe25f0ef62bd0700000000220020f6af70f3906a80cec5f078498ea78aa4f12c2f1698dd8981d213c06b6d7c7446a10d4f00000000001976a914a736f52061972b8731e28d29f5b1a530f4cc82a288acce664900000000001976a9148c521d5e2b576a2862fc5582357b1a16a46f2f5088acf6ed331700000000220020683f4012a4a72205fd34395f48e7143349868dc4e4f511e8127c754c73191c054f571c0000000000160014c012361a24db2aa78c9a34b81b1c9389bfdcebf6e1d0a10e00000000220020ac7d271dc00dcf4ab1256b8c4ae15cd37accf032dd1a00ae55d150676998085ed6c20a01000000001976a9145b9ff0f0500f64bf8ae2f7609beb3bc222ad319888acd02e3c0f000000001976a914bbc705f2f248b9f58ea8d9d6952e37a39f99a63688ac658a141000000000220020fbcdb50b171efa9d942fefdcc9692af1901336f20fd271bb4e1a225c9c7cc0e076501900000000001976a914ac3148d1e996c2c4c9e3c556965b17b071ca6e5c88ac82007b000000000016001402a4ad07136ce6c57d487df3b084fb207105a33249e43b00000000001976a9141bf32b93916d3e7aefea706303db243bc4e8044988acfd6d4002000000002200207e60c7655a948888f473585ab4070532b32a8aeeaac157c06346a7240a380c2c56f041000000000017a9148241531ce543638296d367ca6a5582878be4d52387e7f0cb0200000000160014ba7e481361fd153416ba3c769fecea04853df4900035210000000000160014f33ce746cc4a788efe1917c353964cdb91b9cea3a74400000000000017a9141ee03164cd150a7ee8d6b20ec6ee7cca091e52d3879bee67000000000017a914cae51d03c5a21009eb59f21d866b5322cbb0c9cb87d2f70000000000001976a914f224a25f7571513f151f545dde2e5651c730da3e88accff930000000000017a914ff6a67ab6553201593855ba6d464de29690fddef8703da2300000000001976a9144d88966cccbc91a5b02c24cf1ab572f01884757588acbcb53e00000000001600142cca05b48b099516b0415e3eee4c1d4e37a06e51ef383e000000000017a91413387d59374e2902d8104e94ceaef972c8772f1387c04c2700000000001976a91431fb2f4d5d91f265b68af597985a5a9a9ef107e588ac9df5300000000000220020047773f4f2ee3e7c10fc7cb10fd2d55cc7a44f40f6e029662421adfebf5cf7d202a501000000000017a914662dccd7f87359202cec7f4191e81ab40c6d6e8087fb8c42000000000017a91493cbc7dbc80bf5c943bd4f30a9559d9c698ccd2a87eeb20100000000001976a914957bc6a064c17757a8c701f49ce724865b61a84588ac34f71500000000001976a914aeeab1f0d9a9233a865306b31e77d8f76c46c42588ac4c1514000000000017a9143e17ca0cc1125598bf7ca4237ff7c636de9a5f1f87de1a0000000000001976a91489b7260548172866e4bab9b986ee6bdaac52e36388ac66a10000000000001976a914a7713b1802e761de5975b61a341eb713143ae4b688acde1a0000000000001976a9143198360ac3d877e13e20c66327dfe4d7ca9616ab88acde1a00000000000017a914e59e605188d61a92946ca1d910fd80d1e3dfc89787bc3500000000000017a91473ea5fc29c0e3f512dba51780b9193186851deb187de1a000000000000160014b76a1f99afd29bc2aeb603e432b987eefb4250d3de1a0000000000001976a914999b3ea90a894ddc8e199c77b4530235cd8c4fb188acde1a0000000000001976a9148d7ea3f62eec34d5f49fd89fe146da5ab7800cb788acde1a0000000000001976a9148e49d0b94904c651aea497961748280c4efd7b4f88acde1a0000000000001976a9144f57e26a7270bb7e6f364c5bde08285f5246d39088ac776b00000000000017a91454d61fd19dd494e2d1d68fcd4936738af4298ff68794ba0400000000001600143ec2301f68ecac2ca9ff87a0c4b98c1a58cefa35c929000000000000160014b5f708e7d819a46be5b0d1d1a0753cd05e87fc01948b000000000000160014512d10c304604f8ecd324a03be6c28fd1f4114b0012300000000000017a91453412fe523b2fa6dd0e2d51ca6c04346603c4c2a87ca370000000000001600146afed3964b642c26468e493c6e371ac80e958dd340db0600000000001600148dad9f6a93987d24a865c152ed043694ba97b05c1a97610000000000220020683f4012a4a72205fd34395f48e7143349868dc4e4f511e8127c754c73191c05e2131300000000001976a914322e3034eec5f5ec540ff3af59dc2b76c6885e2688ac078909000000000017a914d4f0d9518f008750963bcab32c18e6b65a52d71987525210000000000017a9146f29b552c7eefe1c3f3e7a0f3f7a8f87090aa61187201c0c00000000001976a91403fe68d6e4aca4fa07a1dae67c98ef99b815e25388ac46730a00000000001976a9143de4f70ac6c686dc01a8a8c5c07449ed8075109e88aceb2308000000000016001497c504705a7809b7d77e92df0685cf26d391848a89d302000000000017a914c0551a107be69045ce1bcecbeae91f9c0642c77c87c82b0e000000000017a914edd45d89d0b2389b9066beca83da35ce82fd3bbb87031c0000000000001976a9146c9cca5af732081ad64a99f25e6d6ef4c1c1767488ac234600000000000017a914f6c619a5f845c77db76ab26bc948437b00529dcf87031c0000000000001600140654966e03dfc2e99b92bf2f47f329a64ec7dccb1f2a0000000000001976a9140002f49af773a4b1f499acae131dca51a4695c3c88ac3f540000000000001976a9147e4be5b37b80d82d7d5765c92ee02ba33c9665f688ac64f505000000000016001455d81b3db5e16f3c7a88276a969384a3997259955bcb0400000000001976a914cd2334bff96a27f19c52d1d8c35b5773cd2cf0ea88ac2c251100000000001600148d1d531ccece61f64a318bdf4f2986d4e3ff8df3c19620020000000022002035d9942ba1fa527687736fd244c20379921b09c2d308f71d8a73b837c316b09dd10c4d000000000016001460f018abe8cc4766fa0f0a19afcc78a06755b90930a70100000000001600145834c2ae3a639ed740a6823019308f6df6001b1e30a701000000000016001412cf52e211620ce81915c3c65fdfc2b314bac7dcf6510300000000002200200faa629bd161883fc84344a99559df151f9d62c61bcb867ac3bd972d5c701fee5c8ec5000000000017a914af157bc8dd70aca22a00b9b2f03cad935daad39e8700000000"
    tx_decoded: list[BlockTransactionInput] = blockDecoder.decode_transaction_inputs_from_raw_tx(tx)
    print(json.dumps(tx_decoded, indent=4))

    print("================== TRANSACTION DECODED ==================")
    tx: str = "01000000043fe3f3d1dc833f7333a9c38ddc547acdd025eab8ccf4c695702e8209c95ee70b00000000da00483045022100d93edf8fb82410f2005dc8d636c40a756227ce7a122b755a9d32ab3ed91d16350220758adf19bc5411fba5c5967745d8f4d9a314c303c148aacd59fe0df6dad2fc8d0147304402200ca0d4dd25d7f407bd6184297e041d5cdaece7934c3246fa0fd63de05ae7500a02204eca7856e8f2e763baa3b417dab7c0ab2409dbdab92e6dd4ceec3b79e9c317e00147522102f1ff11c3b2f8f6a7a636043adde524e2e130ce23ca7b364ed868a69d3980da5c21034f0457f9ceb8ba7a6a49f242f565f12f7039c996b9dd9a63aa812d75e51638d152aeffffffff7df1df419b2aa8bb5d0812e02afdb1a81241503ac10fd98b189610bdc3aec91ff4010000db0048304502210096cd98b4f39f13d9e54466bf09b292f86dbf4738a09ba1599f79a3e51eeb5e10022074a2c36d1da95e5ed94768fb1525689820dcc43b80ede9d2612c19b3f6bee65f01483045022100e163709303cd20029ef8c7e9a23bb3253968f684f3f3ec4dc8c6b6a750261c6f022007a93f04ebf911713ee347cfccccfc858b22017964b98281e0cdd9ca84fce04f0147522102f1ff11c3b2f8f6a7a636043adde524e2e130ce23ca7b364ed868a69d3980da5c21034f0457f9ceb8ba7a6a49f242f565f12f7039c996b9dd9a63aa812d75e51638d152aeffffffff9ef1d1fd18b4e8fa6cbc250ab8a184ff55aba1b74b08bb6194596b673f5813ac00000000da00473044022061e7d3708ebb10aa76d80099a2d5c3690f898a6008e21a0c18d741d36aebb95502204b6ba364cece90b0fda5927da49f1737905a47bed00dbde28cf0e966126b2cdb01483045022100cb08dde8a2be0d14866580b00d276f5355bf552ef1789cdd9ea9ea52b09d660502202bfd901ffc36e61ace4b42bcfa2b8d86b53747910790c49e67be91725ea92d010147522102f1ff11c3b2f8f6a7a636043adde524e2e130ce23ca7b364ed868a69d3980da5c21034f0457f9ceb8ba7a6a49f242f565f12f7039c996b9dd9a63aa812d75e51638d152aeffffffff827db2f6433f72b03a6327c4a586643f3bbadf6ab55fa0b0a6429db35a9986bb63010000db00483045022100c57fe8ec1ac092887b262baf9006b7b56c436032597d86de8a2a0f3a0eef306a02204c2d582050e6528f14320898fd7cab7a40bd0d864d2173f80170ac9866b80354014830450221009cbbd54099841da13b453c132330fe140b2e3b81208e47402dad2b94cc8f0352022031c75c254efe87df2150015faf3143c142162d49232ac0c124728761c80b011f0147522102f1ff11c3b2f8f6a7a636043adde524e2e130ce23ca7b364ed868a69d3980da5c21034f0457f9ceb8ba7a6a49f242f565f12f7039c996b9dd9a63aa812d75e51638d152aefffffffffd5601a4130d00000000001976a914f20f5744c526493965fa5ebaa0adde3c49ddfb4988ac456b0900000000001976a914d61c26109b62d6d52ae62294c65718452485341e88ac6d620900000000001976a9148c2504d3a1b1951e47c67ec3102dece28effcc2588ac9a470d000000000017a914f9322bccffd14d6d5f1ad681e2a4cc6257edb6078763b90c000000000016001451e0b46a0fcfa1b357d7a7f6e2c3dadfecedcd3b579d0800000000001976a914e757e66a2ba68cebc7d37dfb6e03f70ecbb2aa1688acbec00700000000001976a914e0273eb5f5d6604966275083b20a81b5e7ee9a0688ac140569000000000017a914811d16a8ea7fd0f9e67303a779a36823738424708795775400000000001976a9141dcff52a220c6d585040260576c05212f3154ce088acc8c707000000000017a9146ab852c6c641b94e478844833c9c802d7df181b387e090230000000000160014e7b6da19a0c1f2f336b113128be37ae0b7c0a5368cdd0700000000002200203a8d8a4b94f19c2d729333cb742613e61fd33002974c133509997568cc44cca29d9d080000000000160014cd6f71f664150cb4580e39ba13e2353dc73d23ed18060800000000001976a914eadecf61e5c88d7888694f0fad57ae10209ada2188ac82d42a0000000000220020e42e925f342d61ca31ced1acb4fabfc08a867f43c44e90c50a3e726dc15469121c4745000000000017a914b3f62eff69d20ba641d755980eba0d6a443327e187ce7b4d000000000017a914ccc8dfa42083393c21be76dc3fa1f9aa592ab20987cb6909000000000017a91403e0a87ae2dadfffd55a8224c16fa7ea6851679a8765e707000000000016001452b3394a4410c8810d8c1b6b31b7610270d44c8ac0ff83010000000017a9146ba34c01741dd497b6cd2572b060e9b5b3ec297f8703020a00000000001976a914aea17113ff03712aa19412524e791c99ffcaabf988acf74d0a000000000016001448616cb875aa61f09ff67cb931a3544ac318c5e3a4a7080000000000160014bbe092304c273ae1dfc61c99fc045a53988971c51b79090000000000220020b53e61bc57c4b726a53cfdcc4a8c685a1646fc18695ddc9d6057d003457256a425640a0000000000160014603d78a217cc840fe2f6c94dea82c77fe0b4788d09a70c0000000000160014b514c1b71bbfe9007ee33db210f5d8d46ab72650f6a40e00000000001976a914db144d69edcaa2f52556fe0aebc0b163b9928f8588ac7d45220000000000160014d1bf34733a30bf459d44ae6af6265fdd8a04b59de6bb2500000000001976a9142c66b5fa638a611c2e46863eef327c9f7dbdc8f188acc9101f000000000017a9140e569509ac7fc5b33f48f29fc3e43dce5b67e9208787c507000000000017a9148adc307e3de0b0a267c88ecb14915201a28e2f658794ba07000000000017a9149c483adc7a0bee8630a48ac60d96cda46e8fd38a8726a40900000000001976a91442dc178c3309451d2f68ad77ea22f2974c84ff6b88acc1b0070000000000160014451be5ca98deddb2360aa31cf1eb4e3ac3267229e2bf0e00000000001600140c903adf7b7aae30a67f75e013527186dc247931ff740f0000000000220020bbde61ac8dbaf89ba0261dbb03a949c232903f7ea1fadb4fc0f0ce06a66960c4ff8b0800000000001976a91427344f04565c9dd4e8935b96d6176d660b41cf4288ac33650900000000001976a914536d3353579644b06a3ab8d278f45ca215ede4b488ac9cc308000000000017a914a79eee04c421e6ea5bf5bc25cfe48833f7648f5687ee1a0e00000000001976a9142301395d6660c565829061c4c6d545136ef0d1a288ac4baa0700000000001976a91481f34d51b75faea4b519e9ca0ba6da102649219388ac047108000000000017a91451ad7f775348221e13875fb69c0b89d382925f518792b51100000000001976a9143c38eec5fbc95c866201f31306ec8484b7feb1d388aca811080000000000220020e4f420707ee739c200a69e7b0fd70f191bd76b92255af8bade8280550d1899521dd30a000000000017a914ede45383cebfdada166a762473832da748ac572887358e58000000000017a9144e9d065688c97a3db011fc9f66c473e5c7515b0f87f706090000000000160014584f0fa8966f4a451334c8f916bf0401aefb54bdca3209000000000017a914a1e87a795891e99024d5d6d2789621526ac8b229878cac5b0000000000160014aa6d680a3d4826cbe511a26c2eed97e2574db17b631208000000000017a9147454e0f27d88f7439d6f22ec740bb52c1abdafa887a1540900000000001600143a78a1d8f4354301c107e573044429e3f11904d2d41208000000000016001423f4cc84f0eb1bb16b41f060ed72b246347bf73cd3a20700000000001976a9141f77a13970f615db05f3f80e6bcd5c6f14d44bbd88acedf709000000000017a914ff70d487299b70ca4d47657624b6f39377d7385c875c4d0900000000002200205a284ed5af10a30ea041895774f9d8d0d7f48bd45ee927a66dabeb5d3d2b9dd1734e08000000000017a914de11cb5452da5eebebc52301a20f5b13032d1f538711e60b0000000000160014645a4a1377143294b92c9a92c7787891ce7d41ff35b4070000000000220020c172f8bd63e42bb6ddbbe9a871e03224d83fd3b6d5a6b9d58bf5944c7c2150204ba80a0000000000160014aa35225a00ba84e1e83a4068eb32e434b70c898f04cd07000000000017a9140e32826452ad67de8f6ac4b4ef4d9a2f8bcd10c387ff4508000000000017a9149140aac8839fc47b8873d2feea97123bece9a82087d0af0700000000001976a9142f3067f9624b66f44f037b90a4b5348a6b3dd6b788acb7a52300000000001600148db46d95cebfe9e18306a9ba0599f1ab9ffb27d109e109000000000017a9145b091b7e4f1f020a21ddf88d194903eb1bc9364787542f08000000000016001444b7dadef962245f08ac2abb002d2270a792fbbe565d34000000000017a91403ceef2de6d3e7f79205fb6f8692d56b0f1431f88744e40700000000001976a9141f1cb150280f2948213b2bab2f5ac614462c59de88ac366314000000000017a91433c5ced582ffc0807b9386b76d5ebf21b790b17287bdd02f000000000017a914cd6acfd8fd771b4fe764e8dd754cdf46e933a9e787e6540b00000000001976a91437504650eec9d52f518a4b5cdc77329850b3161c88acd900b4000000000016001457cf919b78c7f256afc5e59feb9f27e3b940deab0c1c0a00000000001976a914259a303dc91ba077e323e94e28686fe0b76df2ad88ac66b10700000000001976a9149fa403bb0cf8d93e0f372ea9ac45267f5bc6a2e288ac28b60700000000001976a914efe533633dc721b51f9560a3e5b1d934c719ec3588ac8a1a7600000000001976a91415eb4c9551f520aaf8e0992a22e63252e2502c1988acb1a207000000000017a91407be2033d21a452c357e99fb247e03ab54854e1d87945d0d0000000000220020bb271aa470560e3b801ea162c8bad6669ca128941146132cbe1573ce48f05340691f0a00000000001976a914cb90f36a3c30ab738c3340d6f600f794a7da9a3788ac896d0800000000001976a914f48faaae2522aa8fdf27f9844f690abdebd9965c88ac269a30000000000017a9147c7c3d79ef7fcf829d5b148f3eb65f259fd28e0e87730c63000000000016001482c92f14a52189bc38e83e9da2df6dd4490a6f1680bd07000000000017a914ea061f4c9deca9dbb4529a4c334f3607110797be8761d50900000000001976a914f8399b4c8524085060abe0e6b7f33fee693c335488ace2a207000000000016001465266f4baa753ca3b2457da91b1ebafbba4319f310080800000000001976a914754d1a9ae8c0f8b8f4fdb279e15bd124b3f08f9588acabf90800000000001976a91493d7790b1e2774bb82c0f34afc153d2c01ae04ba88ac49ab07000000000017a91466c3025db4cccbe6186c4283d269241cfddbd1988725340900000000001976a9147c85d5ff6bc4850c4f29284a7dce5ffa34cb6f7c88ac7d8f080000000000160014be07152190ca0c198735f9925445e9ab26e0b7715d74110000000000220020d3380245c2371ba452ad3762d41d321d6c63a9b2d1cc9b2724bc21a5c828bcab91b50f000000000016001495830ad22fd9112099701389fa6111551365308e906627000000000017a91471f7eedb90e6344379eeeb5b12ad0a8b8eed940c8721d509000000000017a9141cc402a331a166a45e05eac2fa3317e8e11dfb1c8702ef1e000000000017a914bffca9a20bd16870b3e7be0022efb487bb307d60875f091100000000001976a914206ed3da7885e186c94d123543fd32c639a0f6cb88ac9cef0e000000000017a914e170ad2ad244c4ce9c8ff732aa53149e512eeace87cb5a09000000000017a914f1b26a42d4a7793c2f263f11a649ea45dbe748be87f97b09000000000017a9144a8d4942fae11b1efd574b1aad42c2528ff31d6f87fc5f0b00000000001976a914c226ba4de47eb29603b6531841c0a17ca32f6d2588ac8b9809000000000017a914795acf91441bf988d7ebc4708022fc23797a284587dcb11c000000000017a9145e25ab53c2a95912ccdee7260a0d123c0213b95a8752c007000000000017a9143d7684f040411ca192be6a05a1b2a28ef8e94864877db307000000000017a91420a1b612f92db805eaafcaeaf86a6c0c9977970e87587209000000000016001452bc616870d16fd4215347b946b5e3cf67329ee632fe080000000000160014d651b06ffb99bd57cf0c1a56781bb1de570ba963f1450f0000000000160014cfee80338f0cd24da28316254a2a09c2dccebb43e90d08000000000017a9146363e8ec06e50e85808934c42f0bda0b905edca9874ca60700000000001976a9148b9a6cafa47d8b0c63b965de12416184065013ae88ac25d00c000000000017a914759086bef4b95964b5e73d291179fb7320e5ea5a87b3d614000000000017a914d9c11454493142dd7131ffcbb1df215772c68ed587c0b607000000000017a914cf77be78338df3ecf4cecf40b2071af35e54ac1d87cf1908000000000017a914142b3ba73f249d329e162a43f3dfece058696e3987b5010800000000001976a914a0706b07774353e43ef790d5d6ec9b25c917cd1688ac4db50700000000001976a9147c4e684824ea41a7d21ef140e064f82a00defc2c88ac7a7509000000000017a9145de3ca96fc7f8bf7e1ae01e27e30ceffaf4ca5a2878ba10700000000001976a9148b3c013fb26e0ed0b33958be254323bbe2f2e5c888acd4bed4020000000017a9149cf6199044257c175b9830107b7eeca522386a2887b5d40b00000000001976a914cb78c14af50916a2997cf341bd5ce0e013a222cd88ac50760b00000000001976a914e0f5d8a846aadebe12634cfc46811d819e2cf76f88ac9eab1f00000000001976a91411eba5220f38feaa0a855d84a89d03a52064c93c88ac3eb10700000000001976a9143e40481a2834f4b4a09c29875ecc9bebab24f5cd88ac1d1008000000000017a914f2c098825e2a2a92543731af5af5c91708939d9687db650800000000002251200341a8dcc8405d6a09c2c00b7977c184d9fbe3ed11c4b373d634ac1654a143fc61ee0a00000000001976a914524dd72fcc69b96d3fe8090d25fb7b63970a4f7d88ac2ed307000000000017a91444cb041e1c393e4e877e2a0d4f63e6e3d05341d78784f10800000000001976a914d78979c28149685a91a1259ee2cc10bf3b7c211388acd9040800000000001976a914924474d7723462f391a70576047bec8b634d66ee88aca7b10e000000000017a91444051c459761e0caa833b85c6151369706e9453c87053c0d000000000017a914f9af9d1b5f71a5271e2183ac73159f4d856d79b787426508000000000017a914080d2664a6bd9c6f1692fffe6e3a22bd414e89988736680a00000000001976a91407b52d788780c7c495b10af9f714a06a7456051888ac62ec0800000000001976a9143e5e5161e2bd27af00178526185b4d4b8400925b88acc15a0b0000000000160014f2d1788464d5644a1a56d2a73e87e48c03ca1e9276b00700000000001976a914122dfe5fc40268574b8247edb08f1ac0bc10b8e488acd9d70700000000001976a9145ec3fdb0aadca71762764d33113b594badf5156688ac1569080000000000160014be83e2375327999ea8b3de37760b9ccc052a9643831a0c000000000017a914078a6c87e5ae6fb6a4d8dfcd1ada0fbef7116947875d7a0b00000000001976a914366b11353487a5f42ecf49ffb13b8f73cbe0c57a88ac20bd0900000000001976a9146d3c6d86a831783d7e288a078f96a3b01cbd5e5888acad351c000000000017a9149c7a58c28a7a3b94c6197be8fbc85bc7c7fd949f87d4d107000000000016001438bfa3a5f0108851abe18206b2e42bc5cd69d85d336a0f00000000001976a914f154f69849c59e5e42466ecee299cdc0605d876c88ac790f09000000000017a91494d50ac1abd4c47fb039ffd50ee0c062aece6b3a870dfa0800000000001976a914fdacd50b161b1b85648a40600a4f155e5f40d66888ac9fd511000000000016001470ad8cc7744f92aa1b275dbdf5fa09ba5007a65fa6780a00000000001600140865d5ea0758d689b3f32159e299282a91f52843e8761501000000001976a9141837a306002d0e04e17cf5e206b749b09138f0b588aceb920800000000001976a914a3b3d5373a66296701295a54dd4b4bb984f6385b88ac0890080000000000160014de90b4cef578b88c520f86221c08c0c03c7330a001c20700000000001976a914f7cbe2343685ba86ccf40986622c7f962c9f3b4988acaf25150000000000160014380d52a5060f687266dee936f6a47424ed6df183d8400900000000001600149a4a14f762848581ad5d302118945455c853980e21650900000000001976a91444791dbaedb1c0c4bd672f7be761a116fe4dd5a088acfff70700000000001976a9143eae8bd216c041d25d1a1e1f2125d53808e23f9f88ac4ec4630000000000160014d04ad39197cf1cfeb006f4a0201c0a5f32096ef878d40700000000001976a914fb92165754d823b1c73462bbebc25803c99fb7f588acf0f00c00000000002200201c78b634e3ec8b007e666fbac434d42a4ebdaeec1903ddc8296ee7a47e048f5f89d80900000000001600149b7f3bc413d0eeada1359fb2f741d30dc173ec8d815d0900000000001976a914fb89ae489b3678f1814677b24676d6497cc40f4888ac1ad407000000000017a914d6b457a44ec446afbaed33e0c70dd333492a5e508710f51f00000000001600145eed8c7399104dfbc32fb40c8530752a3a6c82f1a4d70a000000000017a914950e59478e2b399d27f816a18bc4d82b9deb6d69877eaf08000000000017a91423bfd33b104aabb3d6f64137fb5eddf889ccba8e87a019080000000000160014ba337764cf3549a0c9a8e936c0f29230727fdc07b6ffd400000000001600146d68541dfe10f351d679fa36cb65346b4d8650974f330300000000001600147ba3a9b3721fac95a0830e81599b3def9b3baf5d343928000000000017a9144a6c1df634c0f8c2420a29dce7f6d4c3adaff22b87f5d73500000000001976a9147665fb32ca3cc9d46ed7d6b84bdb442c0ccf72a388ac75755b00000000001976a91480f4de0660447e3fa667a236fa252f90f0f6b12988ac7d9535000000000016001405e19e1b67950670aeadaa4c1e15c7bbfd33f13d44b908000000000017a914e50e7a99578b51eed30ba362337b4ca41854d898870ea02e000000000016001440f27dc046f1c996678e1e070ba244f773937f1c61913f00000000001976a91462b47cb5dc25814a23023ac69efdc12f5141443a88ac332bd200000000001976a9141f109e19a2f0d46a32c423efb9b7e507a07fce3188acb5a1d8050000000022002098d7824b9a9dc3f11c0e3f6783740a162b74874ef9a79b17fac7b1739b1d2cbf58278c000000000017a914f563b4f0a32a56e4db47afdb5f46308cf40f12f587a01532000000000017a91447b775ab23ba4dde75b476b6696e16a678d3f8838725ed2d0100000000160014e64ad6410efef4c1d31719b6a47287d629dfcc114ef6310000000000225120f1b99ed53f914129e299934473c453577ba45bf4ce6449a238d85d380a4267a06e4e4b0100000000160014977a8ab28f1515c7964988184deaa3f7657f0d8ec69b5a0a00000000160014e342a3d12e2cb80f9522d94a7955da4e0c92835cdb1a2000000000001976a914308bfb39b7bd31061c836743567ab85b941b058d88ac8b4b890300000000160014c2d95ded8e7f60e270a04a7619cc414f44d8dbf5821617000000000016001475779c0a479231e7b766fa783b525f77591c23c8fdb81400000000001976a914933a19fb2f7338b5aad78b16bbd3ee57ce2434a488acfacb1c000000000016001475b5c00c94fa96d5ce9595760a8e60f67578ed14b2f3810300000000220020840ecc1c09d05b4fdeef04729d2d12ba508608a9e1899963969f3388e3d31c0656b90f00000000001976a914854a8fb2673303563f7d45c10a28f99b6bd6af4288accea8f80f000000001976a914897fd9c4f7184fcf71c5535f70e1e47244d3fd8588ac8fc21a00000000001976a9142c60fd86e2f26b064a1204f1ee6927d1c6af170a88ac32b81c01000000001976a914be8bc9508bc647561feb7deb908e77cd74ff1cca88aca7440000000000001600142e9af69ee3066fd50206822878f8a95d4885f88af1113000000000001976a914d7b28dc5a70ee09bcc6541433467bcc34cc6421c88acb2937c0300000000220020beb957c4ea55ddbf6ef3c4d4d71c24ef02adb9950d647c593928682945cd313337471c00000000001976a9144b70fb97e079a175ca908c04624084585e2674cb88ac5ce9671a0000000017a9148e15b2feb07007b0a4ed079baf600cd21db7e5ca876b326426000000001976a9147c154ed1dc59609e3d26abb2df2ea3d587cd8c4188ac4611150000000000160014ece678d0a0f0609e51133f50138e86bfdfee4a90700117000000000017a914115e35029953009ccfb87441c029dca9a3412edc87fb855c1900000000220020ed6f65aa3bec00e7c55e3a809c919b83e933a881248f8b7d5fd987e2b05c98fa3a08f20f000000002200206b8d6fbe7ddb736347b9e623e464ddd9d1b42cd2262b964b091195bc6e46a6ab3a2563000000000017a9142801702f6cfa051efe95855615f10d801e8c87c7876c7d170000000000160014757d7e9c43c2e544e90dcd61bb08416465a3e1b697c322000000000017a914a37417bc67cf0010adf9ead98610a1ecd3737997874b2a1c000000000017a9149456a5fed8b8dcad27db2a960a2f61b1a267be198742c202010000000022002042444da6b7b85fdd6018a2b1db440a510d8465dd69a1c5131100ad4a80e2b7816d2888070000000017a9140cba5f33196f03d6414f7519a772ad4bd47210da87e8e515000000000017a9145f5e5dfece5d562df2750f183cffc87837f11a20871448330000000000160014df71dd05505bceec3679581d1fca94eef0bfa9db72fe28000000000016001495d165ba40e59ef570b4acd9cf6f35f2c8c81165afbff001000000002200207f6b0309fb368f6c956ec910c747d3af7c8ce57a8f0aef36361675a5047ae012e0533001000000001976a9143bc97e769d22572c155a613612c52450fc96744088ac6fae85000000000017a91480fb0e7c1399a0d0111c17b302890d96a38442af874a5816090000000017a91438d7463b6717477f77cd3872c98e6dd86bdc070687f0ed380000000000160014d2023810c1b46c23f9e10897234f51d1f22028f760b966000000000016001411ea06798939bdc96965b900d05e51e118bd740527020a00000000001976a914edfecc730fe114712b9b476bb714255ed132222a88ac5d8c6200000000002200202efed53514c3a51f830260fd6f02ca966e62c8f09afc18816f7b8b81df799329c8218300000000001976a914cba04a706c9a5cabb2e745b97e5368656fe7b92488acfd2917000000000017a914454b96995c25297ecb3f86c7ded99423fc2898c28728ae58000000000016001423b66bb9a31b8ee19206aaf15063976ba2d33b5591798600000000002200204d531ad99782381270b7db353e5b6333f49264390fa05a97ac5738680f4cae55d0fc6116000000001976a9149a377e6e011cdedccb0f4bb3555445b864ccd19688ac8a194d030000000017a91458ab8874d660806ef8f9c5fd92e8849734d7aba087e7dbea0000000000220020838a66bb98fda7d7801ae9f089a297060020f16183bad8b9c4e2561e1a93272289531a00000000001976a91432cecbe493e34ee5b67cee7042cf346c69f248eb88ac7ad562000000000017a91428c4db8dc8b4771f1d59469c09ed1733525a83478754321100000000001976a914022316a2269be4ac1dfb9ab310902273ab572cae88ac8320ea0000000000220020061d96527401c863fe41c4352e78f7e9f6df44bdf69eb1f74bd605747bc97b4712816b00000000001976a9145e5d41275d67f77b47259527e34b6accac71c30488ac102a830200000000220020c75a8449d3f698d0c25cdee86fda3b5bf2ccf102235f5d5789605d53ca0c200d271790000000000022002099510b22f981b7ae71324f5ce587a2f0bf661723c1e5a5710fed41e16e4282ee7b5b61000000000017a914ee60ea3e4189d4b8972a50c14dbd090f4d5b32b887b43252270000000022002051f77f8ee88c1bc47f834f38294de7cf0cd5a30d57b671bac4a8e2b23cda0f836a0c8500000000001976a914fa9853b1735d424e6e31cbec90c5d6cc397d3f3a88aca5d92101000000001600149868d4bb24dd924fc5c2d88069100fcc92ac4c24d17f69000000000017a9143d2b4ae72dc1fb674c505c3e48549f3ef5c19f9587f1ee4800000000001976a91438ef779fbc09ad797c0179ba755c358a3475b4d688acd8240702000000001976a9144b78f6f99b3a2f0db4d975fa4492d9c7258df1b488ac16b213000000000017a9146c86fa99133ecc863a7467a40a66df4eb2affb5e87d9a323000000000017a914d9cbf0e0079726ab129c36178ae7160585632df9877481af0a00000000220020a3f07ddf98a416d5038b626055b9749e17648d92f85d9bb3fcc7c9d0ae47ef5c41ccbd03000000001600147e8f6d6295ebd577ea1b579c5701306d935c6f64ea37e60000000000220020d631aada07d7a39f58f0d7453a155c84625758beabdf02490ad67dbaa35674ca4aa00100000000001600143b792aed9e5daa59d680352eebfd933ca6e2374c9824d0070000000017a914efbe93c4920a418a14bbb023c2e64ece9d3383ee87084a4c00000000001976a9145a1b44d65c5e2cae78736ad334907c27a03e3c8988ac3f0b2900000000001600142b61b00e18024c492d38cc1946b3bc3d985acec2850e3d000000000017a91488bb4888ba449262ba2acc1f1a9e14e5f4fa80418776a25602000000001976a9146e3aa22256b638f2f87a40b3ba9a84687029acc088ac702fcc00000000001976a91462b47cb5dc25814a23023ac69efdc12f5141443a88ac82002306000000001976a914d84b8ba836a978c9b0c0e3bc27f090d64b7eef3188ac183c63010000000016001423f3c8adfa4d7b2b4c5654aa0f09d9f789e724ddeb52150100000000220020e97a0534229dc3b99e741cd6640222574ccfee6fe7444cf192b136537ee2b9d27a665100000000001600143e191ebbed6154ebebe4a9809a9d1bc7fd355c6f05af12010000000017a914fbb1708f162357df887a010ffbe01b384d9376c787384413000000000017a9147b81789ae0d5848877e9021caa3904dddbb8e606877e5f4e01000000002200202fb7542d8d8188a772ede3e4a221908ab243486f8fbecb0d70e9cefd3bff9d2fa60b1400000000001976a9144aefa51a5c34f77ef73c301ba27c7fdcf2f9734788ac61db5d00000000002200201eb471622f9b5c5f99831cda4578c519604726593fafaf5cceb0a47ab2baa55b2c06120000000000220020fc729746ede8cfd6caf75261f8b6ed630a01c912b747cd789798b35be985fd63225e850500000000220020e14b4bed6e592f2b75f4fb80c46a18b778c2e15d12fe4af9caa8b5012940c80798ba1100000000001600140fe57128453b6a7b6c24dc3774f3677ba73e5dc4247b9d0a00000000220020f568475c10842d3eb8f0a1308b31e8e7dad9f613aad309391bd696c40541004974398d040000000017a914d4db11782707bbd1b48a1f7638c15a7744f7b7f987a1e702000000000022002099604f392648fae7e3db3dd1875e98b4b217cf6fcfd01d0889623eb5bdbd212715a423000000000017a9146642687f0cf3182d3dff345e12bc0ca78e2061a78753ce530300000000160014de552fad74f072310801b4f85d0b6d1b7d088d2bda941b00000000001976a91447b28c40f81ae390b34a573c443c8c702ead3e9d88acac11e40f000000001600141700b4e07fec57e80e6d32f881c9ba2625f4608634a5b900000000001976a914f50df06462ea72e6b8b0e6bdf854bad6dd390dae88ac338bbb0000000000220020a25dda37971342c1ec45c6e7223db9a53422657d20f7072e3dd54537dafe25f0ef62bd0700000000220020f6af70f3906a80cec5f078498ea78aa4f12c2f1698dd8981d213c06b6d7c7446a10d4f00000000001976a914a736f52061972b8731e28d29f5b1a530f4cc82a288acce664900000000001976a9148c521d5e2b576a2862fc5582357b1a16a46f2f5088acf6ed331700000000220020683f4012a4a72205fd34395f48e7143349868dc4e4f511e8127c754c73191c054f571c0000000000160014c012361a24db2aa78c9a34b81b1c9389bfdcebf6e1d0a10e00000000220020ac7d271dc00dcf4ab1256b8c4ae15cd37accf032dd1a00ae55d150676998085ed6c20a01000000001976a9145b9ff0f0500f64bf8ae2f7609beb3bc222ad319888acd02e3c0f000000001976a914bbc705f2f248b9f58ea8d9d6952e37a39f99a63688ac658a141000000000220020fbcdb50b171efa9d942fefdcc9692af1901336f20fd271bb4e1a225c9c7cc0e076501900000000001976a914ac3148d1e996c2c4c9e3c556965b17b071ca6e5c88ac82007b000000000016001402a4ad07136ce6c57d487df3b084fb207105a33249e43b00000000001976a9141bf32b93916d3e7aefea706303db243bc4e8044988acfd6d4002000000002200207e60c7655a948888f473585ab4070532b32a8aeeaac157c06346a7240a380c2c56f041000000000017a9148241531ce543638296d367ca6a5582878be4d52387e7f0cb0200000000160014ba7e481361fd153416ba3c769fecea04853df4900035210000000000160014f33ce746cc4a788efe1917c353964cdb91b9cea3a74400000000000017a9141ee03164cd150a7ee8d6b20ec6ee7cca091e52d3879bee67000000000017a914cae51d03c5a21009eb59f21d866b5322cbb0c9cb87d2f70000000000001976a914f224a25f7571513f151f545dde2e5651c730da3e88accff930000000000017a914ff6a67ab6553201593855ba6d464de29690fddef8703da2300000000001976a9144d88966cccbc91a5b02c24cf1ab572f01884757588acbcb53e00000000001600142cca05b48b099516b0415e3eee4c1d4e37a06e51ef383e000000000017a91413387d59374e2902d8104e94ceaef972c8772f1387c04c2700000000001976a91431fb2f4d5d91f265b68af597985a5a9a9ef107e588ac9df5300000000000220020047773f4f2ee3e7c10fc7cb10fd2d55cc7a44f40f6e029662421adfebf5cf7d202a501000000000017a914662dccd7f87359202cec7f4191e81ab40c6d6e8087fb8c42000000000017a91493cbc7dbc80bf5c943bd4f30a9559d9c698ccd2a87eeb20100000000001976a914957bc6a064c17757a8c701f49ce724865b61a84588ac34f71500000000001976a914aeeab1f0d9a9233a865306b31e77d8f76c46c42588ac4c1514000000000017a9143e17ca0cc1125598bf7ca4237ff7c636de9a5f1f87de1a0000000000001976a91489b7260548172866e4bab9b986ee6bdaac52e36388ac66a10000000000001976a914a7713b1802e761de5975b61a341eb713143ae4b688acde1a0000000000001976a9143198360ac3d877e13e20c66327dfe4d7ca9616ab88acde1a00000000000017a914e59e605188d61a92946ca1d910fd80d1e3dfc89787bc3500000000000017a91473ea5fc29c0e3f512dba51780b9193186851deb187de1a000000000000160014b76a1f99afd29bc2aeb603e432b987eefb4250d3de1a0000000000001976a914999b3ea90a894ddc8e199c77b4530235cd8c4fb188acde1a0000000000001976a9148d7ea3f62eec34d5f49fd89fe146da5ab7800cb788acde1a0000000000001976a9148e49d0b94904c651aea497961748280c4efd7b4f88acde1a0000000000001976a9144f57e26a7270bb7e6f364c5bde08285f5246d39088ac776b00000000000017a91454d61fd19dd494e2d1d68fcd4936738af4298ff68794ba0400000000001600143ec2301f68ecac2ca9ff87a0c4b98c1a58cefa35c929000000000000160014b5f708e7d819a46be5b0d1d1a0753cd05e87fc01948b000000000000160014512d10c304604f8ecd324a03be6c28fd1f4114b0012300000000000017a91453412fe523b2fa6dd0e2d51ca6c04346603c4c2a87ca370000000000001600146afed3964b642c26468e493c6e371ac80e958dd340db0600000000001600148dad9f6a93987d24a865c152ed043694ba97b05c1a97610000000000220020683f4012a4a72205fd34395f48e7143349868dc4e4f511e8127c754c73191c05e2131300000000001976a914322e3034eec5f5ec540ff3af59dc2b76c6885e2688ac078909000000000017a914d4f0d9518f008750963bcab32c18e6b65a52d71987525210000000000017a9146f29b552c7eefe1c3f3e7a0f3f7a8f87090aa61187201c0c00000000001976a91403fe68d6e4aca4fa07a1dae67c98ef99b815e25388ac46730a00000000001976a9143de4f70ac6c686dc01a8a8c5c07449ed8075109e88aceb2308000000000016001497c504705a7809b7d77e92df0685cf26d391848a89d302000000000017a914c0551a107be69045ce1bcecbeae91f9c0642c77c87c82b0e000000000017a914edd45d89d0b2389b9066beca83da35ce82fd3bbb87031c0000000000001976a9146c9cca5af732081ad64a99f25e6d6ef4c1c1767488ac234600000000000017a914f6c619a5f845c77db76ab26bc948437b00529dcf87031c0000000000001600140654966e03dfc2e99b92bf2f47f329a64ec7dccb1f2a0000000000001976a9140002f49af773a4b1f499acae131dca51a4695c3c88ac3f540000000000001976a9147e4be5b37b80d82d7d5765c92ee02ba33c9665f688ac64f505000000000016001455d81b3db5e16f3c7a88276a969384a3997259955bcb0400000000001976a914cd2334bff96a27f19c52d1d8c35b5773cd2cf0ea88ac2c251100000000001600148d1d531ccece61f64a318bdf4f2986d4e3ff8df3c19620020000000022002035d9942ba1fa527687736fd244c20379921b09c2d308f71d8a73b837c316b09dd10c4d000000000016001460f018abe8cc4766fa0f0a19afcc78a06755b90930a70100000000001600145834c2ae3a639ed740a6823019308f6df6001b1e30a701000000000016001412cf52e211620ce81915c3c65fdfc2b314bac7dcf6510300000000002200200faa629bd161883fc84344a99559df151f9d62c61bcb867ac3bd972d5c701fee5c8ec5000000000017a914af157bc8dd70aca22a00b9b2f03cad935daad39e8700000000"
    tx_decoded: list[BlockTransactionOutput] = blockDecoder.decode_transaction_outputs_from_raw_tx(tx)
    print(json.dumps(tx_decoded, indent=4))

if __name__ == "__main__":
    main()
