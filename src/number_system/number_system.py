class NumberSystem:
    """Utility class for number system conversions, binary operations, complements, and size calculations."""

    # === Conversions ===
    def decimal_to_binary(self, n: int) -> str:
        return bin(n & 0xFFFFFFFF)[2:] if n < 0 else bin(n)[2:]

    def decimal_to_octal(self, n: int) -> str:
        return oct(n & 0xFFFFFFFF)[2:] if n < 0 else oct(n)[2:]

    def decimal_to_hex(self, n: int) -> str:
        return hex(n & 0xFFFFFFFF)[2:] if n < 0 else hex(n)[2:]

    def binary_to_decimal(self, b: str) -> int:
        return int(b, 2)

    def octal_to_decimal(self, o: str) -> int:
        return int(o, 8)

    def hex_to_decimal(self, h: str) -> int:
        return int(h, 16)

    # === Complements ===
    def ones_complement(self, b: str) -> str:
        return ''.join('1' if bit == '0' else '0' for bit in b)

    def twos_complement(self, b: str) -> str:
        one_comp = self.ones_complement(b)
        return bin(int(one_comp, 2) + 1)[2:].zfill(len(b))

    # === Binary Arithmetic ===
    def binary_add(self, a: str, b: str) -> str:
        result = bin(int(a, 2) + int(b, 2))[2:]
        return result.zfill(max(len(a), len(b)))

    def binary_subtract(self, a: str, b: str) -> str:
        result = int(a, 2) - int(b, 2)
        if result < 0:
            return '-' + bin(abs(result))[2:]
        return bin(result)[2:]

    # === Signed Binary Representation ===
    def to_signed_binary(self, n: int, bits: int = 8) -> str:
        if n >= 0:
            return bin(n)[2:].zfill(bits)
        else:
            return bin((1 << bits) + n)[2:]

    def from_signed_binary(self, b: str) -> int:
        bits = len(b)
        val = int(b, 2)
        if b[0] == '1':
            return val - (1 << bits)
        return val

    # === Size Calculations ===
    def bit_length(self, n: int) -> int:
        if n == 0:
            return 1
        elif n > 0:
            return n.bit_length()
        else:
            return (abs(n)).bit_length() + 1  # Add sign bit

    def byte_size(self, n: int) -> float:
        bits = self.bit_length(n)
        return bits / 8

# -----------------------------------------------------------------------------------------------------------------

def main() -> None:
    number_system = NumberSystem()
    print("\n=")
    number_system: NumberSystem = NumberSystem()

    n = 369369369  # type: ignore
    print("== Conversions ==")
    print("Binary:", number_system.decimal_to_binary(n))
    print("Octal:", number_system.decimal_to_octal(n))
    print("Hex:", number_system.decimal_to_hex(n))
    print("Dec:", number_system.binary_to_decimal(number_system.decimal_to_binary(n)))

    b = "00010010"  # type: ignore
    print("\n== Complements ==")
    print("1's:", number_system.ones_complement(b))
    print("2's:", number_system.twos_complement(b))

    print("\n== Binary Arithmetic ==")
    print("Add:", number_system.binary_add("0011", "0101"))
    print("Subtract:", number_system.binary_subtract("0101", "0011"))

    print("\n== Signed Binary ==")
    signed_bin = number_system.to_signed_binary(-5)
    print("Signed -5:", signed_bin)
    print("Back to int:", number_system.from_signed_binary(signed_bin))

    print("\n== Size ==")
    print(f"Bit length of {n}:", number_system.bit_length(n), "bits")
    print(f"Byte size of {n}:", number_system.byte_size(n), "bytes")

if __name__ == "__main__":
    main()