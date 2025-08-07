from helloworld import HelloWorld
from number_system import NumberSystem
from oop import Vehicle


def main():
    """
    Main function.
    """
    print("Starting the application...")

    #   -----------------------------------------------------------------------------------------------------
    print("\n=")
    hello_world = HelloWorld()
    hello_world.hello()

    #   -----------------------------------------------------------------------------------------------------
    print("\n=")
    ollie_car = Vehicle("Pickle Rick", 2, 0)
    ollie_car.printSpecs()

    #   -----------------------------------------------------------------------------------------------------
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
    print(f"Bit length of {n}:" , number_system.bit_length(n),"bits")
    print(f"Byte size of {n}:" , number_system.byte_size(n), "bytes")


if __name__ == "__main__":
    main()
