from math import gcd
from typing import Tuple, Optional

class Fraction:
    def __init__(self):
        pass

    @staticmethod
    def improper_to_mixed(numerator: int, denominator: int) -> Tuple[int, int, int, str]:
        """
        Convert an improper fraction to a mixed number.
        Returns a tuple: (whole, remainder_numerator, remainder_denominator, string_representation)
        - whole: integer whole part (may be 0)
        - remainder_numerator: numerator of the fractional part (reduced), 0 if none
        - remainder_denominator: denominator of the fractional part (reduced), 1 if none
        - string_representation: human-friendly mixed number, using '-' for negative results

        Steps (algorithm):
        1. Validate denominator != 0.
        2. Determine the overall sign from numerator and denominator.
        3. Work with absolute values to compute whole part and remainder:
           whole = abs(numerator) // abs(denominator)
           remainder = abs(numerator) % abs(denominator)
        4. Reduce the remainder/denominator fraction by their gcd.
        5. Attach the sign to the whole part (or to the fractional part if whole == 0).
        6. Build a clean string representation:
           - If remainder == 0, return just the integer (e.g., "3" or "-2").
           - If whole == 0, return proper fraction (e.g., "1/2" or "-1/2").
           - Otherwise return "W R/D" (e.g., "4 1/3" or "-4 1/3").
        """
        if denominator == 0:
            raise ZeroDivisionError("Denominator cannot be zero.")

        # Determine sign of the final result
        sign = -1 if (numerator * denominator) < 0 else 1

        numerator_absolute_value = abs(numerator)
        denominator_absolute_value = abs(denominator)

        # Whole part and remainder (using integer division and modulo)
        whole = numerator_absolute_value // denominator_absolute_value
        remainder = numerator_absolute_value % denominator_absolute_value

        if remainder == 0:
            # It's an integer
            whole_signed = sign * whole
            str_representation = str(whole_signed)
            return whole_signed, 0, 1, str_representation

        # Reduce the fractional remainder
        g = gcd(remainder, denominator_absolute_value)
        rn = remainder // g
        rd = denominator_absolute_value // g

        # Apply sign: attach to whole if whole != 0, otherwise to numerator
        if whole != 0:
            whole_signed = sign * whole
            str_representation = f"{whole_signed} {rn}/{rd}"
            return whole_signed, rn, rd, str_representation
        else:
            # whole == 0, fractional result only (proper fraction)
            rn_signed = sign * rn
            str_representation = f"{rn_signed}/{rd}"
            return 0, rn_signed, rd, str_representation

# -----------------------------------------------------------------------------------------------------------------
def main() -> None:
    fraction = Fraction()
    examples = [
        (7, 3),  # 7/3 -> 2 1/3
        (6, 3),  # 6/3 -> 2
        (3, 4),  # 3/4 -> 3/4 (already proper)
        (-7, 3),  # -7/3 -> -2 1/3
        (7, -3),  # 7/-3 -> -2 1/3
        (-7, -3),  # -7/-3 -> 2 1/3
        (10, 5),  # 10/5 -> 2
        (0, 5),  # 0/5 -> 0
        (4, 2),  # 4/2 -> 2
        (9, 6),  # 9/6 -> 1 1/2 (reduce 3/6 -> 1/2)
        (1, -2),  # 1/-2 -> -1/2
    ]

    results = []
    for numerator, denominator in examples:
        try:
            res = fraction.improper_to_mixed(numerator, denominator)
        except Exception as e:
            res = ("error", str(e))
        results.append(((numerator, denominator), res))

    # Display results
    for inp, out in results:
        print(f"{inp[0]}/{inp[1]} -> {out[3]}    (tuple: whole={out[0]}, num={out[1]}, den={out[2]}, str_representation={out[3]})")
# -----------------------------------------------------------------------------------------------------------------
if __name__ == "__main__":
    main()