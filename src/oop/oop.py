
# Class Example

class Vehicle:
    def __init__(self, veh_name: str, num_doors: int, num_wheels: int):
        self.name = veh_name
        self.doors = num_doors
        self.wheels = num_wheels
        self.make = "Generic Engines"

    def printSpecs(self):
        print(self.name, self.doors, self.wheels, self.make)


# -----------------------------------------------------------------------------------------------------------------
# Class example with defaults
# Defaults can be used in other languages with or parameters param = input | "Default"
# This is actually how you would overload a function, by using defaults

class Vehicle2:
    def __init__(self, veh_name:str, num_doors:int = 2, num_wheels:int = 4, make:str = "Porschwagon") -> None:
        self.name = veh_name
        self.doors = num_doors
        self.wheels = num_wheels
        self.make = make

    def printSpecs(self):
        print(self.name, self.doors, self.wheels, self.make)

# -----------------------------------------------------------------------------------------------------------------

# Subclass examples
class Van(Vehicle):
    def __init__(self, veh_name:str, num_doors:int, num_wheels:int, num_rear_doors:int, num_side_doors:int) -> None:
        super().__init__(veh_name, num_doors, num_wheels)
        self.rearDoors = num_rear_doors
        self.sideDoors = num_side_doors

    # Overwriting function
    def printSpecs(self):
        print(self.name, self.doors, self.wheels, self.make, "Rear doors -", self.rearDoors, "Side doors -", self.sideDoors)


class Lorry(Vehicle):
    def __init__(self, veh_name:str, num_doors:int, num_wheels:int, trailer:bool, max_load:int) -> None:
        super().__init__(veh_name, num_doors, num_wheels)
        self.trailer = trailer
        self.load = max_load

    # Overwriting function
    def printSpecs(self):
        print(self.name, self.doors, self.wheels, self.make, "Trailer -", self.trailer, "Max load -", self.load)

# -----------------------------------------------------------------------------------------------------------------


def main() -> None:

    # Class Example 1
    ollie_car = Vehicle("Pickle Rick", 2, 0)
    tom_car = Vehicle("Knight Rider", 3, 4)

    ollie_car.printSpecs()
    tom_car.printSpecs()

# -----------------------------------------------------------------------------------------------------------------

    # Class Example 2
    ollie_car_2 = Vehicle2("Le Delorian")
    tom_car_2 = Vehicle2("Running in the 90s", 4, 6)

    ollie_car_2.printSpecs()
    tom_car_2.printSpecs()

# -----------------------------------------------------------------------------------------------------------------

    # Object storage example
    from typing import Union
    cars: list[Union[Vehicle, Vehicle2]] = [ollie_car, tom_car, ollie_car_2, tom_car_2]
    for i in range(0, len(cars)):
        print(cars[i].name) # You can reference individual attributes of objects this way - even from lists
        cars[i].printSpecs()
        # Careful, these would error if each class had functions or parameters called different things

# -----------------------------------------------------------------------------------------------------------------

    van_example = Van("Ice Cream Van", 2, 4, 2, 1)
    lorry_example = Lorry("My Big Green Lorry", 2, 8, True, 75)

    van_example.printSpecs()
    lorry_example.printSpecs()

# -----------------------------------------------------------------------------------------------------------------
if __name__ == "__main__":
    main()