
# Class Example

class Vehicle:
    def __init__(self, vehName: str, numDoors: int, numWheels: int):
        self.name = vehName
        self.doors = numDoors
        self.wheels = numWheels
        self.make = "Generic Engines"

    def printSpecs(self):
        print(self.name, self.doors, self.wheels, self.make)


# -----------------------------------------------------------------------------------------------------------------
# Class example with defaults
# Defaults can be used in other languages with or parameters param = input | "Default"
# This is actually how you would overload a function, by using defaults

class Vehicle2:
    def __init__(self, vehName:str, numDoors:int = 2, numWheels:int = 4, make:str = "Porschwagon") -> None:
        self.name = vehName
        self.doors = numDoors
        self.wheels = numWheels
        self.make = make

    def printSpecs(self):
        print(self.name, self.doors, self.wheels, self.make)

# -----------------------------------------------------------------------------------------------------------------

# Subclass examples
class Van(Vehicle):
    def __init__(self, vehName:str, numDoors:int, numWheels:int, numRearDoors:int, numSideDoors:int) -> None:
        super().__init__(vehName, numDoors, numWheels)
        self.rearDoors = numRearDoors
        self.sideDoors = numSideDoors

    # Overwriting function
    def printSpecs(self):
        print(self.name, self.doors, self.wheels, self.make, "Rear doors -", self.rearDoors, "Side doors -", self.sideDoors)


class Lorry(Vehicle):
    def __init__(self, vehName:str, numDoors:int, numWheels:int, trailer:bool, maxLoad:int) -> None:
        super().__init__(vehName, numDoors, numWheels)
        self.trailer = trailer
        self.load = maxLoad

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