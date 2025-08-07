from helloworld import HelloWorld
from oop import Vehicle


def main():
    """
    Main function.
    """

    print("Starting the application...")
    hello_world = HelloWorld()
    hello_world.hello()

    ollie_car = Vehicle("Pickle Rick", 2, 0)
    ollie_car.printSpecs()

if __name__ == '__main__':
    main()
