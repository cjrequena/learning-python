class HelloWorld:
    def __init__(self) -> None:
        pass

    def hello(self) -> None:
        print("Hello World")
# -----------------------------------------------------------------------------------------------------------------

def main() -> None:
    hello_world = HelloWorld()
    hello_world.hello() # This will print "Hello World" 

if __name__ == "__main__":
    main()