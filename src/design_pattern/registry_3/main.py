from command_handler import command_handler_registry # noqa: F401

def main():
    """
    Main function.
    """
    print("Starting the application...")

    print(command_handler_registry.handle("start"))
    print(command_handler_registry.handle("pause"))
    print(command_handler_registry.handle("stop"))
    print(command_handler_registry.handle("foo"))  # Unknown command

    print("\nRegistered handlers:", list(command_handler_registry.all_handlers().keys()))

if __name__ == "__main__":
    main()
