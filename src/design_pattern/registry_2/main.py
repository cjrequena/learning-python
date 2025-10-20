from command_handler_registry import CommandHandlerRegistry
from pause_command_handler import PauseCommandHandler
from start_command_handler import StartCommandHandler
from stop_command_handler import StopCommandHandler


def main():
    """
    Main function.
    """
    print("Starting the application...")

    # Create instances
    command_handler_registry = CommandHandlerRegistry()

    # Register class methods as command handlers
    command_handler_registry.register("start", StartCommandHandler)
    command_handler_registry.register("pause", PauseCommandHandler)
    command_handler_registry.register("stop", StopCommandHandler)


    # Execute some commands
    print(command_handler_registry.handle("start"))
    print(command_handler_registry.handle("pause"))
    print(command_handler_registry.handle("stop"))
    print(command_handler_registry.handle("foo"))  # Unknown command


if __name__ == "__main__":
    main()
