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
    start_command_handler = StartCommandHandler()
    stop_command_handler = StopCommandHandler()
    pause_command_handler = PauseCommandHandler()


    # Register class methods as command handlers
    command_handler_registry.register("start", start_command_handler.handle)
    command_handler_registry.register("pause", pause_command_handler.handle)
    command_handler_registry.register("stop", stop_command_handler.handle)


    # Execute some commands
    print(command_handler_registry.handle("start"))
    print(command_handler_registry.handle("pause"))
    print(command_handler_registry.handle("stop"))
    print(command_handler_registry.handle("foo"))  # Unknown command


if __name__ == "__main__":
    main()
