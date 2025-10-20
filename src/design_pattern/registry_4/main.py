from command_handler_registry import CommandHandlerRegistry
from pause_command_handler import PauseCommandHandler  # noqa: F401
from start_command_handler import StartCommandHandler  # noqa: F401
from stop_command_handler import StopCommandHandler  # noqa: F401


def main():
    """
    Main function.
    """
    print("Starting the application...")

    print(CommandHandlerRegistry.handle("start"))
    print(CommandHandlerRegistry.handle("pause"))
    print(CommandHandlerRegistry.handle("stop"))
    print(CommandHandlerRegistry.handle("foo"))  # Unknown command

    print("\nRegistered handlers:", list(CommandHandlerRegistry.all_handlers().keys()))

if __name__ == "__main__":
    main()
