from command_handler_registry import CommandHandlerRegistry

# Create a global command_handler_registry instance
command_handler_registry = CommandHandlerRegistry()

@command_handler_registry.register("start")
class StartCommandHandler:

    def handle(self) -> str:
        return "Starting the system..."

@command_handler_registry.register("pause")
class PauseCommandHandler:

    def handle(self) -> str:
        return "Pausing the system..."

@command_handler_registry.register("stop")
class StopCommandHandler:

    def handle(self) -> str:
        return "Stopping the system..."