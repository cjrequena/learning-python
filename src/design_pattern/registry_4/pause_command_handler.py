from command_handler_registry import CommandHandlerRegistry

@CommandHandlerRegistry.register("pause")
class PauseCommandHandler:

    def handle(self) -> str:
        return "Pausing the system..."
