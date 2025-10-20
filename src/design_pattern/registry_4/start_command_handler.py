from command_handler_registry import CommandHandlerRegistry

@CommandHandlerRegistry.register("start")
class StartCommandHandler:

    def handle(self) -> str:
        return "Starting the system..."
