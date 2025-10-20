from command_handler_registry import CommandHandlerRegistry

@CommandHandlerRegistry.register("stop")
class StopCommandHandler:

    def handle(self) -> str:
        return "Stopping the system..."