from typing import Callable, Dict, Optional

# Define a type alias for your callable signature
CommandHandler = Callable[[], str]

class CommandHandlerRegistry:
    """A registry to manage command handlers."""

    def __init__(self):
        self.command_handler_registry: Dict[str, CommandHandler] = {}

    def register(self, name: str, handler: CommandHandler) -> None:
        """Register a command handler under a given name."""
        if name in self.command_handler_registry:
            raise KeyError(f"Command '{name}' is already registered.")
        self.command_handler_registry[name] = handler

    def get(self, name: str) -> Optional[CommandHandler]:
        """Retrieve a handler by name."""
        return self.command_handler_registry.get(name)

    def handle(self, name: str) -> str:
        """Execute a handler by name."""
        handler = self.get(name)
        if handler is None:
            return f"No specialized handle found with: {name}"
        return handler()

    def all_commands(self) -> Dict[str, CommandHandler]:
        """Return a copy of all registered commands."""
        return dict(self.command_handler_registry)
