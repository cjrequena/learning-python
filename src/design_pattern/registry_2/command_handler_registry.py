from typing import Type, Dict, Optional, Protocol

# Define an interface (Protocol) for all command_handler classes
class CommandHandler(Protocol):
    def handle(self) -> str:
        """Handle the command and return a message."""
        ...

class CommandHandlerRegistry:
    """A command handler registry to manage command handlers."""

    def __init__(self):
        # Registry maps string names to class types (subclasses of Command)
        self._command_handler_registry: Dict[str, Type[CommandHandler]] = {}

    def register(self, name: str, command_handler_cls: Type[CommandHandler]) -> None:
        """Register a command_handler class under a given name."""
        if name in self._command_handler_registry:
            raise KeyError(f"Command '{name}' is already registered.")
        self._command_handler_registry[name] = command_handler_cls

    def instantiate(self, name: str) -> Optional[CommandHandler]:
        """Instantiate a command by name."""
        command_handler_cls = self._command_handler_registry.get(name)
        if command_handler_cls is None:
            return None
        return command_handler_cls()

    def handle(self, name: str) -> str:
        """Create and run a command_handler by name."""
        command_handler = self.instantiate(name)
        if command_handler is None:
            return f"No specialized handler found with: {name}"
        return command_handler.handle()

    def all_command_handlers(self) -> Dict[str, Type[CommandHandler]]:
        """Return a copy of all registered command_handler classes."""
        return dict(self._command_handler_registry)
