from typing import Type, Dict, Optional, Protocol, Callable


class CommandHandler(Protocol):
    def handle(self) -> str:
        """Handle the command and return a message."""
        ...

class CommandHandlerRegistry:
    """A global command_handler_registry using class methods."""

    _command_handler_registry: Dict[str, Type[CommandHandler]] = {}

    def __init__(self):
        self._command_handler_registry: Dict[str, Type[CommandHandler]] = {}

    def register(self, name: str) -> Callable[[Type[CommandHandler]], Type[CommandHandler]]:
        """Classmethod decorator to register command handler classes."""
        def decorator(command_handler_cls: Type[CommandHandler]) -> Type[CommandHandler]:
            if name in self._command_handler_registry:
                raise KeyError(f"Command Handler '{name}' is already registered.")
            self._command_handler_registry[name] = command_handler_cls
            return command_handler_cls
        return decorator

    def instantiate(self, name: str) -> Optional[CommandHandler]:
        """Instantiate a command handler by name."""
        command_handler_cls = self._command_handler_registry.get(name)
        if command_handler_cls is None:
            return None
        return command_handler_cls()

    def handle(self, name: str) -> str:
        """Create and execute a command_handler by name."""
        command_handler = self.instantiate(name)
        if command_handler is None:
            return f"No specialized handler found with: {name}"
        return command_handler.handle()

    def all_handlers(self) -> Dict[str, Type[CommandHandler]]:
        """Return all registered command handlers."""
        return dict(self._command_handler_registry)
