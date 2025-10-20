from typing import Type, Dict, Optional, Protocol, Callable


class CommandHandler(Protocol):
    def handle(self) -> str:
        """Handle the command and return a message."""
        ...

class CommandHandlerRegistry:
    """A global registry using class methods."""

    # A static global _command_handler_registry
    _command_handler_registry: Dict[str, Type[CommandHandler]] = {}

    @classmethod
    def register(cls, name: str) -> Callable[[Type[CommandHandler]], Type[CommandHandler]]:
        """Classmethod decorator to register command handler classes."""
        def decorator(command_handler_cls: Type[CommandHandler]) -> Type[CommandHandler]:
            if name in cls._command_handler_registry:
                raise KeyError(f"Command Handler '{name}' is already registered.")
            cls._command_handler_registry[name] = command_handler_cls
            return command_handler_cls
        return decorator

    @classmethod
    def instantiate(cls, name: str) -> Optional[CommandHandler]:
        """Instantiate a command handler by name."""
        command_handler_cls = cls._command_handler_registry.get(name)
        if command_handler_cls is None:
            return None
        return command_handler_cls()

    @classmethod
    def handle(cls, name: str) -> str:
        """Create and execute a command_handler by name."""
        command_handler = cls.instantiate(name)
        if command_handler is None:
            return f"No specialized handler found with: {name}"
        return command_handler.handle()

    @classmethod
    def all_handlers(cls) -> Dict[str, Type[CommandHandler]]:
        """Return all registered command handlers."""
        return dict(cls._command_handler_registry)
