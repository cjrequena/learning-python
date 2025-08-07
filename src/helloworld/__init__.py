# Imports HelloWorld class into the package namespace
from .helloworld import HelloWorld

# Defines what is publicly exported from the package
# This line ensures that when the package is imported, HelloWorld is accessible
__all__: list[str] = ['HelloWorld'] 


# ----------------------------------------------------------------------------------------------------------------- 
