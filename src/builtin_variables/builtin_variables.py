class BuiltInVariables:
    def __init__(self):
        pass
    def print_builtin_variables(self) -> None:
        print("__name__ =", __name__)
        print("__file__ =", __file__)
        print("__doc__ =", __doc__)
        print("__package__ = ", __package__)

def main():
    builtin_variables = BuiltInVariables()
    builtin_variables.print_builtin_variables()

if __name__ == "__main__":
    main()