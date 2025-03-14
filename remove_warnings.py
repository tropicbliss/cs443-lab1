import warnings

def remove_warnings():
    # Filter out the specific protobuf warnings
    warnings.filterwarnings("ignore", 
                        message="Protobuf gencode version.*is exactly one major version older than the runtime version.*",
                        category=UserWarning)

    # Also filter out the CppHeaderParser warnings
    warnings.filterwarnings("ignore", 
                        message="invalid escape sequence.*",
                        category=SyntaxWarning)