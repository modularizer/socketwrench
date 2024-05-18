spoof_modules = False

def raise_import_error_if_testing(module_name):
    if not spoof_modules:
        return

    if (module_name == "any" and spoof_modules):
        raise ImportError(f"spoofing {spoof_modules}")
    elif spoof_modules == "all":
        raise ImportError("spoofing all imports")
    elif module_name in spoof_modules:
        raise ImportError(f"spoofing {module_name}")