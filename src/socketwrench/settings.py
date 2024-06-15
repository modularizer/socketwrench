
config = {
    "spoof_modules": False,
    "socket_module": None,
    "ignore_special_names": False,
}

def raise_import_error_if_testing(module_name):
    spoof_modules = config.get("spoof_modules", None)
    if not spoof_modules:
        return

    if (module_name == "any" and spoof_modules):
        raise ImportError(f"spoofing {spoof_modules}")
    elif spoof_modules == "all" or spoof_modules is True:
        raise ImportError("spoofing all imports")
    elif module_name in spoof_modules:
        raise ImportError(f"spoofing {module_name}")


def disable_autofill(f=None):
    if f in [None, True]:
        config["ignore_special_names"] = True
    elif f in [False]:
        config["ignore_special_names"] = False
    elif f:
        from socketwrench.tags import tag
        return tag(f, ignore_special_names=True)