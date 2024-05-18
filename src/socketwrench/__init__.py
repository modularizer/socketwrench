
def _spoof_modules(which="all"):
    from socketwrench.settings import config
    config["spoof_modules"] = which

class _unspecified:
    pass

def serve(*args, spoof_modules=_unspecified, **kwargs):
    if spoof_modules is not _unspecified:
        _spoof_modules(spoof_modules)
    import socketwrench.public
    return socketwrench.public.serve(*args, **kwargs)

def __getattr__(name):
    # import from public
    if name == "_spoof_modules":
        return _spoof_modules
    import socketwrench.public
    return getattr(socketwrench.public, name)
