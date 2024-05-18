
def _spoof_modules(which="all"):
    from socketwrench.settings import config
    config["spoof_modules"] = which

def set_socket_module(module):
    from socketwrench.settings import config
    if not hasattr(module, "socket"):
        raise ValueError("socket module must have a 'socket' attribute. expecting a module like that from 'import socket'")
    config["socket_module"] = module


class _unspecified:
    pass


def serve(*args, spoof_modules=_unspecified, socket=_unspecified, log_level=None, **kwargs):
    if spoof_modules is not _unspecified:
        _spoof_modules(spoof_modules)
    if socket is not _unspecified:
        set_socket_module(socket)
    import socketwrench.public
    if log_level is not None:
        from socketwrench.standardlib_dependencies import logging
        logging.basicConfig(level=log_level)
    return socketwrench.public.serve(*args, **kwargs)


def __getattr__(name):
    # import from public
    if name == "_spoof_modules":
        return _spoof_modules
    import socketwrench.public
    return getattr(socketwrench.public, name)
