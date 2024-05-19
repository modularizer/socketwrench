"""Imports all standard library dependencies to document what is used and allow for an easy spot to patch."""
from socketwrench.settings import raise_import_error_if_testing

# hard to fake imports
# this is the hardest one to fake and is not available in micropython, so will take some work to fake
try:
    raise_import_error_if_testing('inspect')
    import inspect
except ImportError:
    from socketwrench.fake_imports.fake_inspect import inspect

try:
    raise_import_error_if_testing('builtins')
    import builtins
except ImportError:
    builtins = None

# nested imports
try:
    raise_import_error_if_testing('argparse')
    from argparse import ArgumentParser
except ImportError:
    from socketwrench.fake_imports.fake_argparse import ArgumentParser

try:
    raise_import_error_if_testing('tempfile')
    from tempfile import TemporaryFile
except ImportError:
    from socketwrench.fake_imports.fake_tempfile import TemporaryFile

try:
    raise_import_error_if_testing('zipfile')
    from zipfile import ZipFile
except ImportError:
    class ZipFile:
        def __init__(self, *args, **kwargs):
            raise ImportError("zipfile is not available.")


try:
    raise_import_error_if_testing('argv')
    from sys import argv
except ImportError:
    argv = ["__main__"]

try:
    raise_import_error_if_testing('functools')
    from functools import wraps, partial
except ImportError:
    from socketwrench.fake_imports.fake_functools import wraps, partial

try:
    raise_import_error_if_testing('dataclasses')
    import dataclasses
except ImportError:
    from socketwrench.fake_imports.fake_dataclasses import dataclasses

try:
    raise_import_error_if_testing('datetime')
    from datetime import datetime
except ImportError:
    from socketwrench.fake_imports.fake_datetime import datetime

try:
    raise_import_error_if_testing('pathlib')
    from pathlib import Path
except ImportError:
    from socketwrench.fake_imports.fake_pathlib import Path


try:
    raise_import_error_if_testing('json')
    from json import dumps, loads
except ImportError:
    try:
        from ujson import dumps, loads
    except ImportError:
        from socketwrench.fake_imports.fake_json import dumps, loads

try:
    raise_import_error_if_testing('logging')
    import logging
except ImportError:
    from socketwrench.fake_imports.fake_logging import logging

try:
    raise_import_error_if_testing('time')
    from time import sleep
except ImportError:
    def sleep(seconds):
        pass

try:
    raise_import_error_if_testing('threading')
    from threading import Event, Thread
    from concurrent.futures import ThreadPoolExecutor
    threading_available = True
except ImportError:
    threading_available = False
    Event = Thread = ThreadPoolExecutor = None

try:
    raise_import_error_if_testing('traceback')
    from traceback import format_exception
except ImportError:
    from socketwrench.fake_imports.fake_traceback import format_exception

# only used if serve is called on a string: very niche case
try:
    raise_import_error_if_testing('importlib')
    import importlib
    from sys import modules
except ImportError:
    class importlib_cls:
        def __getattr__(self, item):
            raise ImportError("importlib is not available.")


    importlib = importlib_cls()


    class modules_cls:
        def __getattr__(self, item):
            raise ImportError("modules is not available.")


    modules = modules_cls()