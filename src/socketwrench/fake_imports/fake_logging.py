import logging


CRITICAL = 50
FATAL = CRITICAL
ERROR = 40
WARNING = 30
WARN = WARNING
INFO = 20
DEBUG = 10
NOTSET = 0

_levelToName = {
    CRITICAL: 'CRITICAL',
    ERROR: 'ERROR',
    WARNING: 'WARNING',
    INFO: 'INFO',
    DEBUG: 'DEBUG',
    NOTSET: 'NOTSET',
}
_nameToLevel = {
    'CRITICAL': CRITICAL,
    'FATAL': FATAL,
    'ERROR': ERROR,
    'WARN': WARNING,
    'WARNING': WARNING,
    'INFO': INFO,
    'DEBUG': DEBUG,
    'NOTSET': NOTSET,
}

class Logger:
    root_level = NOTSET

    def __init__(self, name, level=DEBUG):
        self.name = name
        self.level = level

    def info(self, msg, *args):
        self.log(INFO, msg, *args)

    def debug(self, msg, *args):
        self.log(DEBUG, msg, *args)
        
    def error(self, msg, *args):
        self.log(ERROR, msg, *args)
        
    def warning(self, msg, *args):
        self.log(WARNING, msg, *args)
        
    def critical(self, msg, *args):
        self.log(CRITICAL, msg, *args)
        
    def exception(self, msg, *args):
        self.log(ERROR, msg,*args)
        
    def log(self, level, msg, *args):
        if level < (self.level or self.root_level):
            return
        name = _levelToName[level]
        m = msg % args
        print(f"{name}: {m}")
        
    def setLevel(self, level):
        if isinstance(level, str):
            level = _nameToLevel[level]
        self.level = level


class logging:
    DEBUG = DEBUG
    INFO = INFO
    WARNING = WARNING
    ERROR = ERROR
    CRITICAL = CRITICAL
    NOTSET = NOTSET
    Logger = Logger

    _loggers = {}

    @classmethod
    def getLogger(cls, name="", level=NOTSET):
        if name not in cls._loggers:
            cls._loggers[name] = Logger(name)
        return cls._loggers[name]

    @classmethod
    def basicConfig(cls, level=INFO):
        Logger.root_level = level
