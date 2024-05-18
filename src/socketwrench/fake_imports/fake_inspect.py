class _empty:
    pass


class Parameter:
    POSITIONAL_ONLY = 0
    POSITIONAL_OR_KEYWORD = 1
    VAR_POSITIONAL = 2
    KEYWORD_ONLY = 3
    VAR_KEYWORD = 4
    empty = _empty

    def __init__(self, name, kind, default=_empty, annotation=_empty):
        self.name = name
        self.kind = kind
        self.default = default
        self.annotation = annotation


class Signature:
    def __init__(self, parameters, return_annotation=_empty):
        self.parameters = parameters
        self.return_annotation = return_annotation


class inspect:
    Parameter = Parameter

    @staticmethod
    def signature(func):
        if not callable(func):
            raise TypeError(f"{func} is not a callable function")

        code = func.__code__
        varnames = code.co_varnames
        argcount = code.co_argcount
        defaults = func.__defaults__ or ()
        kwdefaults = func.__kwdefaults__ or {}

        parameters = []

        # Process positional arguments
        for i, varname in enumerate(varnames[:argcount]):
            kind = Parameter.POSITIONAL_OR_KEYWORD
            default = Parameter.empty
            if i >= argcount - len(defaults):
                default = defaults[i - (argcount - len(defaults))]
            param = Parameter(name=varname, kind=kind, default=default)
            parameters.append(param)

        # Add keyword-only arguments
        for varname in kwdefaults:
            kind = Parameter.KEYWORD_ONLY
            default = kwdefaults[varname]
            param = Parameter(name=varname, kind=kind, default=default)
            parameters.append(param)

        return Signature({param.name: param for param in parameters})

    @staticmethod
    def getsourcelines(obj):
        return ["# Source code not available\n"], 0

    @staticmethod
    def isfunction(obj):
        return callable(obj) and str(type(obj)) in ["<class 'function'>", "<class 'method'>"]


    @staticmethod
    def getmembers(obj, predicate=None):
        return [(name, value) for name, value in obj.__dict__.items() if predicate is None or predicate(value)]